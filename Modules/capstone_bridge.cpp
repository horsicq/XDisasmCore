/* Copyright (c) 2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "capstone_bridge.h"

Capstone_Bridge::Capstone_Bridge(XBinary::DM disasmMode, XBinary::SYNTAX syntax, QObject *pParent) : XDisasmAbstract(pParent)
{
    XCapstone::openHandle(disasmMode, &m_handle, true, syntax);

    m_disasmMode = disasmMode;
    m_disasmFamily = XBinary::getDisasmFamily(disasmMode);
    m_syntax = syntax;
}

Capstone_Bridge::~Capstone_Bridge()
{
    if (m_handle) {
        XCapstone::closeHandle(&m_handle);
    }
}

QList<XDisasmAbstract::DISASM_RESULT> Capstone_Bridge::_disasm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                                               XBinary::PDSTRUCT *pPdStruct)
{
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    STATE state = {};
    state.nCurrentCount = 0;
    state.nCurrentOffset = 0;
    state.nLimit = nLimit;
    state.nMaxSize = nDataSize;
    state.nAddress = nAddress;

    while (XBinary::isPdStructNotCanceled(pPdStruct) && (!(state.bIsStop))) {
        XDisasmAbstract::DISASM_RESULT result = {};
        result.nAddress = nAddress;

        cs_insn *pInsn = nullptr;

        // cs_reg_name

        quint64 nNumberOfOpcodes = cs_disasm(m_handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

        if (nNumberOfOpcodes > 0) {
            result.bIsValid = true;
            result.bIsRet = isRetOpcode(m_disasmFamily, pInsn->id);
            result.bIsCall = isCallOpcode(m_disasmFamily, pInsn->id);
            result.bIsJmp = isJumpOpcode(m_disasmFamily, pInsn->id);
            result.bIsCondJmp = isCondJumpOpcode(m_disasmFamily, pInsn->id);
            result.nOpcode = pInsn->id;
            result.sMnemonic = pInsn->mnemonic;
            result.sOperands = pInsn->op_str;
            result.nSize = pInsn->size;
            result.nNextAddress = nAddress + result.nSize;

            if (m_disasmFamily == XBinary::DMFAMILY_X86) {
                result.nDispOffset = pInsn->detail->x86.encoding.disp_offset;
                result.nDispSize = pInsn->detail->x86.encoding.disp_size;
                result.nImmOffset = pInsn->detail->x86.encoding.imm_offset;
                result.nImmSize = pInsn->detail->x86.encoding.imm_size;
            }

            // Relatives
            for (qint32 i = 0; i < pInsn->detail->groups_count; i++) {
                if (pInsn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                    if (m_disasmFamily == XBinary::DMFAMILY_X86) {
                        for (qint32 j = 0; j < pInsn->detail->x86.op_count; j++) {
                            // TODO mb use groups
                            if (pInsn->detail->x86.operands[j].type == X86_OP_IMM) {
                                if (result.bIsCall) {
                                    result.relType = XDisasmAbstract::RELTYPE_CALL;
                                } else if (result.bIsJmp) {
                                    result.relType = XDisasmAbstract::RELTYPE_JMP_UNCOND;
                                } else if (result.bIsCondJmp) {
                                    result.relType = XDisasmAbstract::RELTYPE_JMP_COND;
                                } else {
                                    result.relType = XDisasmAbstract::RELTYPE_JMP;
                                }

                                result.nXrefToRelative = pInsn->detail->x86.operands[j].imm;
                                result.nNextAddress = result.nXrefToRelative;
                                result.bIsConst = true;

                                break;
                            }
                        }
                    } else if (m_disasmFamily == XBinary::DMFAMILY_ARM) {
                        for (qint32 j = 0; j < pInsn->detail->arm.op_count; j++) {
                            if (pInsn->detail->arm.operands[j].type == ARM_OP_IMM) {
                                result.relType = XDisasmAbstract::RELTYPE_JMP;  // TODO
                                result.nXrefToRelative = pInsn->detail->arm.operands[j].imm;
                                result.nNextAddress = result.nXrefToRelative;
                                result.bIsConst = true;

                                break;
                            }
                        }
                    } else if (m_disasmFamily == XBinary::DMFAMILY_ARM64) {
                        for (qint32 j = 0; j < pInsn->detail->arm64.op_count; j++) {
                            if (pInsn->detail->arm64.operands[j].type == ARM64_OP_IMM) {
                                result.relType = XDisasmAbstract::RELTYPE_JMP;  // TODO
                                result.nXrefToRelative = pInsn->detail->arm64.operands[j].imm;
                                result.nNextAddress = result.nXrefToRelative;
                                result.bIsConst = true;

                                break;
                            }
                        }
                    }

                    break;
                }
            }

            // Memory
            if (m_disasmFamily == XBinary::DMFAMILY_X86) {
                for (qint32 i = 0; i < pInsn->detail->x86.op_count; i++) {
                    if (pInsn->detail->x86.operands[i].type == X86_OP_MEM) {
                        bool bLEA = (pInsn->id == X86_INS_LEA);

                        // mb TODO flag
                        if ((pInsn->detail->x86.operands[i].mem.base == X86_REG_INVALID) && (pInsn->detail->x86.operands[i].mem.index == X86_REG_INVALID)) {
                            result.memType = XDisasmAbstract::MEMTYPE_READ;  // TODO
                            result.nXrefToMemory = pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            break;
                        } else if ((pInsn->detail->x86.operands[i].mem.base == X86_REG_RIP) && (pInsn->detail->x86.operands[i].mem.index == X86_REG_INVALID)) {
                            result.memType = XDisasmAbstract::MEMTYPE_READ;  // TODO
                            result.nXrefToMemory = nAddress + pInsn->size + pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            QString sOldString;
                            QString sNewString;

                            // TODO Check
                            if ((m_syntax == XBinary::SYNTAX_DEFAULT) || (m_syntax == XBinary::SYNTAX_INTEL) || (m_syntax == XBinary::SYNTAX_MASM)) {
                                if (pInsn->detail->x86.operands[i].mem.disp >= 0) {
                                    if (result.sOperands.contains("rip + ")) {
                                        sOldString = QString("rip + %1").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp, m_disasmMode, m_syntax));
                                    }
                                } else {
                                    if (result.sOperands.contains("rip - ")) {
                                        sOldString = QString("rip - %1").arg(getNumberString(0 - pInsn->detail->x86.operands[i].mem.disp, m_disasmMode, m_syntax));
                                    }
                                }
                            } else if (m_syntax == XBinary::SYNTAX_ATT) {
                                if (result.sOperands.contains("(%rip)")) {
                                    sOldString = QString("%1(%rip)").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp, m_disasmMode, m_syntax));
                                }
                            }

                            if (sOldString != "") {
                                sNewString = getNumberString(result.nXrefToMemory, m_disasmMode, m_syntax);
                                result.sOperands = result.sOperands.replace(sOldString, sNewString);
                            }

                            break;
                        }
                    }
                }
            }

            //            if (disasmMode == XBinary::DM_X86_64) {
            //                if (result.sString.contains("[rip + 0x")) {
            //                    // TODO
            //                    qint32 nNumberOfOpcodes = pInsn->detail->x86.op_count;

            //                    for (qint32 i = 0; i < nNumberOfOpcodes; i++) {

            //                    }
            //                }
            //            }

            cs_free(pInsn, nNumberOfOpcodes);
        } else {
            if (cs_errno(m_handle) == CS_ERR_MEM) {
                state.bIsStop = true;
                result.bMemError = true;
            }

            if (m_disasmFamily == XBinary::DMFAMILY_ARM) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 2;
            } else if (m_disasmFamily == XBinary::DMFAMILY_ARM64) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 4;
            } else if (m_disasmFamily == XBinary::DMFAMILY_M68K) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 2;
            } else {
                result.sMnemonic = "db";
                result.sOperands = getNumberString(*((uint8_t *)pData), m_disasmMode, m_syntax);
                result.nSize = 1;
            }
        }

        _addDisasmResult(&listResult, result, &state, disasmOptions);

        pData += result.nSize;
        nAddress += result.nSize;
    }

    return listResult;
}
