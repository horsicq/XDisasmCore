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

Capstone_Bridge::Capstone_Bridge(XBinary::DM disasmMode, XBinary::SYNTAX syntax, QObject *parent) : XDisasmAbstract(parent)
{
    XCapstone::openHandle(disasmMode, &g_handle, true, syntax);

    g_disasmMode = disasmMode;
    g_disasmFamily = XBinary::getDisasmFamily(disasmMode);
    g_syntax = syntax;
}

Capstone_Bridge::~Capstone_Bridge()
{
    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }
}

QList<XDisasmAbstract::DISASM_RESULT> Capstone_Bridge::_disasm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                                               XBinary::PDSTRUCT *pPdStruct)
{
    cs_reg_name(0,0);
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    STATE state = {};
    state.nCurrentCount = 0;
    state.nCurrentOffset = 0;
    state.nLimit = nLimit;
    state.nMaxSize = nDataSize;
    state.nAddress = nAddress;

    while ((!(pPdStruct->bIsStop)) && (!(state.bIsStop))) {
        XDisasmAbstract::DISASM_RESULT result = {};
        result.nAddress = nAddress;

        cs_insn *pInsn = nullptr;

        quint64 nNumberOfOpcodes = cs_disasm(g_handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

        if (nNumberOfOpcodes > 0) {
            result.nOpcode = pInsn->id;
            result.sMnemonic = pInsn->mnemonic;
            result.sString = pInsn->op_str;
            result.nSize = pInsn->size;
            result.bIsValid = true;
            result.nNextAddress = nAddress + result.nSize;

            if (g_disasmFamily == XBinary::DMFAMILY_X86) {
                result.nDispOffset = pInsn->detail->x86.encoding.disp_offset;
                result.nDispSize = pInsn->detail->x86.encoding.disp_size;
                result.nImmOffset = pInsn->detail->x86.encoding.imm_offset;
                result.nImmSize = pInsn->detail->x86.encoding.imm_size;
            }

            // Relatives
            for (qint32 i = 0; i < pInsn->detail->groups_count; i++) {
                if (pInsn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                    if (g_disasmFamily == XBinary::DMFAMILY_X86) {
                        for (qint32 j = 0; j < pInsn->detail->x86.op_count; j++) {
                            // TODO mb use groups
                            if (pInsn->detail->x86.operands[j].type == X86_OP_IMM) {
                                if (isCallOpcode(g_disasmFamily, pInsn->id)) {
                                    result.relType = XDisasmAbstract::RELTYPE_CALL;
                                } else if (isJumpOpcode(g_disasmFamily, pInsn->id)) {
                                    result.relType = XDisasmAbstract::RELTYPE_JMP_UNCOND;
                                } else if (isCondJumpOpcode(g_disasmFamily, pInsn->id)) {
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
                    } else if (g_disasmFamily == XBinary::DMFAMILY_ARM) {
                        for (qint32 j = 0; j < pInsn->detail->arm.op_count; j++) {
                            if (pInsn->detail->arm.operands[j].type == ARM_OP_IMM) {
                                result.relType = XDisasmAbstract::RELTYPE_JMP;  // TODO
                                result.nXrefToRelative = pInsn->detail->arm.operands[j].imm;
                                result.nNextAddress = result.nXrefToRelative;
                                result.bIsConst = true;

                                break;
                            }
                        }
                    } else if (g_disasmFamily == XBinary::DMFAMILY_ARM64) {
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
            if (g_disasmFamily == XBinary::DMFAMILY_X86) {
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
                            if ((g_syntax == XBinary::SYNTAX_DEFAULT) || (g_syntax == XBinary::SYNTAX_INTEL) || (g_syntax == XBinary::SYNTAX_MASM)) {
                                if (result.sString.contains("rip + ")) {
                                    sOldString = QString("rip + %1").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp, g_disasmMode, g_syntax));
                                }
                            } else if (g_syntax == XBinary::SYNTAX_ATT) {
                                if (result.sString.contains("(%rip)")) {
                                    sOldString = QString("%1(%rip)").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp, g_disasmMode, g_syntax));
                                }
                            }

                            if (sOldString != "") {
                                sNewString = getNumberString(result.nXrefToMemory, g_disasmMode, g_syntax);
                                result.sString = result.sString.replace(sOldString, sNewString);
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
            if (g_disasmFamily == XBinary::DMFAMILY_ARM) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 2;
            } else if (g_disasmFamily == XBinary::DMFAMILY_ARM64) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 4;
            } else if (g_disasmFamily == XBinary::DMFAMILY_M68K) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 2;
            } else {
                result.sMnemonic = "db";
                result.sString = getNumberString(*((uint8_t *)pData), g_disasmMode, g_syntax);
                result.nSize = 1;
            }
        }

        _addDisasmResult(&listResult, result, &state, disasmOptions);

        pData += result.nSize;
        nAddress += result.nSize;
    }

    return listResult;
}
