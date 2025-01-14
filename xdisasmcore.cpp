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

#include "xdisasmcore.h"

XDisasmCore::XDisasmCore(QObject *pParent) : QObject(pParent)
{
    g_disasmMode=XBinary::DM_UNKNOWN;
    g_disasmFamily = XBinary::DMFAMILY_UNKNOWN;
    g_handle = 0;
    g_bIsCapstone = false;
    g_nOpcodeSize = 15;
}

XDisasmCore::~XDisasmCore()
{
    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }
}

void XDisasmCore::setMode(XBinary::DM disasmMode, XBinary::SYNTAX syntax)
{
    if ((g_disasmMode != disasmMode) || (g_syntax != syntax)) {
        if (g_handle) {
            XCapstone::closeHandle(&g_handle);
        }

        g_bIsCapstone = false;

        if (XCapstone::isModeValid(disasmMode)) {
            XCapstone::openHandle(disasmMode, &g_handle, true, syntax);
            g_bIsCapstone = true;
        }

        g_disasmMode = disasmMode;
        g_disasmFamily = XBinary::getDisasmFamily(disasmMode);
        g_syntax = syntax;
    }
}

QString XDisasmCore::getNumberString(qint64 nNumber)
{
    QString sResult;

    if (g_disasmFamily == XBinary::DMFAMILY_X86) {
        if (nNumber < 0) {
            sResult += "- ";
        }
        nNumber = qAbs(nNumber);

        if (nNumber < 10) {
            sResult += QString::number(nNumber);
        } else {
            if ((g_syntax == XBinary::SYNTAX_DEFAULT) || (g_syntax == XBinary::SYNTAX_INTEL) || (g_syntax == XBinary::SYNTAX_ATT)) {
                sResult += QString("0x%1").arg(QString::number(nNumber, 16));
            } else if (g_syntax == XBinary::SYNTAX_MASM) {
                sResult += QString("%1h").arg(QString::number(nNumber, 16));
            }
        }
    } else {
        sResult += QString("0x%1").arg(QString::number(nNumber, 16));
    }

    return sResult;
}

XBinary::SYNTAX XDisasmCore::getSyntax()
{
    return g_syntax;
}

QString XDisasmCore::getSignature(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, ST signatureType, qint32 nCount)
{
    QString sResult;

    XDisasmCore::DISASM_OPTIONS disasmOptions = {};

    while (nCount > 0) {
        qint64 nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);

        if (nOffset == -1) {
            break;
        }

        QByteArray baData = XBinary::read_array(pDevice, nOffset, 15);

        DISASM_RESULT _disasmResult = disAsm(baData.data(), baData.size(), nAddress, disasmOptions);

        if (_disasmResult.bIsValid) {
            baData.resize(_disasmResult.nSize);

            QString sHEX = baData.toHex().data();

            if ((signatureType == ST_FULL) || (signatureType == ST_MASK)) {
                nAddress += _disasmResult.nSize;

                if (signatureType == ST_MASK) {
                    if (_disasmResult.nDispSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nDispOffset, _disasmResult.nDispSize, '.');
                    }

                    if (_disasmResult.nImmSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '.');
                    }
                }
            } else if (signatureType == ST_REL) {
                bool bIsJump = false;

                nAddress = _disasmResult.nNextAddress;

                if ((pMemoryMap->fileType == XBinary::FT_COM) && (_disasmResult.nImmSize == 2)) {
                    if (nAddress > 0xFFFF) {
                        nAddress &= 0xFFFF;
                    }
                }

                if (XCapstone::isBranchOpcode(g_disasmFamily, _disasmResult.nOpcode)) {
                    // TODO another archs !!!
                    if (g_disasmFamily == XBinary::DMFAMILY_X86) {
                        if (_disasmResult.nImmSize) {
                            sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '$');
                        }

                        bIsJump = true;
                    }
                }

                if (!bIsJump) {
                    if (_disasmResult.nDispSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nDispOffset, _disasmResult.nDispSize, '.');
                    }

                    if (_disasmResult.nImmSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '.');
                    }
                }
            }

            sResult += sHEX;
        } else {
            break;
        }

        nCount--;
    }

    return sResult;
}

QList<XDisasmCore::SIGNATURE_RECORD> XDisasmCore::getSignatureRecords(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, qint64 nOffset, qint32 nCount, ST signatureType)
{
    QList<SIGNATURE_RECORD> listResult;

    XDisasmCore::DISASM_OPTIONS disasmOptions = {};

    bool bStopBranch = false;

    for (qint32 i = 0; (i < nCount) && (!bStopBranch); i++) {
        if (nOffset != -1) {
            XADDR nAddress = XBinary::offsetToAddress(pMemoryMap, nOffset);

            QByteArray baData = XBinary::read_array(pDevice, nOffset, 15);

            DISASM_RESULT _disasmResult = disAsm(baData.data(), baData.size(), nAddress, disasmOptions);

            if (_disasmResult.bIsValid) {
                bStopBranch = !XBinary::isOffsetValid(pMemoryMap, nOffset + _disasmResult.nSize - 1);

                if (!bStopBranch) {
                    XDisasmCore::SIGNATURE_RECORD record = {};

                    record.nAddress = nAddress;
                    record.sOpcode = _disasmResult.sMnemonic;

                    if (_disasmResult.sString != "") {
                        record.sOpcode += " " + _disasmResult.sString;
                    }

                    baData.resize(_disasmResult.nSize);

                    record.baOpcode = baData;

                    record.nDispOffset = _disasmResult.nDispOffset;
                    record.nDispSize = _disasmResult.nDispSize;
                    record.nImmOffset = _disasmResult.nImmOffset;
                    record.nImmSize = _disasmResult.nImmSize;

                    if ((signatureType == ST_FULL) || (signatureType == ST_MASK)) {
                        nAddress += _disasmResult.nSize;
                    } else if (signatureType == ST_REL) {
                        nAddress = _disasmResult.nNextAddress;
                        record.bIsConst = _disasmResult.bIsConst;
                    }

                    if ((pMemoryMap->fileType == XBinary::FT_COM) && (_disasmResult.nImmSize == 2)) {
                        if (nAddress > 0xFFFF) {
                            nAddress &= 0xFFFF;
                        }
                    }

                    listResult.append(record);
                }
            } else {
                bStopBranch = true;
            }

            nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);
        }
    }

    return listResult;
}

QString XDisasmCore::replaceWildChar(const QString &sString, qint32 nOffset, qint32 nSize, QChar cWild)
{
    QString sResult = sString;
    QString sWild;

    sWild = sWild.fill(cWild, nSize * 2);

    sResult = sResult.replace(nOffset * 2, nSize * 2, sWild);

    return sResult;
}

XDisasmCore::DISASM_RESULT XDisasmCore::disAsm(QIODevice *pDevice, qint64 nOffset, XADDR nAddress, const DISASM_OPTIONS &disasmOptions)
{
    QByteArray baData = XBinary::read_array(pDevice, nOffset, g_nOpcodeSize);

    return disAsm(baData.data(), baData.size(), nAddress, disasmOptions);
}

XDisasmCore::DISASM_RESULT XDisasmCore::disAsm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions)
{
    DISASM_RESULT result = {};

    result.nAddress = nAddress;

    if (g_bIsCapstone) {
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
                                if (XCapstone::isCallOpcode(g_disasmFamily, pInsn->id)) {
                                    result.relType = RELTYPE_CALL;
                                } else if (XCapstone::isJumpOpcode(g_disasmFamily, pInsn->id)) {
                                    result.relType = RELTYPE_JMP_UNCOND;
                                } else if (XCapstone::isCondJumpOpcode(g_disasmFamily, pInsn->id)) {
                                    result.relType = RELTYPE_JMP_COND;
                                } else {
                                    result.relType = RELTYPE_JMP;
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
                                result.relType = RELTYPE_JMP;  // TODO
                                result.nXrefToRelative = pInsn->detail->arm.operands[j].imm;
                                result.nNextAddress = result.nXrefToRelative;
                                result.bIsConst = true;

                                break;
                            }
                        }
                    } else if (g_disasmFamily == XBinary::DMFAMILY_ARM64) {
                        for (qint32 j = 0; j < pInsn->detail->arm64.op_count; j++) {
                            if (pInsn->detail->arm64.operands[j].type == ARM64_OP_IMM) {
                                result.relType = RELTYPE_JMP;  // TODO
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
                            result.memType = MEMTYPE_READ;  // TODO
                            result.nXrefToMemory = pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            break;
                        } else if ((pInsn->detail->x86.operands[i].mem.base == X86_REG_RIP) && (pInsn->detail->x86.operands[i].mem.index == X86_REG_INVALID)) {
                            result.memType = MEMTYPE_READ;  // TODO
                            result.nXrefToMemory = nAddress + pInsn->size + pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            QString sOldString;
                            QString sNewString;

                            // TODO Check
                            if ((g_syntax == XBinary::SYNTAX_DEFAULT) || (g_syntax == XBinary::SYNTAX_INTEL) ||
                                (g_syntax == XBinary::SYNTAX_MASM)) {
                                if (result.sString.contains("rip + ")) {
                                    sOldString =
                                        QString("rip + %1").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp));
                                }
                            } else if (g_syntax == XBinary::SYNTAX_ATT) {
                                if (result.sString.contains("(%rip)")) {
                                    sOldString =
                                        QString("%1(%rip)").arg(getNumberString(pInsn->detail->x86.operands[i].mem.disp));
                                }
                            }

                            if (sOldString != "") {
                                sNewString = getNumberString(result.nXrefToMemory);
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
                result.nSize = 4;
            } else if (g_disasmFamily == XBinary::DMFAMILY_ARM) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 4;
            } else if (g_disasmFamily == XBinary::DMFAMILY_M68K) {
                result.sMnemonic = tr("Invalid opcode");
                result.nSize = 2;
            } else {
                result.sMnemonic = "db";
                result.sString = getNumberString(*((uint8_t *)pData));
                result.nSize = 1;
            }
        }
    } else {
        result.nSize = 1;
    }

    if (disasmOptions.bIsUppercase) {
        result.sMnemonic = result.sMnemonic.toUpper();
        result.sString = result.sString.toUpper();
    }

    return result;
}
