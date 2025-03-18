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

#include "xmacho_commands.h"

XMachO_Commands::XMachO_Commands(XBinary::DM disasmMode, QObject *parent) : XDisasmAbstract(parent)
{
    g_disasmMode = disasmMode;
}

quint64 XMachO_Commands::_handleULEB128(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions, const QString &sPrefix)
{
    if (pState->bIsStop) {
        return 0;
    }

    quint64 nResult = 0;

    XBinary::PACKED_UINT puTag = XBinary::_read_uleb128(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);

    if (puTag.bIsValid) {
        nResult = puTag.nValue;
        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, puTag.nByteSize, sPrefix, QString("0x%1").arg(QString::number(puTag.nValue, 16)),
                         pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return nResult;
}

QString XMachO_Commands::_handleAnsiString(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions, const QString &sPrefix)
{
    if (pState->bIsStop) {
        return 0;
    }

    qint64 nMaxSize = qMin(pState->nMaxSize - pState->nCurrentOffset, (qint64)256);
    QString sResult = XBinary::_read_ansiString(pData + pState->nCurrentOffset, nMaxSize);

    if (sResult != "") {
        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, sResult.size() + 1, sPrefix, sResult, pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return sResult;
}

QList<XDisasmAbstract::DISASM_RESULT> XMachO_Commands::_disasm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                                               XBinary::PDSTRUCT *pPdStruct)
{
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    STATE state = {};
    state.nCurrentCount = 0;
    state.nCurrentOffset = 0;
    state.nLimit = nLimit;
    state.nMaxSize = nDataSize;
    state.nAddress = nAddress;

    if (g_disasmMode == XBinary::DM_CUSTOM_MACH_EXPORT) {
        while (!(state.bIsStop)) {
            quint64 nTerminalSize = _handleULEB128(&listResult, pData, &state, disasmOptions, "TERMINAL_SIZE");

            if (nTerminalSize > 0) {
                _handleULEB128(&listResult, pData, &state, disasmOptions, "FLAGS");
                _handleULEB128(&listResult, pData, &state, disasmOptions, "SYMBOL_OFFSET");
            }

            quint64 nChildCount = _handleULEB128(&listResult, pData, &state, disasmOptions, "CHILD_COUNT");

            for (quint64 i = 0; i < nChildCount; i++) {
                _handleAnsiString(&listResult, pData, &state, disasmOptions, "NODE_LABEL");
                _handleULEB128(&listResult, pData, &state, disasmOptions, "NODE_OFFSET");
            }

            if ((nTerminalSize == 0) && (nChildCount == 0)) {
                state.bIsStop = true;
            }
        }
    } else if ((g_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) || (g_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (g_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
        while (!(state.bIsStop)) {
            quint8 nOpcode = XBinary::_read_uint8(pData + state.nCurrentOffset);

            bool bString = false;
            bool bUleb1 = false;
            bool bUleb2 = false;
            bool bImm = false;

            QString sMnemonic;

            if (g_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) {
                switch (nOpcode & XMACH_DEF::S_REBASE_OPCODE_MASK) {
                    case XMACH_DEF::S_REBASE_OPCODE_SET_TYPE_IMM:
                        sMnemonic = QString("SET_TYPE_IMM");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                        sMnemonic = QString("SET_SEGMENT_AND_OFFSET_ULEB");
                        bImm = true;
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_ADD_ADDR_ULEB:
                        sMnemonic = QString("ADD_ADDR_ULEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                        sMnemonic = QString("ADD_ADDR_IMM_SCALED");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                        sMnemonic = QString("DO_REBASE_IMM_TIMES");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                        sMnemonic = QString("DO_REBASE_ULEB_TIMES");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                        sMnemonic = QString("DO_REBASE_ADD_ADDR_ULEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                        sMnemonic = QString("DO_REBASE_ULEB_TIMES_SKIPPING_ULEB");
                        bUleb1 = true;
                        bUleb2 = true;
                        break;
                    default:
                        if (nOpcode == 0) {
                            sMnemonic = QString("DONE");
                        } else {
                            state.bIsStop = true;
                        }
                }
            } else if ((g_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (g_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
                switch (nOpcode & XMACH_DEF::S_BIND_OPCODE_MASK) {
                    case XMACH_DEF::S_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        sMnemonic = QString("SET_DYLIB_ORDINAL_IMM");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        sMnemonic = QString("SET_DYLIB_ORDINAL_ULEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                        sMnemonic = QString("SET_DYLIB_SPECIAL_IMM");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        sMnemonic = QString("SET_SYMBOL_TRAILING_FLAGS_IMM");
                        bImm = true;
                        bString = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_TYPE_IMM:
                        sMnemonic = QString("SET_TYPE_IMM");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_ADDEND_SLEB:
                        sMnemonic = QString("SET_ADDEND_SLEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                        sMnemonic = QString("SET_SEGMENT_AND_OFFSET_ULEB");
                        bImm = true;
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_ADD_ADDR_ULEB:
                        sMnemonic = QString("ADD_ADDR_ULEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_DO_BIND: sMnemonic = QString("DO_BIND"); break;
                    case XMACH_DEF::S_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                        sMnemonic = QString("DO_BIND_ADD_ADDR_ULEB");
                        bUleb1 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                        sMnemonic = QString("DO_BIND_ADD_ADDR_IMM_SCALED");
                        bImm = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                        sMnemonic = QString("DO_BIND_ULEB_TIMES_SKIPPING_ULEB");
                        bUleb1 = true;
                        bUleb2 = true;
                        break;
                    case XMACH_DEF::S_BIND_OPCODE_THREADED:
                        sMnemonic = QString("THREADED");
                        bImm = true;
                        break;
                    default:
                        if (nOpcode == 0) {
                            sMnemonic = QString("DONE");
                        } else {
                            state.bIsStop = true;
                        }
                }
            }

            QString sString;
            XBinary::PACKED_UINT puTag1 = {};
            XBinary::PACKED_UINT puTag2 = {};

            if (!state.bIsStop) {
                if (bImm) {
                    if (g_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) {
                        sString = XBinary::appendText(sString, QString::number(nOpcode & XMACH_DEF::S_REBASE_IMMEDIATE_MASK, 16), ", ");
                    } else if ((g_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (g_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
                        sString = XBinary::appendText(sString, QString::number(nOpcode & XMACH_DEF::S_BIND_IMMEDIATE_MASK, 16), ", ");
                    }
                }
            }

            qint32 nOpcodeSize = 1;

            if (!state.bIsStop) {
                if (bString) {
                    qint64 nMaxSize = qMin(state.nMaxSize - state.nCurrentOffset + nOpcodeSize, (qint64)256);
                    QString _sString = XBinary::_read_ansiString(pData + state.nCurrentOffset + nOpcodeSize, nMaxSize - nOpcodeSize);
                    nOpcodeSize += _sString.size() + 1;

                    sString = XBinary::appendText(sString, _sString, ", ");
                }
            }

            if (!state.bIsStop) {
                if (bUleb1) {
                    puTag1 = XBinary::_read_uleb128(pData + state.nCurrentOffset + nOpcodeSize, state.nMaxSize - state.nCurrentOffset - nOpcodeSize);

                    if (puTag1.bIsValid) {
                        sString = XBinary::appendText(sString, QString::number(puTag1.nValue, 16), ", ");
                        nOpcodeSize += puTag1.nByteSize;
                    } else {
                        state.bIsStop = true;
                    }
                }
            }

            if (!state.bIsStop) {
                if (bUleb2) {
                    puTag2 = XBinary::_read_uleb128(pData + state.nCurrentOffset + nOpcodeSize, state.nMaxSize - state.nCurrentOffset - nOpcodeSize);

                    if (puTag2.bIsValid) {
                        sString = XBinary::appendText(sString, QString::number(puTag2.nValue, 16), ", ");
                        nOpcodeSize += puTag2.nByteSize;
                    } else {
                        state.bIsStop = true;
                    }
                }
            }

            if (!state.bIsStop) {
                _addDisasmResult(&listResult, state.nAddress + state.nCurrentOffset, nOpcodeSize, sMnemonic, sString, &state, disasmOptions);
            }

            // if (nOpcode == 0) {
            //     state.bIsStop = true;
            // }
        }
    } else {
        _addDisasmResult(&listResult, nAddress, nDataSize, "ARRAY", "TST", &state, disasmOptions);
    }

    return listResult;
}
