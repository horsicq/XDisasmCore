/* Copyright (c) 2025-2026 hors<horsicq@gmail.com>
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

// XBinary only provides an unsigned ULEB128 reader. Mach-O bind streams use a signed LEB128 for
// SET_ADDEND_SLEB, so decode the unsigned magnitude with the shared reader and sign-extend it here.
static XBinary::PACKED_UINT machoReadSleb128(char *pData, qint64 nSize, qint64 *pnSignedValue)
{
    XBinary::PACKED_UINT result = XBinary::_read_uleb128(pData, nSize);

    qint64 nSigned = (qint64)result.nValue;

    if (result.bIsValid && (result.nByteSize > 0)) {
        const qint32 nBits = result.nByteSize * 7;

        if ((nBits < 64) && (result.nValue & ((quint64)1 << (nBits - 1)))) {
            nSigned |= -((qint64)1 << nBits);  // sign bit set -> sign-extend to 64 bits
        }
    }

    *pnSignedValue = nSigned;

    return result;
}

XMachO_Commands::XMachO_Commands(XBinary::DM disasmMode, QObject *pParent) : XDisasmAbstract(pParent)
{
    m_disasmMode = disasmMode;
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
        return {};
    }

    qint64 nMaxSize = qMin(pState->nMaxSize - pState->nCurrentOffset, (qint64)256);
    QString sResult = XBinary::_read_ansiString(pData + pState->nCurrentOffset, nMaxSize);

    if (!sResult.isEmpty()) {
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
    state.nLimit = nLimit;
    state.nMaxSize = nDataSize;
    state.nAddress = nAddress;

    if (m_disasmMode == XBinary::DM_CUSTOM_MACH_EXPORT) {
        while (!(state.bIsStop) && XBinary::isPdStructNotCanceled(pPdStruct)) {
            quint64 nTerminalSize = _handleULEB128(&listResult, pData, &state, disasmOptions, "TERMINAL_SIZE");

            // The terminal payload occupies exactly nTerminalSize bytes. Regular exports store FLAGS +
            // SYMBOL_OFFSET, but re-export and stub-and-resolver kinds carry extra bytes. Bound the payload
            // by its declared size so CHILD_COUNT is always read from the correct offset regardless of kind.
            const qint64 nTermPayloadStart = state.nCurrentOffset;

            if (nTerminalSize > 0) {
                _handleULEB128(&listResult, pData, &state, disasmOptions, "FLAGS");
                _handleULEB128(&listResult, pData, &state, disasmOptions, "SYMBOL_OFFSET");

                if (!state.bIsStop) {
                    const qint64 nTermPayloadEnd = nTermPayloadStart + (qint64)nTerminalSize;

                    if ((nTermPayloadEnd >= nTermPayloadStart) && (nTermPayloadEnd <= state.nMaxSize)) {
                        state.nCurrentOffset = nTermPayloadEnd;  // skip any unparsed terminal bytes
                    } else {
                        state.bIsStop = true;
                    }
                }
            }

            quint64 nChildCount = 0;

            if (!state.bIsStop) {
                nChildCount = _handleULEB128(&listResult, pData, &state, disasmOptions, "CHILD_COUNT");
            }

            for (quint64 i = 0; (i < nChildCount) && (!state.bIsStop); i++) {
                _handleAnsiString(&listResult, pData, &state, disasmOptions, "NODE_LABEL");
                _handleULEB128(&listResult, pData, &state, disasmOptions, "NODE_OFFSET");
            }

            if ((nTerminalSize == 0) && (nChildCount == 0)) {
                state.bIsStop = true;
            }
        }
    } else if ((m_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) || (m_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (m_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
        while (!(state.bIsStop)) {
            if (state.nCurrentOffset >= state.nMaxSize) {
                state.bIsStop = true;
                break;
            }

            quint8 nOpcode = XBinary::_read_uint8(pData + state.nCurrentOffset);

            bool bString = false;
            bool bUleb1 = false;
            bool bUleb2 = false;
            bool bImm = false;
            bool bSleb1 = false;

            QString sMnemonic;

            if (m_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) {
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
            } else if ((m_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (m_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
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
                        bSleb1 = true;  // signed LEB128, not unsigned
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
                    if (m_disasmMode == XBinary::DM_CUSTOM_MACH_REBASE) {
                        sString = XBinary::appendText(sString, QString::number(nOpcode & XMACH_DEF::S_REBASE_IMMEDIATE_MASK, 16), ", ");
                    } else if ((m_disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (m_disasmMode == XBinary::DM_CUSTOM_MACH_WEAK)) {
                        sString = XBinary::appendText(sString, QString::number(nOpcode & XMACH_DEF::S_BIND_IMMEDIATE_MASK, 16), ", ");
                    }
                }
            }

            qint32 nOpcodeSize = 1;

            if (!state.bIsStop) {
                if (bString) {
                    // The readable window is the bytes AFTER the opcode byte: (nMaxSize - nCurrentOffset - nOpcodeSize).
                    // The previous form added nOpcodeSize instead of subtracting it, over-reading the buffer by nOpcodeSize.
                    qint64 nStrMax = qMin(state.nMaxSize - state.nCurrentOffset - nOpcodeSize, (qint64)256);

                    if (nStrMax > 0) {
                        QString _sString = XBinary::_read_ansiString(pData + state.nCurrentOffset + nOpcodeSize, (qint32)nStrMax);
                        nOpcodeSize += _sString.size() + 1;

                        sString = XBinary::appendText(sString, _sString, ", ");
                    } else {
                        state.bIsStop = true;
                    }
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
                if (bSleb1) {
                    qint64 nSignedValue = 0;
                    XBinary::PACKED_UINT puSleb =
                        machoReadSleb128(pData + state.nCurrentOffset + nOpcodeSize, state.nMaxSize - state.nCurrentOffset - nOpcodeSize, &nSignedValue);

                    if (puSleb.bIsValid) {
                        QString sNum;

                        if (nSignedValue < 0) {
                            sNum = QString("-%1").arg(QString::number(-nSignedValue, 16));
                        } else {
                            sNum = QString::number(nSignedValue, 16);
                        }

                        sString = XBinary::appendText(sString, sNum, ", ");
                        nOpcodeSize += puSleb.nByteSize;
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

            // 0x00 is REBASE_OPCODE_DONE / BIND_OPCODE_DONE and terminates the stream. Stop after emitting the
            // DONE record so trailing padding is not decoded into a run of spurious DONE instructions.
            if (nOpcode == 0) {
                state.bIsStop = true;
            }
        }
    }
    // Any other mode is not handled by this backend; return an empty list rather than a fabricated
    // "ARRAY TST" record. (XDisasmCore::setMode only routes the four custom Mach-O modes here.)

    return listResult;
}
