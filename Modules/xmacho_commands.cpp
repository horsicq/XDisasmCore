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

quint64 XMachO_Commands::_handleULEB128(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions, QString sPrefix)
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

QString XMachO_Commands::_handleAnsiString(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions, QString sPrefix)
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
    } else {
        _addDisasmResult(&listResult, nAddress, nDataSize, "ARRAY", "TST", &state, disasmOptions);
    }

    return listResult;
}
