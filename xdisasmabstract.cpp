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

#include "xdisasmabstract.h"

XDisasmAbstract::XDisasmAbstract(QObject *parent) : QObject(parent)
{
}

QString XDisasmAbstract::getNumberString(qint64 nValue, XBinary::DM disasmMode, XBinary::SYNTAX syntax)
{
    QString sResult;

    if ((disasmMode == XBinary::DM_X86_16) || (disasmMode == XBinary::DM_X86_32) || (disasmMode == XBinary::DM_X86_64)) {
        if (nValue < 0) {
            sResult += "- ";
        }
        nValue = qAbs(nValue);

        if (nValue < 10) {
            sResult += QString::number(nValue);
        } else {
            if ((syntax == XBinary::SYNTAX_DEFAULT) || (syntax == XBinary::SYNTAX_INTEL) || (syntax == XBinary::SYNTAX_ATT)) {
                sResult += QString("0x%1").arg(QString::number(nValue, 16));
            } else if (syntax == XBinary::SYNTAX_MASM) {
                sResult += QString("%1h").arg(QString::number(nValue, 16));
            }
        }
    } else {
        sResult += QString("0x%1").arg(QString::number(nValue, 16));
    }

    return sResult;
}

QString XDisasmAbstract::getOpcodeFullString(const DISASM_RESULT &disasmResult)
{
    QString sResult = disasmResult.sMnemonic;

    if (disasmResult.sString != "") {
        sResult += " " + disasmResult.sString;
    }

    return sResult;
}

void XDisasmAbstract::_addDisasmResult(QList<DISASM_RESULT> *pListResults, DISASM_RESULT &disasmResult, STATE *pState,
                                       const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    if (pState->nLimit == 0) {
        if (!disasmResult.bIsValid) {
            pState->bIsStop = true;
        }
    }

    if (!(pState->bIsStop)) {
        if (disasmOptions.bIsUppercase) {
            disasmResult.sMnemonic = disasmResult.sMnemonic.toUpper();
            disasmResult.sString = disasmResult.sString.toUpper();
        }

        pListResults->append(disasmResult);
        pState->nCurrentCount++;
        pState->nCurrentOffset += disasmResult.nSize;
    }

    if ((pState->nLimit > 0) && (pState->nCurrentCount > pState->nLimit)) {
        pState->bIsStop = true;
    } else if (pState->nCurrentOffset >= pState->nMaxSize) {
        pState->bIsStop = true;
    }
}

void XDisasmAbstract::_addDisasmResult(QList<DISASM_RESULT> *pListResults, XADDR nAddress, qint32 nSize, QString sMnemonic, QString sString, STATE *pState,
                                       const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    DISASM_RESULT disasmResult = {};
    disasmResult.bIsValid = true;
    disasmResult.nAddress = nAddress;
    disasmResult.nSize = nSize;
    disasmResult.sMnemonic = sMnemonic;
    disasmResult.sString = sString;

    _addDisasmResult(pListResults, disasmResult, pState, disasmOptions);
}
