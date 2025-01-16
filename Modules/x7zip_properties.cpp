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

#include "x7zip_properties.h"

X7Zip_Properties::X7Zip_Properties(QObject *parent)
    : XDisasmAbstract(parent)
{

}

QList<XDisasmAbstract::DISASM_RESULT> X7Zip_Properties::_disasm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions, qint32 nLimit, XBinary::PDSTRUCT *pPdStruct)
{
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    qint32 nCount = 0;
    qint32 nCurrentSize = 0;

    while ((nCurrentSize < nDataSize) && (!(pPdStruct->bIsStop)))  {
        XDisasmAbstract::DISASM_RESULT result = {};
        result.nAddress = nAddress;
        result.sMnemonic = "TEST";
        result.nSize = 1;
        result.bIsValid = true;

        if (disasmOptions.bIsUppercase) {
            result.sMnemonic = result.sMnemonic.toUpper();
            result.sString = result.sString.toUpper();
        }

        listResult.append(result);

        nCount++;

        if (nLimit > 0) {
            if (nCount > nLimit) {
                break;
            }
        } else if (nLimit == 0) {
            if (!result.bIsValid) {
                break;
            }
        }

        pData += result.nSize;
        nAddress += result.nSize;
        nCurrentSize += result.nSize;
    }

    return listResult;
}
