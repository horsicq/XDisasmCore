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

#ifndef X7ZIP_PROPERTIES_H
#define X7ZIP_PROPERTIES_H

#include "../xdisasmabstract.h"
#include "xsevenzip.h"

class X7Zip_Properties : public XDisasmAbstract {
    Q_OBJECT
public:
    explicit X7Zip_Properties(QObject *parent = nullptr);

    virtual QList<DISASM_RESULT> _disasm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                         XBinary::PDSTRUCT *pPdStruct);

private:
    void _addTagId(QList<DISASM_RESULT> *pListResults, quint64 nValue, XSevenZip::EIdEnum id, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    void _handleTag(QList<DISASM_RESULT> *pListResults, char *pData, XSevenZip::EIdEnum id, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    quint64 _handleNumber(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    quint8 _handleByte(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    quint32 _handleUINT32(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    QByteArray _handleArray(QList<DISASM_RESULT> *pListResults, char *pData, qint32 nDataSize, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
};

#endif  // X7ZIP_PROPERTIES_H
