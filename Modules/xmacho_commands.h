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

#ifndef XMACHO_COMMANDS_H
#define XMACHO_COMMANDS_H

#include "../xdisasmabstract.h"
#include "xmach.h"

class XMachO_Commands : public XDisasmAbstract {
    Q_OBJECT

public:
    explicit XMachO_Commands(XBinary::DM disasmMode, QObject *parent = nullptr);

    virtual QList<DISASM_RESULT> _disasm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                         XBinary::PDSTRUCT *pPdStruct);

private:
    quint64 _handleULEB128(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions, const QString &sPrefix);
    QString _handleAnsiString(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions,
                              const QString &sPrefix);

private:
    XBinary::DM g_disasmMode;
};

#endif  // XMACHO_COMMANDS_H
