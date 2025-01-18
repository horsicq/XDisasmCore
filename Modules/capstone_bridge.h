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

#ifndef CAPSTONE_BRIDGE_H
#define CAPSTONE_BRIDGE_H

#include "../xdisasmabstract.h"
#include "xcapstone.h"

class Capstone_Bridge : public XDisasmAbstract {
    Q_OBJECT
public:
    explicit Capstone_Bridge(XBinary::DM disasmMode, XBinary::SYNTAX syntax = XBinary::SYNTAX_DEFAULT, QObject *parent = nullptr);
    ~Capstone_Bridge();

    virtual QList<DISASM_RESULT> _disasm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                         XBinary::PDSTRUCT *pPdStruct);

private:
    csh g_handle;
    XBinary::DM g_disasmMode;
    XBinary::DMFAMILY g_disasmFamily;
    XBinary::SYNTAX g_syntax;
};

#endif  // CAPSTONE_BRIDGE_H
