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

#ifndef XDISASMCORE_H
#define XDISASMCORE_H

#include "xcapstone.h"

#ifdef QT_GUI_LIB
#include <QColor>
#endif

class XDisasmCore : public QObject {
    Q_OBJECT
public:
    enum ST {
        ST_UNKNOWN = 0,
        ST_FULL,
        ST_MASK,
        ST_REL
    };

    enum RELTYPE {
        RELTYPE_NONE = 0,
        RELTYPE_ALL,
        RELTYPE_JMP = 0x10,
        RELTYPE_JMP_UNCOND,
        RELTYPE_JMP_COND,
        RELTYPE_CALL = 0x20
    };

    enum MEMTYPE {
        MEMTYPE_NONE = 0,
        MEMTYPE_READ,
        MEMTYPE_WRITE,
        MEMTYPE_ACCESS
    };

    struct DISASM_RESULT {
        bool bIsValid;
        XADDR nAddress;
        qint32 nSize;
        quint32 nOpcode;
        QString sMnemonic;
        QString sString;
        RELTYPE relType;
        XADDR nXrefToRelative;
        MEMTYPE memType;
        XADDR nXrefToMemory;
        qint32 nMemorySize;
        XADDR nNextAddress;
        bool bIsConst;  // For signatures
        quint32 nDispOffset;
        quint32 nDispSize;
        quint32 nImmOffset;
        quint32 nImmSize;
    };

    struct DISASM_OPTIONS {
        bool bIsUppercase;
    };

    struct SIGNATURE_RECORD {
        XADDR nAddress;
        QString sOpcode;
        QByteArray baOpcode;
        qint32 nDispOffset;
        qint32 nDispSize;
        qint32 nImmOffset;
        qint32 nImmSize;
        bool bIsConst;
    };

    enum OG {
        OG_UNKNOWN = 0,
        OG_ARROWS,
        OG_ARROWS_SELECTED,
        OG_REGS,
        OG_NUMBERS,
        OG_OPCODE,
        OG_REFS,
        OG_REGS_GENERAL,
        OG_REGS_STACK,
        OG_REGS_SEGMENT,
        OG_REGS_DEBUG,
        OG_REGS_IP,
        OG_REGS_FLAGS,
        OG_REGS_FPU,
        OG_REGS_XMM,
        OG_OPCODE_CALL,
        OG_OPCODE_RET,
        OG_OPCODE_PUSH,
        OG_OPCODE_POP,
        OG_OPCODE_NOP,
        OG_OPCODE_JMP,
        OG_OPCODE_CONDJMP,
        OG_OPCODE_INT3,
        OG_OPCODE_SYSCALL
    };

#ifdef QT_GUI_LIB
    struct COLOR_RECORD {
        QColor colMain;
        QColor colBackground;
    };
#endif

    explicit XDisasmCore(QObject *pParent = nullptr);
    ~XDisasmCore();

    void setMode(XBinary::DM disasmMode, XBinary::SYNTAX syntax = XBinary::SYNTAX_DEFAULT);

    DISASM_RESULT disAsm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions);
    DISASM_RESULT disAsm(QIODevice *pDevice, qint64 nOffset, XADDR nAddress, const DISASM_OPTIONS &disasmOptions);

    QString getNumberString(qint64 nNumber);

    XBinary::SYNTAX getSyntax();

    QString getSignature(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, ST signatureType, qint32 nCount);
    QList<XDisasmCore::SIGNATURE_RECORD> getSignatureRecords(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, qint64 nOffset, qint32 nCount,
                                                                  ST signatureType);
    static QString replaceWildChar(const QString &sString, qint32 nOffset, qint32 nSize, QChar cWild);  // Move to XBinary

private:
    XBinary::DM g_disasmMode;
    XBinary::DMFAMILY g_disasmFamily;
    XBinary::SYNTAX g_syntax;
    bool g_bIsCapstone;
    csh g_handle;
    qint32 g_nOpcodeSize;
};

#endif  // XDISASMCORE_H
