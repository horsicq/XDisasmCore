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

#ifndef XDISASMABSTRACT_H
#define XDISASMABSTRACT_H

#include "xbinary.h"
#include "xcapstone.h"

class XDisasmAbstract : public QObject {
    Q_OBJECT

public:
    struct STATE {
        bool bIsStop;
        XADDR nAddress;
        qint32 nLimit;
        qint64 nMaxSize;
        qint32 nCurrentCount;
        qint64 nCurrentOffset;
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
        bool bMemError;
        XADDR nAddress;
        qint32 nSize;
        quint32 nOpcode;
        QString sMnemonic;
        QString sOperands;
        RELTYPE relType;
        XADDR nXrefToRelative;
        MEMTYPE memType;
        XADDR nXrefToMemory;
        qint32 nMemorySize;
        XADDR nNextAddress;
        bool bIsConst;  // For signatures
        bool bIsRet;
        bool bIsCall;
        bool bIsJmp;
        bool bIsCondJmp;
        quint32 nDispOffset;
        quint32 nDispSize;
        quint32 nImmOffset;
        quint32 nImmSize;
    };

    struct DISASM_OPTIONS {
        bool bIsUppercase;
        bool bNoStrings;
    };

    enum REGS {
        REGS_UNKNOWN = 0,
        REGS_GENERAL,
        REGS_FPU,
        REGS_XMM,
        REGS_STACK,
        REGS_SEGMENT,
        REGS_FLAGS,
        REGS_DEBUG,
        REGS_IP
    };

    explicit XDisasmAbstract(QObject *parent = nullptr);
    virtual QList<DISASM_RESULT> _disasm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                         XBinary::PDSTRUCT *pPdStruct) = 0;

    static QString getNumberString(qint64 nValue, XBinary::DM disasmMode, XBinary::SYNTAX syntax);
    static QString getOpcodeFullString(const DISASM_RESULT &disasmResult);
    static bool isBranchOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);  // mb TODO rename
    static bool isJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isRetOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isPushOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isPopOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isCallOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isCondJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isNopOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isInt3Opcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isSyscallOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID);
    static bool isGeneralRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isStackRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isSegmentRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isDebugRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isInstructionPointerRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isFlagsRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isFPURegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isXMMRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);
    static bool isRef(XBinary::DMFAMILY dmFamily, const QString &sOperand, XBinary::SYNTAX syntax);
    static bool isNumber(XBinary::DMFAMILY dmFamily, const QString &sNumber, XBinary::SYNTAX syntax);

    static QString removeRegPrefix(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax);

    void _addDisasmResult(QList<DISASM_RESULT> *pListResults, DISASM_RESULT &disasmResult, STATE *pState, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
    void _addDisasmResult(QList<DISASM_RESULT> *pListResults, XADDR nAddress, qint32 nSize, const QString &sMnemonic, const QString &sString, STATE *pState,
                          const XDisasmAbstract::DISASM_OPTIONS &disasmOptions);
};

#endif  // XDISASMABSTRACT_H
