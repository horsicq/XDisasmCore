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

XDisasmAbstract::DISASM_RESULT_EX XDisasmAbstract::disAsmEx(char *pData, qint32 nDataSize, XADDR nAddress)
{
    DISASM_RESULT_EX result = {};

    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();

    DISASM_OPTIONS options = {};
    QList<DISASM_RESULT> list = _disasm(pData, nDataSize, nAddress, options, 1, &pdStructEmpty);

    if (list.count()) {
        result.bIsValid = list.at(0).bIsValid;
        result.bMemError = list.at(0).bMemError;
        result.nAddress = list.at(0).nAddress;
        result.nSize = list.at(0).nSize;
        result.nOpcode = list.at(0).nOpcode;
        result.relType = list.at(0).relType;
        result.nXrefToRelative = list.at(0).nXrefToRelative;
        result.memType = list.at(0).memType;
        result.nXrefToMemory = list.at(0).nXrefToMemory;
        result.nMemorySize = list.at(0).nMemorySize;
        result.nNextAddress = list.at(0).nNextAddress;
        result.nDispOffset = list.at(0).nDispOffset;
        result.nDispSize = list.at(0).nDispSize;
        result.nImmOffset = list.at(0).nImmOffset;
        result.nImmSize = list.at(0).nImmSize;
    } else {
        result.bIsValid = false;
        result.nAddress = nAddress;
    }

    return result;
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

bool XDisasmAbstract::isBranchOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    return isJumpOpcode(dmFamily, nOpcodeID) || isCondJumpOpcode(dmFamily, nOpcodeID) || isCallOpcode(dmFamily, nOpcodeID);
}

bool XDisasmAbstract::isJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        if (nOpcodeID == ARM_INS_B) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (nOpcodeID == ARM64_INS_B) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (nOpcodeID == BPF_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((nOpcodeID == MIPS_INS_J) || (nOpcodeID == MIPS_INS_JAL)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (nOpcodeID == M68K_INS_BRA) {
            bResult = true;
        }
    }

    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isJumpOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        if (sOpcode == "b") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (sOpcode == "b") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((sOpcode == "j") || (sOpcode == "jal")) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (sOpcode == "bra") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isRetOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_RET) || (nOpcodeID == X86_INS_RETF) || (nOpcodeID == X86_INS_RETFQ)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (nOpcodeID == ARM64_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (nOpcodeID == BPF_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if (nOpcodeID == MIPS_INS_JR) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((nOpcodeID == M68K_INS_RTS) || (nOpcodeID == M68K_INS_RTE) || (nOpcodeID == M68K_INS_RTR) || (nOpcodeID == M68K_INS_RTD)) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isRetOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "retw") || (sOpcode == "retl") || (sOpcode == "retq")) {
                bResult = true;
            }
        } else {
            if ((sOpcode == "ret") || (sOpcode == "retf")) {
                bResult = true;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (sOpcode == "ret") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((sOpcode == "rte") || (sOpcode == "rts") || (sOpcode == "rtr") || (sOpcode == "rtd")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isCallOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_CALL) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isCallOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "callw") || (sOpcode == "calll") || (sOpcode == "callq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "call") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isCondJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_JA) || (nOpcodeID == X86_INS_JAE) || (nOpcodeID == X86_INS_JB) || (nOpcodeID == X86_INS_JBE) || (nOpcodeID == X86_INS_JCXZ) ||
            (nOpcodeID == X86_INS_JE) || (nOpcodeID == X86_INS_JECXZ) || (nOpcodeID == X86_INS_JG) || (nOpcodeID == X86_INS_JGE) || (nOpcodeID == X86_INS_JL) ||
            (nOpcodeID == X86_INS_JLE) || (nOpcodeID == X86_INS_JNE) || (nOpcodeID == X86_INS_JNO) || (nOpcodeID == X86_INS_JNP) || (nOpcodeID == X86_INS_JNS) ||
            (nOpcodeID == X86_INS_JO) || (nOpcodeID == X86_INS_JP) || (nOpcodeID == X86_INS_JRCXZ) || (nOpcodeID == X86_INS_JS) || (nOpcodeID == X86_INS_LOOP) ||
            (nOpcodeID == X86_INS_LOOPE) || (nOpcodeID == X86_INS_LOOPNE)) {
            bResult = true;
        }
    }

    return bResult;
}

bool XDisasmAbstract::isCondJumpOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sOpcode == "je") || (sOpcode == "jne") || (sOpcode == "jz") || (sOpcode == "jnz") || (sOpcode == "ja") || (sOpcode == "jc") || (sOpcode == "jb") ||
            (sOpcode == "jo") || (sOpcode == "jno") || (sOpcode == "js") || (sOpcode == "jns") || (sOpcode == "jae") || (sOpcode == "jbe") || (sOpcode == "jl") ||
            (sOpcode == "jge") || (sOpcode == "jg") || (sOpcode == "jb") || (sOpcode == "loop") || (sOpcode == "loopne") || (sOpcode == "loope")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isNopOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (nOpcodeID == M68K_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if (nOpcodeID == MIPS_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_WASM) {
        if (nOpcodeID == WASM_INS_NOP) {
            bResult = true;
        }
    }

    return bResult;
}

bool XDisasmAbstract::isNopOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "nopw") || (sOpcode == "nopl") || (sOpcode == "nopq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "nop") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isInt3Opcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_INT3) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isInt3Opcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "int3") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isSyscallOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "syscall") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isPushOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "pushw") || (sOpcode == "pushl") || (sOpcode == "pushq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "push") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isPopOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "popw") || (sOpcode == "popl") || (sOpcode == "popq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "pop") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isGeneralRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = sRegister;

        if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sRegister.size();

            if (nSize >= 2) {
                if (_sRegister.at(0) == QChar('%')) {
                    bResult = true;
                    _sRegister = _sRegister.right(_sRegister.size() - 1);
                }
            }
        } else {
            bResult = true;
        }

        if (bResult) {
            if ((_sRegister == "al") || (_sRegister == "ah") || (_sRegister == "bl") || (_sRegister == "bh") || (_sRegister == "cl") || (_sRegister == "ch") ||
                (_sRegister == "dl") || (_sRegister == "dh") || (_sRegister == "ax") || (_sRegister == "bx") || (_sRegister == "cx") || (_sRegister == "dx") ||
                (_sRegister == "si") || (_sRegister == "di") || (_sRegister == "sp") || (_sRegister == "bp") || (_sRegister == "eax") || (_sRegister == "ebx") ||
                (_sRegister == "ecx") || (_sRegister == "edx") || (_sRegister == "esi") || (_sRegister == "edi") || (_sRegister == "esp") || (_sRegister == "ebp") ||
                (_sRegister == "rax") || (_sRegister == "rbx") || (_sRegister == "rcx") || (_sRegister == "rdx") || (_sRegister == "rsi") || (_sRegister == "rdi") ||
                (_sRegister == "rsp") || (_sRegister == "rbp") || (_sRegister == "r8") || (_sRegister == "r9") || (_sRegister == "r10") || (_sRegister == "r11") ||
                (_sRegister == "r12") || (_sRegister == "r13") || (_sRegister == "r14") || (_sRegister == "r15") || (_sRegister == "r8b") || (_sRegister == "r9b") ||
                (_sRegister == "r10b") || (_sRegister == "r11b") || (_sRegister == "r12b") || (_sRegister == "r13b") || (_sRegister == "r14b") ||
                (_sRegister == "r15b") || (_sRegister == "r8d") || (_sRegister == "r9d") || (_sRegister == "r10d") || (_sRegister == "r11d") || (_sRegister == "r12d") ||
                (_sRegister == "r13d") || (_sRegister == "r14d") || (_sRegister == "r15d")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        qint32 nSize = sRegister.size();

        if (nSize >= 2) {
            if (sRegister.at(0) == QChar('r')) {
                bResult = true;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        qint32 nSize = sRegister.size();

        if (nSize >= 2) {
            if (sRegister.at(0) == QChar('x')) {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isStackRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = removeRegPrefix(dmFamily, sRegister, syntax);

        if (_sRegister != "") {
            if ((_sRegister == "sp") || (_sRegister == "bp") || (_sRegister == "esp") || (_sRegister == "ebp") || (_sRegister == "rsp") || (_sRegister == "rbp")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        if (sRegister == "sp") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isSegmentRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = removeRegPrefix(dmFamily, sRegister, syntax);

        if (_sRegister != "") {
            if ((sRegister == "es") || (sRegister == "gs") || (sRegister == "ss") || (sRegister == "ds") || (sRegister == "cs") || (sRegister == "fs")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isDebugRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "dr0") || (sRegister == "dr1") || (sRegister == "dr2") || (sRegister == "dr3") || (sRegister == "dr6") || (sRegister == "dr7")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isInstructionPointerRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "ip") || (sRegister == "eip") || (sRegister == "rip")) {
            bResult = true;
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        if (sRegister == "pc") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isFlagsRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "flags") || (sRegister == "eflags") || (sRegister == "rflags")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isFPURegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)
    Q_UNUSED(sRegister)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        // TODO
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isXMMRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        qint32 nSize = sRegister.size();

        if (syntax == XBinary::SYNTAX_ATT) {
            if (nSize >= 5) {
                if (sRegister.left(4) == "%xmm") {
                    bResult = true;
                }
            }
        } else {
            if (nSize >= 4) {
                if (sRegister.left(3) == "xmm") {
                    bResult = true;
                }
            }
        }
    }

    return bResult;
}

bool XDisasmAbstract::isRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    return (isGeneralRegister(dmFamily, sRegister, syntax) || isSegmentRegister(dmFamily, sRegister, syntax) || isDebugRegister(dmFamily, sRegister, syntax) ||
            isInstructionPointerRegister(dmFamily, sRegister, syntax) || isFlagsRegister(dmFamily, sRegister, syntax) || isFPURegister(dmFamily, sRegister, syntax) ||
            isXMMRegister(dmFamily, sRegister, syntax));
}

bool XDisasmAbstract::isRef(XBinary::DMFAMILY dmFamily, const QString &sOperand, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    Q_UNUSED(dmFamily)
    Q_UNUSED(syntax)

    if (sOperand.contains("<")) {
        bResult = true;
    }

    return bResult;
}

bool XDisasmAbstract::isNumber(XBinary::DMFAMILY dmFamily, const QString &sNumber, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((syntax == XBinary::SYNTAX_DEFAULT) || (syntax == XBinary::SYNTAX_INTEL)) {
            qint32 nSize = sNumber.size();
            if (nSize == 1) {
                bResult = true;
            } else if (nSize >= 2) {
                if (sNumber.left(2) == "0x") {
                    bResult = true;
                } else if (sNumber.at(0) == QChar('-')) {
                    bResult = true;
                }
            }
        } else if (syntax == XBinary::SYNTAX_MASM) {
            qint32 nSize = sNumber.size();
            if (nSize == 1) {
                bResult = true;
            } else if (nSize > 1) {
                if (sNumber.right(1) == "h") {
                    bResult = true;
                }
            }
        } else if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sNumber.size();
            if ((nSize >= 2) && (sNumber.at(0) == QChar('$')) && (!sNumber.contains(", "))) {
                bResult = true;
            }
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        // TODO
    }
    // TODO Other archs

    return bResult;
}

QString XDisasmAbstract::removeRegPrefix(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    QString sResult = sRegister;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sRegister.size();

            sResult = "";

            if (nSize >= 2) {
                if (sRegister.at(0) == QChar('%')) {
                    sResult = sRegister.right(sRegister.size() - 1);
                }
            }
        }
    }

    return sResult;
}
