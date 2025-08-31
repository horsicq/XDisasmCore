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

XDisasmAbstract::XDisasmAbstract(QObject *pParent) : QObject(pParent)
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

    if (disasmResult.sOperands != "") {
        sResult += " " + disasmResult.sOperands;
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
            disasmResult.sOperands = disasmResult.sOperands.toUpper();
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

void XDisasmAbstract::_addDisasmResult(QList<DISASM_RESULT> *pListResults, XADDR nAddress, qint32 nSize, const QString &sMnemonic, const QString &sString, STATE *pState,
                                       const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    DISASM_RESULT disasmResult = {};
    disasmResult.bIsValid = true;
    disasmResult.nAddress = nAddress;
    disasmResult.nSize = nSize;
    disasmResult.sMnemonic = sMnemonic;
    disasmResult.sOperands = sString;

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
    if ((nOpcodeID == ARM_INS_B) || (nOpcodeID == ARM_INS_BX)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
    if ((nOpcodeID == ARM64_INS_B) || (nOpcodeID == ARM64_INS_BR)) {
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
    if (nOpcodeID == MIPS_INS_J) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
    if ((nOpcodeID == M68K_INS_BRA) || (nOpcodeID == M68K_INS_JMP)) {
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
        if ((nOpcodeID == X86_INS_RET) || (nOpcodeID == X86_INS_RETF) || (nOpcodeID == X86_INS_RETFQ) || (nOpcodeID == X86_INS_IRET) ||
            (nOpcodeID == X86_INS_IRETD) || (nOpcodeID == X86_INS_IRETQ)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if ((nOpcodeID == ARM64_INS_RET) || (nOpcodeID == ARM64_INS_RETAA) || (nOpcodeID == ARM64_INS_RETAB)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if ((nOpcodeID == BPF_INS_RET) || (nOpcodeID == BPF_INS_EXIT)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if ((nOpcodeID == SPARC_INS_RET) || (nOpcodeID == SPARC_INS_RETL)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((nOpcodeID == MIPS_INS_JR) || (nOpcodeID == MIPS_INS_ERET)) {  // JR ra or exception return
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if ((nOpcodeID == MOS65XX_INS_RTS) || (nOpcodeID == MOS65XX_INS_RTI)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((nOpcodeID == M68K_INS_RTS) || (nOpcodeID == M68K_INS_RTE) || (nOpcodeID == M68K_INS_RTR) || (nOpcodeID == M68K_INS_RTD)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_PPC) {
        if (nOpcodeID == PPC_INS_BLR) {  // Branch to link register (return)
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isPushOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_PUSH) || (nOpcodeID == X86_INS_PUSHF) || (nOpcodeID == X86_INS_PUSHFD) || (nOpcodeID == X86_INS_PUSHFQ)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        // PUSH exists for ARM Thumb; classic ARM uses STMDB SP! which Capstone decodes differently
        if (nOpcodeID == ARM_INS_PUSH) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        // PEA pushes effective address onto the stack
        if (nOpcodeID == M68K_INS_PEA) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        // 6502 push instructions
        if ((nOpcodeID == MOS65XX_INS_PHA) || (nOpcodeID == MOS65XX_INS_PHP)) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XDisasmAbstract::isPopOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_POP) || (nOpcodeID == X86_INS_POPF) || (nOpcodeID == X86_INS_POPFD) || (nOpcodeID == X86_INS_POPFQ)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        // POP exists for ARM Thumb
        if (nOpcodeID == ARM_INS_POP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        // 6502/65xx pull instructions
        if ((nOpcodeID == MOS65XX_INS_PLA) || (nOpcodeID == MOS65XX_INS_PLX) || (nOpcodeID == MOS65XX_INS_PLY) || (nOpcodeID == MOS65XX_INS_PLP)) {
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
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        if ((nOpcodeID == ARM_INS_BL) || (nOpcodeID == ARM_INS_BLX)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if ((nOpcodeID == ARM64_INS_BL) || (nOpcodeID == ARM64_INS_BLR)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((nOpcodeID == MIPS_INS_JAL) || (nOpcodeID == MIPS_INS_JALR)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if ((nOpcodeID == SPARC_INS_CALL) || (nOpcodeID == SPARC_INS_JMPL)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_JSR) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((nOpcodeID == M68K_INS_BSR) || (nOpcodeID == M68K_INS_JSR)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_PPC) {
        if ((nOpcodeID == PPC_INS_BL) || (nOpcodeID == PPC_INS_BLA)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (nOpcodeID == BPF_INS_CALL) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_WASM) {
        if (nOpcodeID == WASM_INS_CALL) {
            bResult = true;
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

bool XDisasmAbstract::isSyscallOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_SYSCALL) {
            bResult = true;
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
