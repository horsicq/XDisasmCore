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

#include "xdisasmcore.h"

XDisasmCore::XDisasmCore(QObject *pParent) : QObject(pParent)
{
    m_disasmMode = XBinary::DM_UNKNOWN;
    m_disasmFamily = XBinary::DMFAMILY_UNKNOWN;
    m_pDisasmAbstract = nullptr;
    m_nOpcodeSize = 15;
    m_syntax = XBinary::SYNTAX_DEFAULT;
    m_pOptions = nullptr;
#ifdef QT_GUI_LIB
    m_qTextOptions.setWrapMode(QTextOption::NoWrap);
#endif
}

XDisasmCore::~XDisasmCore()
{
    if (m_pDisasmAbstract) {
        delete m_pDisasmAbstract;
        // XCapstone::closeHandle(&m_handle);
    }
}

void XDisasmCore::setMode(XBinary::DM disasmMode)
{
    if (m_disasmMode != disasmMode) {
        if (m_pDisasmAbstract) {
            delete m_pDisasmAbstract;
            m_pDisasmAbstract = nullptr;
        }

        if (XCapstone::isModeValid(disasmMode)) {
            m_pDisasmAbstract = new Capstone_Bridge(disasmMode, m_syntax);
        } else if (disasmMode == XBinary::DM_CUSTOM_7ZIP_PROPERTIES) {
            m_pDisasmAbstract = new X7Zip_Properties();
        } else if ((disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (disasmMode == XBinary::DM_CUSTOM_MACH_WEAK) || (disasmMode == XBinary::DM_CUSTOM_MACH_EXPORT) ||
                   (disasmMode == XBinary::DM_CUSTOM_MACH_REBASE)) {
            m_pDisasmAbstract = new XMachO_Commands(disasmMode);
        }

        m_disasmMode = disasmMode;
        m_disasmFamily = XBinary::getDisasmFamily(disasmMode);
    }
}

void XDisasmCore::setSyntax(XBinary::SYNTAX syntax)
{
    if (m_syntax != syntax) {
        m_syntax = syntax;
        XBinary::DM disasmMode = m_disasmMode;
        m_disasmMode = XBinary::DM_UNKNOWN;
        setMode(disasmMode);  // Reload
    }
}

void XDisasmCore::setOptions(XOptions *pOptions)
{
    m_pOptions = pOptions;
    setSyntax(XBinary::stringToSyntaxId(pOptions->getValue(XOptions::ID_DISASM_SYNTAX).toString()));

    m_mapColors = getColorRecordsMap(pOptions, m_disasmMode);
}

XBinary::DMFAMILY XDisasmCore::getDisasmFamily()
{
    return m_disasmFamily;
}

XBinary::SYNTAX XDisasmCore::getSyntax()
{
    return m_syntax;
}

QString XDisasmCore::getSignature(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, ST signatureType, qint32 nCount)
{
    QString sResult;

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};

    while (nCount > 0) {
        qint64 nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);

        if (nOffset == -1) {
            break;
        }

        QByteArray baData = XBinary::read_array(pDevice, nOffset, 15);

        XDisasmAbstract::DISASM_RESULT _disasmResult = disAsm(baData.data(), baData.size(), nAddress, disasmOptions);

        if (_disasmResult.bIsValid) {
            baData.resize(_disasmResult.nSize);

            QString sHEX = baData.toHex().data();

            if ((signatureType == ST_FULL) || (signatureType == ST_MASK)) {
                nAddress += _disasmResult.nSize;

                if (signatureType == ST_MASK) {
                    if (_disasmResult.nDispSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nDispOffset, _disasmResult.nDispSize, '.');
                    }

                    if (_disasmResult.nImmSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '.');
                    }
                }
            } else if (signatureType == ST_REL) {
                bool bIsJump = false;

                nAddress = _disasmResult.nNextAddress;

                if ((pMemoryMap->fileType == XBinary::FT_COM) && (_disasmResult.nImmSize == 2)) {
                    if (nAddress > 0xFFFF) {
                        nAddress &= 0xFFFF;
                    }
                }

                if (XDisasmAbstract::isBranchOpcode(m_disasmFamily, _disasmResult.nOpcode)) {
                    // TODO another archs !!!
                    if (m_disasmFamily == XBinary::DMFAMILY_X86) {
                        if (_disasmResult.nImmSize) {
                            sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '$');
                        }

                        bIsJump = true;
                    }
                }

                if (!bIsJump) {
                    if (_disasmResult.nDispSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nDispOffset, _disasmResult.nDispSize, '.');
                    }

                    if (_disasmResult.nImmSize) {
                        sHEX = replaceWildChar(sHEX, _disasmResult.nImmOffset, _disasmResult.nImmSize, '.');
                    }
                }
            }

            sResult += sHEX;
        } else {
            break;
        }

        nCount--;
    }

    return sResult;
}

QList<XDisasmCore::SIGNATURE_RECORD> XDisasmCore::getSignatureRecords(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, qint64 nOffset, qint32 nCount,
                                                                      ST signatureType)
{
    QList<SIGNATURE_RECORD> listResult;

    XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};

    bool bStopBranch = false;

    for (qint32 i = 0; (i < nCount) && (!bStopBranch); i++) {
        if (nOffset != -1) {
            XADDR nAddress = XBinary::offsetToAddress(pMemoryMap, nOffset);

            QByteArray baData = XBinary::read_array(pDevice, nOffset, 15);

            XDisasmAbstract::DISASM_RESULT _disasmResult = disAsm(baData.data(), baData.size(), nAddress, disasmOptions);

            if (_disasmResult.bIsValid) {
                bStopBranch = !XBinary::isOffsetValid(pMemoryMap, nOffset + _disasmResult.nSize - 1);

                if (!bStopBranch) {
                    XDisasmCore::SIGNATURE_RECORD record = {};

                    record.nAddress = nAddress;
                    record.sOpcode = _disasmResult.sMnemonic;

                    if (_disasmResult.sOperands != "") {
                        record.sOpcode += " " + _disasmResult.sOperands;
                    }

                    baData.resize(_disasmResult.nSize);

                    record.baOpcode = baData;

                    record.nDispOffset = _disasmResult.nDispOffset;
                    record.nDispSize = _disasmResult.nDispSize;
                    record.nImmOffset = _disasmResult.nImmOffset;
                    record.nImmSize = _disasmResult.nImmSize;

                    if ((signatureType == ST_FULL) || (signatureType == ST_MASK)) {
                        nAddress += _disasmResult.nSize;
                    } else if (signatureType == ST_REL) {
                        nAddress = _disasmResult.nNextAddress;
                        record.bIsConst = _disasmResult.bIsConst;
                    }

                    if ((pMemoryMap->fileType == XBinary::FT_COM) && (_disasmResult.nImmSize == 2)) {
                        if (nAddress > 0xFFFF) {
                            nAddress &= 0xFFFF;
                        }
                    }

                    listResult.append(record);
                }
            } else {
                bStopBranch = true;
            }

            nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);
        }
    }

    return listResult;
}

QString XDisasmCore::replaceWildChar(const QString &sString, qint32 nOffset, qint32 nSize, QChar cWild)
{
    QString sResult = sString;
    QString sWild;

    sWild = sWild.fill(cWild, nSize * 2);

    sResult = sResult.replace(nOffset * 2, nSize * 2, sWild);

    return sResult;
}

QString XDisasmCore::getNumberString(qint64 nValue)
{
    return XDisasmAbstract::getNumberString(nValue, m_disasmMode, m_syntax);
}
#ifdef QT_GUI_LIB
void XDisasmCore::drawDisasmText(QPainter *pPainter, QRectF rectText, const XDisasmAbstract::DISASM_RESULT &disasmResult)
{
    if (pPainter) {
        pPainter->save();

        XOptions::COLOR_RECORD colorRecord = XOptions::COLOR_RECORD();

        if (!disasmResult.sMnemonic.isEmpty()) {
            QRectF _rectMnemonic = rectText;
            _rectMnemonic.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, disasmResult.sMnemonic).width());

            colorRecord = getOpcodeColor(disasmResult.nOpcode);

            drawColorText(pPainter, _rectMnemonic, disasmResult.sMnemonic, colorRecord);
        }

        if (!disasmResult.sOperands.isEmpty()) {
            QRectF _rectOperands = rectText;
            qreal _dLeft = QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, disasmResult.sMnemonic + " ").width();
            _rectOperands.setLeft(_rectOperands.left() + _dLeft);

            if (!XDisasmAbstract::isNopOpcode(m_disasmFamily, disasmResult.nOpcode)) {
                QString sCurrent;
                QRectF _rectCurrent = _rectOperands;
                qint32 nNumberOfChars = disasmResult.sOperands.size();

                for (qint32 i = 0; i < nNumberOfChars; i++) {
                    QChar ch = disasmResult.sOperands.at(i);
                    if ((ch == ',') || (ch == '[') || (ch == ']') || (ch == '+') || (ch == '-') || (ch == '*') || (ch == '(') || (ch == ')') || (ch == ':') ||
                        (ch == ' ')) {
                        if (!sCurrent.isEmpty()) {
                            drawOperand(pPainter, _rectCurrent, sCurrent);
                        }
                        sCurrent = "";

                        pPainter->drawText(_rectOperands, ch, m_qTextOptions);
                    } else {
                        sCurrent.append(ch);
                    }

                    qreal _dLeft = QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, disasmResult.sOperands.at(i)).width();
                    _rectOperands.setLeft(_rectOperands.left() + _dLeft);

                    if (sCurrent.isEmpty()) {
                        _rectCurrent = _rectOperands;
                    }
                }

                if (!sCurrent.isEmpty()) {
                    drawOperand(pPainter, _rectCurrent, sCurrent);
                }
            } else {
                drawColorText(pPainter, _rectOperands, disasmResult.sOperands, colorRecord);
            }
        }

        pPainter->restore();
    }
}
#endif
#ifdef QT_GUI_LIB
void XDisasmCore::drawOperand(QPainter *pPainter, QRectF rectText, const QString &sOperand)
{
    bool bRef = false;
    bool bGeneralReg = false;
    bool bStackReg = false;
    bool bSegmentReg = false;
    bool bDebugReg = false;
    bool bInstructionPointerReg = false;
    bool bFlagsReg = false;
    bool bFPUReg = false;
    bool bXMMReg = false;
    bool bNumber = false;

    if (XDisasmAbstract::isRef(m_disasmFamily, sOperand, m_syntax)) {
        bRef = true;
    } else if (XDisasmAbstract::isGeneralRegister(m_disasmFamily, sOperand, m_syntax)) {
        bGeneralReg = true;
    } else if (XDisasmAbstract::isStackRegister(m_disasmFamily, sOperand, m_syntax)) {
        bStackReg = true;
    } else if (XDisasmAbstract::isSegmentRegister(m_disasmFamily, sOperand, m_syntax)) {
        bSegmentReg = true;
    } else if (XDisasmAbstract::isDebugRegister(m_disasmFamily, sOperand, m_syntax)) {
        bDebugReg = true;
    } else if (XDisasmAbstract::isInstructionPointerRegister(m_disasmFamily, sOperand, m_syntax)) {
        bInstructionPointerReg = true;
    } else if (XDisasmAbstract::isFlagsRegister(m_disasmFamily, sOperand, m_syntax)) {
        bFlagsReg = true;
    } else if (XDisasmAbstract::isFPURegister(m_disasmFamily, sOperand, m_syntax)) {
        bFPUReg = true;
    } else if (XDisasmAbstract::isXMMRegister(m_disasmFamily, sOperand, m_syntax)) {
        bXMMReg = true;
    } else if (XDisasmAbstract::isNumber(m_disasmFamily, sOperand, m_syntax)) {
        bNumber = true;
    }

    XOptions::COLOR_RECORD colorRecord;

    if (bRef) {
        colorRecord = getColorRecord(XDisasmCore::OG_REFS);
    } else if (bNumber) {
        colorRecord = getColorRecord(XDisasmCore::OG_NUMBERS);
    } else if (bGeneralReg || bStackReg || bSegmentReg || bDebugReg || bInstructionPointerReg || bFlagsReg || bFPUReg || bXMMReg) {
        if (bGeneralReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_GENERAL);
        } else if (bStackReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_STACK);
        } else if (bSegmentReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_SEGMENT);
        } else if (bDebugReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_DEBUG);
        } else if (bInstructionPointerReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_IP);
        } else if (bFlagsReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_FLAGS);
        } else if (bFPUReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_FPU);
        } else if (bXMMReg) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS_XMM);
        }

        if ((colorRecord.sColorMain == "") && (colorRecord.sColorBackground == "")) {
            colorRecord = getColorRecord(XDisasmCore::OG_REGS);
        }
    }

    bool bSave = false;

    if ((colorRecord.sColorMain != "") || (colorRecord.sColorBackground != "")) {
        bSave = true;
    }

    if (bSave) {
        pPainter->save();
    }

    if (colorRecord.sColorBackground != "") {
        pPainter->fillRect(rectText, QBrush(XOptions::stringToColor(colorRecord.sColorBackground)));
    }

    if (colorRecord.sColorMain != "") {
        pPainter->setPen(XOptions::stringToColor(colorRecord.sColorMain));
    }

    pPainter->drawText(rectText, sOperand, m_qTextOptions);

    if (bSave) {
        pPainter->restore();
    }
}
#endif
#ifdef QT_GUI_LIB
void XDisasmCore::drawColorText(QPainter *pPainter, const QRectF &rect, const QString &sText, const XOptions::COLOR_RECORD &colorRecord)
{
    if ((colorRecord.sColorMain != "") || (colorRecord.sColorBackground != "")) {
        pPainter->save();

        QRectF _rectString = rect;
        _rectString.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sText).width());

        if (colorRecord.sColorBackground != "") {
            pPainter->fillRect(_rectString, QBrush(XOptions::stringToColor(colorRecord.sColorBackground)));
        }

        if (colorRecord.sColorMain != "") {
            pPainter->setPen(XOptions::stringToColor(colorRecord.sColorMain));
        }

        pPainter->drawText(_rectString, sText, m_qTextOptions);

        pPainter->restore();
    } else {
        pPainter->drawText(rect, sText, m_qTextOptions);
    }
}
#endif
XOptions::COLOR_RECORD XDisasmCore::getOpcodeColor(quint32 nOpcode)
{
    XOptions::COLOR_RECORD result = {};

    if (XDisasmAbstract::isCallOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_CALL);
    } else if (XDisasmAbstract::isCondJumpOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_CONDJMP);
    } else if (XDisasmAbstract::isRetOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_RET);
    } else if (XDisasmAbstract::isPushOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_PUSH);
    } else if (XDisasmAbstract::isPopOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_POP);
    } else if (XDisasmAbstract::isNopOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_NOP);
    } else if (XDisasmAbstract::isJumpOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_JMP);
    } else if (XDisasmAbstract::isInt3Opcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_INT3);
    } else if (XDisasmAbstract::isSyscallOpcode(m_disasmFamily, nOpcode)) {
        result = getColorRecord(XDisasmCore::OG_OPCODE_SYSCALL);
    }

    if ((result.sColorMain == "") && (result.sColorBackground == "")) {
        result = getColorRecord(XDisasmCore::OG_OPCODE);
    }

    return result;
}

XOptions::COLOR_RECORD XDisasmCore::getColorRecord(XOptions *pOptions, XOptions::ID id)
{
    XOptions::COLOR_RECORD result = {};

    QString sCode = pOptions->getValue(id).toString();
    QString sColorCode = sCode.section("|", 0, 0);
    QString sBackgroundCode = sCode.section("|", 1, 1);

    if (sColorCode != "") {
        result.sColorMain = sColorCode;
    }

    if (sBackgroundCode != "") {
        result.sColorBackground = sBackgroundCode;
    }

    return result;
}

QMap<XDisasmCore::OG, XOptions::COLOR_RECORD> XDisasmCore::getColorRecordsMap(XOptions *pOptions, XBinary::DM disasmMode)
{
    XBinary::DMFAMILY dmFamily = XBinary::getDisasmFamily(disasmMode);

    QMap<XDisasmCore::OG, XOptions::COLOR_RECORD> mapResult;

    mapResult.insert(XDisasmCore::OG_ARROWS, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARROWS));
    mapResult.insert(XDisasmCore::OG_ARROWS_SELECTED, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARROWS_SELECTED));
    mapResult.insert(XDisasmCore::OG_REGS, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_REGS));
    mapResult.insert(XDisasmCore::OG_NUMBERS, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_NUMBERS));
    mapResult.insert(XDisasmCore::OG_OPCODE, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_OPCODE));
    mapResult.insert(XDisasmCore::OG_REFS, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_REFS));

    if (dmFamily == XBinary::DMFAMILY_X86) {
        mapResult.insert(XDisasmCore::OG_REGS_GENERAL, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL));
        mapResult.insert(XDisasmCore::OG_REGS_STACK, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_STACK));
        mapResult.insert(XDisasmCore::OG_REGS_SEGMENT, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT));
        mapResult.insert(XDisasmCore::OG_REGS_DEBUG, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG));
        mapResult.insert(XDisasmCore::OG_REGS_IP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_IP));
        mapResult.insert(XDisasmCore::OG_REGS_FLAGS, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS));
        mapResult.insert(XDisasmCore::OG_REGS_FPU, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_FPU));
        mapResult.insert(XDisasmCore::OG_REGS_XMM, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_REGS_XMM));
        mapResult.insert(XDisasmCore::OG_OPCODE_CALL, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL));
        mapResult.insert(XDisasmCore::OG_OPCODE_CONDJMP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP));
        mapResult.insert(XDisasmCore::OG_OPCODE_RET, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_RET));
        mapResult.insert(XDisasmCore::OG_OPCODE_PUSH, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH));
        mapResult.insert(XDisasmCore::OG_OPCODE_POP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_POP));
        mapResult.insert(XDisasmCore::OG_OPCODE_NOP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP));
        mapResult.insert(XDisasmCore::OG_OPCODE_JMP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP));
        mapResult.insert(XDisasmCore::OG_OPCODE_INT3, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3));
        mapResult.insert(XDisasmCore::OG_OPCODE_SYSCALL, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL));
        // TODO
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        mapResult.insert(XDisasmCore::OG_REGS_GENERAL, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL));
        mapResult.insert(XDisasmCore::OG_OPCODE_JMP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_B));
        mapResult.insert(XDisasmCore::OG_OPCODE_CALL, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL));
        mapResult.insert(XDisasmCore::OG_OPCODE_RET, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET));
        mapResult.insert(XDisasmCore::OG_OPCODE_PUSH, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH));
        mapResult.insert(XDisasmCore::OG_OPCODE_POP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP));
        mapResult.insert(XDisasmCore::OG_OPCODE_NOP, getColorRecord(pOptions, XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP));
    }

    return mapResult;
}

XOptions::COLOR_RECORD XDisasmCore::getColorRecord(OG og)
{
    return m_mapColors.value(og);
}

XDisasmAbstract::DISASM_RESULT XDisasmCore::disAsm(QIODevice *pDevice, qint64 nOffset, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    QByteArray baData = XBinary::read_array(pDevice, nOffset, m_nOpcodeSize);

    return disAsm(baData.data(), baData.size(), nAddress, disasmOptions);
}

QList<XDisasmAbstract::DISASM_RESULT> XDisasmCore::disAsmList(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions,
                                                              qint32 nLimit, XBinary::PDSTRUCT *pPdStruct)
{
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    if (m_pDisasmAbstract) {
        listResult = m_pDisasmAbstract->_disasm(pData, nDataSize, nAddress, disasmOptions, nLimit, pPdStruct);
    }

    return listResult;
}

XDisasmAbstract::DISASM_RESULT XDisasmCore::disAsm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    XDisasmAbstract::DISASM_RESULT result = {};

    if (m_pDisasmAbstract) {
        QList<XDisasmAbstract::DISASM_RESULT> list = disAsmList(pData, nDataSize, nAddress, disasmOptions, 1);

        if (list.count()) {
            result = list.at(0);
        }
    }

    return result;
}
