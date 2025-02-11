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
    g_disasmMode = XBinary::DM_UNKNOWN;
    g_disasmFamily = XBinary::DMFAMILY_UNKNOWN;
    g_pDisasmAbstract = nullptr;
    g_nOpcodeSize = 15;
}

XDisasmCore::~XDisasmCore()
{
    if (g_pDisasmAbstract) {
        delete g_pDisasmAbstract;
        // XCapstone::closeHandle(&g_handle);
    }
}

void XDisasmCore::setMode(XBinary::DM disasmMode, XBinary::SYNTAX syntax)
{
    if ((g_disasmMode != disasmMode) || (g_syntax != syntax)) {
        if (g_pDisasmAbstract) {
            delete g_pDisasmAbstract;
            g_pDisasmAbstract = nullptr;
        }

        if (XCapstone::isModeValid(disasmMode)) {
            g_pDisasmAbstract = new Capstone_Bridge(disasmMode, syntax);
        } else if (disasmMode == XBinary::DM_CUSTOM_7ZIP_PROPERTIES) {
            g_pDisasmAbstract = new X7Zip_Properties();
        } else if ((disasmMode == XBinary::DM_CUSTOM_MACH_BIND) || (disasmMode == XBinary::DM_CUSTOM_MACH_WEAK) || (disasmMode == XBinary::DM_CUSTOM_MACH_EXPORT) ||
                   (disasmMode == XBinary::DM_CUSTOM_MACH_REBASE)) {
            g_pDisasmAbstract = new XMachO_Commands(disasmMode);
        }

        g_disasmMode = disasmMode;
        g_disasmFamily = XBinary::getDisasmFamily(disasmMode);
        g_syntax = syntax;
    }
}

XBinary::SYNTAX XDisasmCore::getSyntax()
{
    return g_syntax;
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

                if (XDisasmAbstract::isBranchOpcode(g_disasmFamily, _disasmResult.nOpcode)) {
                    // TODO another archs !!!
                    if (g_disasmFamily == XBinary::DMFAMILY_X86) {
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

                    if (_disasmResult.sString != "") {
                        record.sOpcode += " " + _disasmResult.sString;
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
    return XDisasmAbstract::getNumberString(nValue, g_disasmMode, g_syntax);
}

XDisasmAbstract::DISASM_RESULT XDisasmCore::disAsm(QIODevice *pDevice, qint64 nOffset, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    QByteArray baData = XBinary::read_array(pDevice, nOffset, g_nOpcodeSize);

    return disAsm(baData.data(), baData.size(), nAddress, disasmOptions);
}

QList<XDisasmAbstract::DISASM_RESULT> XDisasmCore::disAsmList(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions,
                                                              qint32 nLimit, XBinary::PDSTRUCT *pPdStruct)
{
    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();

    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }

    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    if (g_pDisasmAbstract) {
        listResult = g_pDisasmAbstract->_disasm(pData, nDataSize, nAddress, disasmOptions, nLimit, pPdStruct);
    }

    return listResult;
}

XDisasmAbstract::DISASM_RESULT XDisasmCore::disAsm(char *pData, qint32 nDataSize, XADDR nAddress, const XDisasmAbstract::DISASM_OPTIONS &disasmOptions)
{
    XDisasmAbstract::DISASM_RESULT result = {};

    if (g_pDisasmAbstract) {
        QList<XDisasmAbstract::DISASM_RESULT> list = disAsmList(pData, nDataSize, nAddress, disasmOptions, 1);

        if (list.count()) {
            result = list.at(0);
        }
    }

    return result;
}
