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

X7Zip_Properties::X7Zip_Properties(QObject *parent) : XDisasmAbstract(parent)
{
}

void X7Zip_Properties::_addTagId(QList<DISASM_RESULT> *pListResults, quint64 nValue, XSevenZip::EIdEnum id, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return;
    }

    if (nValue == id) {
        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, 1, XSevenZip::idToSring(id), "", pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }
}

void X7Zip_Properties::_handleTag(QList<DISASM_RESULT> *pListResults, char *pData, XSevenZip::EIdEnum id, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return;
    }

    XBinary::PACKED_UINT puTag = XBinary::_read_packedNumber(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);

    if (puTag.bIsValid) {
        if (id == puTag.nValue) {
            _addTagId(pListResults, puTag.nValue, id, pState, disasmOptions);
            if (puTag.nValue == XSevenZip::k7zIdHeader) {
                _handleTag(pListResults, pData, XSevenZip::k7zIdMainStreamsInfo, pState, disasmOptions);
                _handleTag(pListResults, pData, XSevenZip::k7zIdFilesInfo, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdMainStreamsInfo) {
                _handleTag(pListResults, pData, XSevenZip::k7zIdPackInfo, pState, disasmOptions);
                _handleTag(pListResults, pData, XSevenZip::k7zIdUnpackInfo, pState, disasmOptions);
                XBinary::PACKED_UINT puExtra = XBinary::_read_packedNumber(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);
                if (puExtra.bIsValid) {
                    if (puExtra.nValue == XSevenZip::k7zIdSubStreamsInfo) {
                        _handleTag(pListResults, pData, XSevenZip::k7zIdSubStreamsInfo, pState, disasmOptions);
                    }
                }
                _handleTag(pListResults, pData, XSevenZip::k7zIdEnd, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdEncodedHeader) {
                _handleTag(pListResults, pData, XSevenZip::k7zIdPackInfo, pState, disasmOptions);
                _handleTag(pListResults, pData, XSevenZip::k7zIdUnpackInfo, pState, disasmOptions);
                _handleTag(pListResults, pData, XSevenZip::k7zIdEnd, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdPackInfo) {
                _handleNumber(pListResults, pData, pState, disasmOptions);                   // Pack Position
                quint64 nCount = _handleNumber(pListResults, pData, pState, disasmOptions);  // Count of Pack Streams, NUMBER
                for (quint64 i = 0; (i < nCount) && (!(pState->bIsStop)); i++) {
                    _handleNumber(pListResults, pData, pState, disasmOptions);  // Size
                }
                for (quint64 i = 0; (i < nCount) && (!(pState->bIsStop)); i++) {
                    _handleNumber(pListResults, pData, pState, disasmOptions);  // CRC
                }
                _handleTag(pListResults, pData, XSevenZip::k7zIdEnd, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdUnpackInfo) {
                _handleTag(pListResults, pData, XSevenZip::k7zIdFolder, pState, disasmOptions);
                _handleTag(pListResults, pData, XSevenZip::k7zIdEnd, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdSubStreamsInfo) {
                while (!(pState->bIsStop)) {
                    XBinary::PACKED_UINT puExtra = XBinary::_read_packedNumber(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);
                    if (puExtra.bIsValid) {
                        if (puExtra.nValue == XSevenZip::k7zIdCRC) {
                            // TODO mb create a new if
                            _addTagId(pListResults, puExtra.nValue, XSevenZip::k7zIdCRC, pState, disasmOptions);
                            quint64 nCRCCount = _handleNumber(pListResults, pData, pState, disasmOptions);  // Count of CRC
                            for (quint64 i = 0; (i < nCRCCount) && (!(pState->bIsStop)); i++) {
                                _handleUINT32(pListResults, pData, pState, disasmOptions);  // UnpackDigest, UINT32
                            }
                        } else {
                            break;
                        }
                    } else {
                        pState->bIsStop = true;
                    }
                }
                _handleTag(pListResults, pData, XSevenZip::k7zIdEnd, pState, disasmOptions);
            } else if (puTag.nValue == XSevenZip::k7zIdFilesInfo) {
                quint64 nNumberOfFiles = _handleNumber(pListResults, pData, pState, disasmOptions);  // Number of Files
                for (quint64 i = 0; (i < nNumberOfFiles) && (!(pState->bIsStop)); i++) {
                    _handleNumber(pListResults, pData, pState, disasmOptions);  // File ID, NUMBER
                }
            } else if (puTag.nValue == XSevenZip::k7zIdFolder) {
                quint64 nNumberOfFolders = _handleNumber(pListResults, pData, pState, disasmOptions);  // Number of Folders
                quint8 nExt = _handleByte(pListResults, pData, pState, disasmOptions);                 // External
                if (nExt == 0) {
                    _handleNumber(pListResults, pData, pState, disasmOptions);               // Number of Coders, NUMBER
                    quint8 nFlag = _handleByte(pListResults, pData, pState, disasmOptions);  // Flag
                    qint32 nCodecSize = nFlag & 0x0F;
                    bool bIsComplex = (nFlag & 0x10) != 0;
                    bool bHasAttr = (nFlag & 0x20) != 0;
                    _handleArray(pListResults, pData, nCodecSize, pState, disasmOptions);
                    if (bIsComplex) {
                        // TODO
                    }
                    if (bHasAttr) {
                        quint64 nPropertySize = _handleNumber(pListResults, pData, pState, disasmOptions);  // PropertiesSize
                        _handleArray(pListResults, pData, nPropertySize, pState, disasmOptions);
                    }
                } else if (nExt == 1) {
                    _handleNumber(pListResults, pData, pState, disasmOptions);  // Data Stream Index, NUMBER
                }

                while (!(pState->bIsStop)) {
                    XBinary::PACKED_UINT puExtra = XBinary::_read_packedNumber(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);
                    if (puExtra.bIsValid) {
                        if (puExtra.nValue == XSevenZip::k7zIdCodersUnpackSize) {
                            _addTagId(pListResults, puExtra.nValue, XSevenZip::k7zIdCodersUnpackSize, pState, disasmOptions);
                            for (quint64 i = 0; (i < nNumberOfFolders) && (!(pState->bIsStop)); i++) {
                                _handleNumber(pListResults, pData, pState, disasmOptions);  // Unpacksize, NUMBER
                            }
                        } else if (puExtra.nValue == XSevenZip::k7zIdCRC) {
                            _addTagId(pListResults, puExtra.nValue, XSevenZip::k7zIdCRC, pState, disasmOptions);
                            quint64 nCRCCount = _handleNumber(pListResults, pData, pState, disasmOptions);  // Count of CRC
                            for (quint64 i = 0; (i < nCRCCount) && (!(pState->bIsStop)); i++) {
                                _handleUINT32(pListResults, pData, pState, disasmOptions);  // UnpackDigest, UINT32
                            }
                        } else {
                            break;
                        }
                    } else {
                        pState->bIsStop = true;
                    }
                }
            }
        } else {
            pState->bIsStop = true;
        }
    } else {
        pState->bIsStop = true;
    }
}

quint64 X7Zip_Properties::_handleNumber(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return 0;
    }

    quint64 nResult = 0;

    XBinary::PACKED_UINT puTag = XBinary::_read_packedNumber(pData + pState->nCurrentOffset, pState->nMaxSize - pState->nCurrentOffset);

    if (puTag.bIsValid) {
        nResult = puTag.nValue;
        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, puTag.nByteSize, "NUMBER", QString("0x%1").arg(QString::number(puTag.nValue, 16)),
                         pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return nResult;
}

quint8 X7Zip_Properties::_handleByte(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return 0;
    }

    quint8 nResult = 0;

    if (pState->nCurrentOffset + 1 <= pState->nMaxSize) {
        nResult = XBinary::_read_uint8(pData + pState->nCurrentOffset);

        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, 1, "BYTE", QString("0x%1").arg(QString::number(nResult, 16)), pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return nResult;
}

quint32 X7Zip_Properties::_handleUINT32(QList<DISASM_RESULT> *pListResults, char *pData, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return 0;
    }

    quint32 nResult = 0;

    if (pState->nCurrentOffset + 4 <= pState->nMaxSize) {
        nResult = XBinary::_read_uint32(pData + pState->nCurrentOffset);

        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, 4, "UINT32", QString("0x%1").arg(QString::number(nResult, 16)), pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return nResult;
}

QByteArray X7Zip_Properties::_handleArray(QList<DISASM_RESULT> *pListResults, char *pData, qint32 nDataSize, STATE *pState, const DISASM_OPTIONS &disasmOptions)
{
    if (pState->bIsStop) {
        return 0;
    }

    QByteArray baResult;

    if (pState->nCurrentOffset + nDataSize <= pState->nMaxSize) {
        baResult = XBinary::_read_byteArray(pData + pState->nCurrentOffset, nDataSize);

        _addDisasmResult(pListResults, pState->nAddress + pState->nCurrentOffset, nDataSize, "ARRAY", baResult.toHex(), pState, disasmOptions);
    } else {
        pState->bIsStop = true;
    }

    return baResult;
}

QList<XDisasmAbstract::DISASM_RESULT> X7Zip_Properties::_disasm(char *pData, qint32 nDataSize, XADDR nAddress, const DISASM_OPTIONS &disasmOptions, qint32 nLimit,
                                                                XBinary::PDSTRUCT *pPdStruct)
{
    QList<XDisasmAbstract::DISASM_RESULT> listResult;

    STATE state = {};
    state.nCurrentCount = 0;
    state.nCurrentOffset = 0;
    state.nLimit = nLimit;
    state.nMaxSize = nDataSize;
    state.nAddress = nAddress;

    XBinary::PACKED_UINT puTag = XBinary::_read_packedNumber(pData, state.nMaxSize - state.nCurrentOffset);

    if (puTag.bIsValid) {
        if (puTag.nValue == XSevenZip::k7zIdHeader) {
            _handleTag(&listResult, pData, XSevenZip::k7zIdHeader, &state, disasmOptions);
        } else if (puTag.nValue == XSevenZip::k7zIdEncodedHeader) {
            _handleTag(&listResult, pData, XSevenZip::k7zIdEncodedHeader, &state, disasmOptions);
        }
    }

    return listResult;
}
