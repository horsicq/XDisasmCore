INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD
INCLUDEPATH += $$PWD/Modules
DEPENDPATH += $$PWD/Modules

HEADERS += \
    $$PWD/Modules/x7zip_properties.h \
    $$PWD/xdisasmcore.h

SOURCES += \
    $$PWD/Modules/x7zip_properties.cpp \
    $$PWD/xdisasmcore.cpp

!contains(XCONFIG, xbinary) {
    XCONFIG += xbinary
    include($$PWD/../Formats/xbinary.pri)
}

contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone_x86) {
        XCONFIG += xcapstone_x86
        include($$PWD/../XCapstone/xcapstone_x86.pri)
    }
}

!contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone) {
        XCONFIG += xcapstone
        include($$PWD/../XCapstone/xcapstone.pri)
    }
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xdisasmcore.cmake
