include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED XBINARY_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)
    set(XPDF_SOURCES ${XPDF_SOURCES} ${XBINARY_SOURCES})
endif()

set(XPDF_SOURCES
    ${XPDF_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmcore.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmcore.h
)
