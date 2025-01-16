include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/Modules)

if (NOT DEFINED XBINARY_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)
    set(XDISASMCORE_SOURCES ${XDISASMCORE_SOURCES} ${XBINARY_SOURCES})
endif()
if (NOT DEFINED XCAPSTONE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XCapstone/xcapstone.cmake)
    set(XDISASMCORE_SOURCES ${XDISASMCORE_SOURCES} ${XCAPSTONE_SOURCES})
endif()

set(XDISASMCORE_SOURCES
    ${XDISASMCORE_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/Modules/capstone_bridge.cpp
    ${CMAKE_CURRENT_LIST_DIR}/Modules/capstone_bridge.h
    ${CMAKE_CURRENT_LIST_DIR}/Modules/x7zip_properties.cpp
    ${CMAKE_CURRENT_LIST_DIR}/Modules/x7zip_properties.h
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmcore.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmcore.h
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmabstract.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmabstract.h
)
