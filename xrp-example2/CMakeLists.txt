project(xrp_example)
cmake_minimum_required(VERSION 3.4.3)

INCLUDE(CheckIncludeFiles)

if (NOT DEFINED ENV{XTENSA_SYSTEM})
  message(FATAL_ERROR "XTENSA_SYSTEM environment variable not defined")
endif()

if (NOT DEFINED ENV{XTENSA_CORE})
  message(FATAL_ERROR "XTENSA_CORE environment variable not defined")
endif()

set(XTENSA_CORE          $ENV{XTENSA_CORE})
set(XTENSA_SYSTEM        $ENV{XTENSA_SYSTEM})

message("Using XTENSA_SYSTEM ${XTENSA_SYSTEM}")
message("Using XTENSA_CORE   ${XTENSA_CORE}")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
    message(FATAL_ERROR "GCC version must be at least 4.9!")
  endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.4)
    message(FATAL_ERROR "Clang version must be at least 3.4!")
  endif()
else()
    message(WARNING "You are using an unsupported compiler! Compilation has
only been tested with Clang and GCC.")
endif()

add_subdirectory(xrp_standalone)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xrp.dts.o
  COMMAND dtc -O dtb
          ${CMAKE_SOURCE_DIR}/Subsystem/xrp.dts
          -o ${CMAKE_CURRENT_BINARY_DIR}/xrp.dtb
  COMMAND ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/xrp.dtb.s -c -o
                              ${CMAKE_CURRENT_BINARY_DIR}/xrp.dts.o
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xrp.dtb.s
          ${CMAKE_SOURCE_DIR}/Subsystem/xrp.dts
  )

add_custom_target(xrp_dts ALL DEPENDS
                  ${CMAKE_CURRENT_BINARY_DIR}/xrp.dts.o)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xrp.dts.o
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)

