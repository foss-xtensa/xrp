cmake_minimum_required(VERSION 2.6)

project(test-xrp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)

add_definitions(-Wall -Wmissing-declarations -Wextra)

set(NAME "test-xrp")
set(CORENAME VP6_DCT_PROD_200)
set(SYSUPGRADE "sysupgrade-sdipv2")

set(CMAKE_C_FLAGS_DEBUG "-O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-Os -DNDEBUG")

set(CMAKE_EXE_LINKER_FLAGS "-lhal -mlsp=${CMAKE_CURRENT_BINARY_DIR}/sdip-lsp")
set(CMAKE_C_COMPILER_ARG1 --xtensa-core=${CORENAME})
set(CMAKE_CXX_COMPILER_ARG1 --xtensa-core=${CORENAME})

set(LSP_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sdip-lsp/)
set(LSP_INPUT min-rt)

include(GNUInstallDirs)

if (NOT SUPER_BUILD)
	include_directories("${CMAKE_SOURCE_DIR}/../bsp")
	link_directories("${CMAKE_SOURCE_DIR}/../bsp/build")
endif ()

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "${NAME}: No build type selected, default to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif()

set(${NAME}-SOURCES dsp_main.c xrp_dsp.c xrp_dsp_hw_dct.c)

add_executable(${NAME}.elf ${${NAME}-SOURCES})

target_link_libraries(${NAME}.elf LINK_PUBLIC bsp)

add_custom_command(
	OUTPUT ivp.iram.bin ivp.dram.bin ivp.lmem.bin sdipv2-${NAME}-upgrade.tar.gz ${NAME}.bin ${SYSUPGRADE}

	COMMAND xt-objcopy -R .data -R .bss -R .rodata -R .text -R .sram.data -O binary ${NAME}.elf ivp.iram.bin
	COMMAND xt-objcopy -j .data -j .bss -j .rodata -O binary ${NAME}.elf ivp.dram.bin
	COMMAND xt-objcopy -j .text -j .sram.data -O binary ${NAME}.elf ivp.lmem.bin

	COMMAND dd if=ivp.dram.bin of=ivp.dram.bin.new bs=8 conv=sync
	COMMAND dd if=ivp.iram.bin of=ivp.iram.bin.new bs=8 conv=sync
	COMMAND dd if=ivp.lmem.bin of=ivp.lmem.bin.new bs=8 conv=sync

	COMMAND mv ivp.dram.bin.new ivp.dram.bin
	COMMAND mv ivp.iram.bin.new ivp.iram.bin
	COMMAND mv ivp.lmem.bin.new ivp.lmem.bin

	COMMAND dd if=ivp.dram.bin of=${NAME}.dram.img bs=524288 conv=sync
	COMMAND dd if=ivp.iram.bin of=${NAME}.iram.img bs=31744 conv=sync
	COMMAND dd if=ivp.lmem.bin of=${NAME}.lmem.img bs=524288 conv=sync
	COMMAND dd if=/dev/zero of=header.img bs=1024 count=1 conv=sync

	COMMAND cat ${NAME}.dram.img > ${NAME}.bin
	COMMAND cat header.img >> ${NAME}.bin
	COMMAND cat ${NAME}.iram.img >> ${NAME}.bin
	COMMAND cat ${NAME}.lmem.img >> ${NAME}.bin

	COMMAND mkdir -p ${SYSUPGRADE} && cp ${NAME}.bin ${SYSUPGRADE}/ivp
	COMMAND tar czf sdipv2-${NAME}-upgrade.tar.gz ${SYSUPGRADE}/ivp

	COMMAND rm *.img
	COMMAND xt-size ${NAME}.elf
	COMMAND xt-size --format=sysv -x ${NAME}.elf
	DEPENDS ${NAME}.elf
	)

add_custom_target(${NAME}-bin ALL
	DEPENDS ivp.iram.bin ivp.dram.bin ivp.lmem.bin
	)

add_custom_command(
	OUTPUT ${NAME}.lst
	COMMAND xt-objdump -h -S ${NAME}.elf > ${NAME}.lst
	DEPENDS ${NAME}.elf
	)

add_custom_target(${NAME}-disassemble
	DEPENDS ${NAME}.lst
	)

add_custom_command(
	OUTPUT ${LSP_OUTPUT}
	COMMAND mkdir -p ${LSP_OUTPUT} && cp -vr ${CMAKE_CURRENT_SOURCE_DIR}/${LSP_INPUT}/* ${LSP_OUTPUT}/
	COMMAND xt-genldscripts -v -b ${LSP_OUTPUT}/

	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${LSP_INPUT}/specs ${CMAKE_CURRENT_SOURCE_DIR}/${LSP_INPUT}/memmap.xmm
	)

add_custom_target(${NAME}-lsp
	DEPENDS ${LSP_OUTPUT}
	)

add_dependencies(${NAME}.elf ${NAME}-lsp)
