
XRP_SRC		:= ../..

# Heterogeneous subsystem comprising Xtensa controller and DSP
# Description of shared memory, MMIO, and interrupt connectivity
# This example was hand-generated but can be customized
YML		?= ./subsys-rtos-hosted.yml
XLD		?= ./subsys-rtos-hosted.xld
XT_SUBSYS_SRC	:= .

# Set compiler and config
XRP_HOST_CORE	:= sample_controller
XRP_HOST_CC	:= xt-clang --xtensa-core=${XRP_HOST_CORE}
HOST_LSP_PREFIX	?= Host

# Set DSP config
XTENSA_CORE	:= Vision_P6_AO

# Set example build mode for threaded + multiqueue support
XRP_HOST_MODE		:= rtos-hosted
XRP_DSP_HW_PORT		?= simple-xos
XRP_HOST_QUEUE_TYPE	?= threaded
XRP_DSP_USE_SRCS	?= 1

# Default FreeRTOS locations
FREERTOS_SOURCE	?=
ifeq (,$(wildcard ${FREERTOS_SOURCE}))
  $(error FREERTOS_SOURCE set to a path that does not exist)
endif
FREERTOS_XTENSA	:= ${FREERTOS_SOURCE}/portable/ThirdParty/Partner-Supported-Ports/Cadence/Xtensa

-include ../Makefile.common

OVERRIDE_MAKEFILE_COMM := 1
-include ../Makefile

.PHONY: xrpdsp
xrpdsp: ${DSPBLD}/.stmp ${LSPBLD} ${XRP_DSP_BINARIES}

.PHONY: xrprtoshosted
xrprtoshosted:
	make XRP_HOST_MODE=rtos-hosted ${BLDDIR}/xrp-host-rtos-hosted

## Build subsystem and DTS
${SYSBLD}:
	cp ${YML} ${BLDDIR}/subsys.yml
	${XTENSA_TOOLS}/libexec/xt-sysbuilder \
	  -xtensa-system ${XTENSA_SYSTEM} \
	  -subsys ${BLDDIR}/subsys.yml \
	  -swtools ${XTENSA_TOOLS} \
	  -build ${SYSBLD}

## Build LSPs
${LSPBLD}:
	cp ${XLD} ${BLDDIR}/subsys.xld
	${XTENSA_TOOLS}/libexec/xt-mbuild \
	  -root ${LSPBLD} \
	  -tctools ${TCTOOLS} \
	  -syspkg ${LSPBLD}/package \
	  -socfile ${BLDDIR}/subsys.xld \
	  -preclean \
	  -build sw \
	  -lsps sim,sim-stacklocal

${BLDDIR}/xrp-dsp-standalone%: ${XRP_DSP_LIBS_OBJS} ${DSPBLD}/xrp_dsp_standalone-dsp_test.o ${DSPBLD}/xrp_dsp_standalone-dsp_main.o
	$(XRP_DSP_CC) \
	  -mlsp=${LSPBLD}/package/cores/${CORE_NAME_PREFIX}${*}/xtensa-elf/lib/sim-stacklocal \
	  -Wl,--defsym,_memmap_cacheattr_reset=${CACHE_ATTR} \
	  -Wl,--defsym,xrp_dsp_comm_base_magic=${${CORE_NAME_PREFIX}${*}_DEVICE_COMM_BASE_MAGIC} \
	  -o $@ $^ -lxtutil -Wl,--start-group ${XRP_DSP_LDFLAGS} -Wl,--end-group

${HOSTBLD}/freertos/.stmp:
	mkdir -p $(shell dirname $@)
	touch $@

${HOSTBLD}/xrp_host_freertos.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_host_freertos.o: ${XRP_SRC}/xrp-example/rtos-hosted/xrp_host_freertos.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) -I${SYSBLD}/include \
	  -o $@ $<

${HOSTBLD}/freertos/libfreertos.a: ${HOSTBLD}/.stmp
${HOSTBLD}/freertos/libfreertos.a: ${HOSTBLD}/freertos/.stmp
	${MAKE} -C ${FREERTOS_XTENSA} \
	  XTENSA_CORE=${XRP_HOST_CORE} XT_CORE=${XRP_HOST_CORE} \
	  BLDROOT=$(abspath ${HOSTBLD}/freertos/) \
	  CFGFLAGS=-I$(abspath ${XRP_SRC}/xrp-example/rtos-hosted)

${HOSTBLD}/host_main_freertos.o: ${HOSTBLD}/.stmp
${HOSTBLD}/host_main_freertos.o: ${HOSTBLD}/freertos/libfreertos.a
${HOSTBLD}/host_main_freertos.o: ${XRP_SRC}/xrp-example/rtos-hosted/host_main_freertos.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -I${XRP_SRC} -I${XRP_SRC}/xrp-example -I${XRP_SRC}/xrp-example/rtos-hosted \
	  -I${FREERTOS_SOURCE}/include -I${FREERTOS_XTENSA} -I${HOSTBLD}/freertos/${XRP_HOST_CORE} \
	  -o $@ $<

${BLDDIR}/xrp-host-rtos-hosted: \
  ${HOSTBLD}/xrp_rb_file.o ${HOSTBLD}/xrp_ns.o \
  ${HOSTBLD}/xrp_host_common.o ${HOSTBLD}/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o \
  ${HOSTBLD}/xrp_host.o ${HOSTBLD}/xrp_host_freertos.o ${HOSTBLD}/xrp_alloc.o \
  ${HOSTBLD}/xrp_dtb.o ${HOSTBLD}/host_main_freertos.o
	$(XRP_HOST_CC) $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -mlsp=${LSPBLD}/package/cores/${HOST_LSP_PREFIX}/xtensa-elf/lib/sim-stacklocal \
	  -L${HOSTBLD}/freertos/${XRP_HOST_CORE} \
	  -o $@ $^ \
	  -lfdt -lfreertos


.PHONY: run
run:
	xtsc-run --define=Host_SIM_STOP_ON_EXIT=true --define=DSP_SIM_STOP_ON_EXIT=true --define=Host_BINARY=${BLDDIR}/xrp-host-${XRP_HOST_MODE} --define=Host_BINARY_ARGS= --define=DSP_BINARY=./${BLDDIR}/xrp-dsp-standalone0 --include=${SYSBLD}/xtsc-run/SubSystem.inc


.PHONY: clean
clean:
	rm -rf ${BLDDIR}/subsys.* ${SYSBLD} ${LSPBLD}
	rm -rf ${DSPBLD} ${XRP_DSP_BINARIES}
	rm -rf ${HOSTBLD} ${BLDDIR}/xrp-host-{standalone,rtos-hosted,hosted,single}
