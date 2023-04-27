
ifndef XTENSA_SYSTEM
  $(error XTENSA_SYSTEM is not defined)
endif

ifndef XTENSA_CORE
  $(error XTENSA_CORE is not defined)
endif

ifndef XTSUBSYS_SRC
XTSUBSYS_SRC := \
  ${XTENSA_SYSTEM}/../../../../builds/${XTENSA_RELEASE}/${XTENSA_CORE}/examples/MP_Subsystem/xt_sysbuilder_mp/
endif

-include ${XTSUBSYS_SRC}/Makefile.attr

XTENSA_TOOLS := ${XTENSA_SYSTEM}/..
XTCLANG := ${XTENSA_TOOLS}/bin/xt-clang

XTENSA_RELEASE := $(shell basename $(dir $(shell ${XTCLANG} --show-config=xttools)))

DTC := ${XTENSA_TOOLS}/Tools/bin/dtc

LIBFDT_PATH := ${XTENSA_TOOLS}/Tools/

XRP_DSP_CC := ${XTCLANG} --xtensa-core=${XTENSA_CORE}

XRP_SRC := ../

XRP_DSP_CPPFLAGS := \
  -I${XRP_SRC}/xrp-common -I${XRP_SRC}/xrp-dsp

XRP_DSP_CFLAGS := -W -Wall -g -O2

ifndef XRP_DSP_HW_PORT
  XRP_DSP_HW_PORT := simple
endif

XRP_DSP_LIBS := \
	-lxrp-common \
	-lxrp-dsp \
	-lxrp-dsp-hw-${XRP_DSP_HW_PORT}

ifeq (${XRP_DSP_HW_PORT}, simple)
else ifeq (${XRP_DSP_HW_PORT}, simple-xos)
  XRP_DSP_CPPFLAGS += \
    -DHAVE_THREADS_XOS=1 \
    -DHAVE_XTOS_SET_INTERRUPT_HANDLER=1 \
    -DHAVE_XTOS_INTERRUPT_ENABLE=1 \
    -DHAVE_XTOS_INTERRUPT_DISABLE=1 \
    -DHAVE_XTOS_SET_EXCEPTION_HANDLER=1
  XRP_DSP_LIBS += \
    -lxos -lxtutil
else
  $(error XRP_DSP_HW_PORT must be "simple" or "simple-xos")
endif

XRP_HOST_CC := gcc

XRP_HOST_CPPFLAGS := \
  -DHAVE_NANOSLEEP=1 \
  -DHAVE_LIBFDT=1 \
  -DHAVE_FDT_GETPROP=1 \
  -DHAVE_FDT_STRERROR=1 \
  -I${LIBFDT_PATH}/include \
  -I${XRP_SRC} -I${XRP_SRC}/xrp-common \
  -I${XRP_SRC}/xrp-host \
  -I${XRP_SRC}/xrp-host/standalone

XRP_HOST_CFLAGS := -W -Wall -g -O2

ifndef XRP_HOST_QUEUE_TYPE
  XRP_HOST_QUEUE_TYPE := sync
endif

ifeq (${XRP_HOST_QUEUE_TYPE}, sync)
  XRP_HOST_CPPFLAGS += \
    -I${XRP_SRC}/xrp-host/thread-single/
else ifeq (${XRP_HOST_QUEUE_TYPE}, threaded)
  XRP_HOST_CPPFLAGS += \
    -DHAVE_THREADS_POSIX=1 \
    -I${XRP_SRC}/xrp-host/thread-pthread
else
  $(error XRP_HOST_QUEUE_TYPE must be "sync" or "threaded")
endif

CORE_NUMS := 0 $(shell seq `expr $(NUM_CORES) - 1`)
XRP_DSP_BINARIES := $(addprefix xrp-dsp-standalone,$(CORE_NUMS))
CORES = $(addprefix DSP_,$(CORE_NUMS))
XTSC_RUN_BINARY_DEF := $(addprefix --define=,$(join $(addsuffix _BINARY=,$(CORES)), $(XRP_DSP_BINARIES)))


.PHONY: all
all: sysbld lspbld \
  dspbld ${XRP_DSP_BINARIES} \
  hostbld xrp-host-standalone

sysbld: ## Build subsystem and DTS
	cp ${XTSUBSYS_SRC}/subsys.yml .
	${XTENSA_TOOLS}/libexec/xt-sysbuilder \
	  -subsys subsys.yml \
	  -swtools ${XTENSA_TOOLS} \
	  -build sysbld
	cp sysbld/xrp/XRP_Controller.lua sysbld/xtsc-run/TestBenchMaster.vec

lspbld: ## Build LSPs
	cp ${XTSUBSYS_SRC}/subsys.xld .
	${XTENSA_TOOLS}/libexec/xt-mbuild \
	  -root lspbld \
	  -syspkg lspbld/package \
	  -socfile subsys.xld \
	  -preclean \
	  -build sw \
	  -lsps sim,sim-stacklocal

dspbld:
	mkdir -p $@

dspbld/xrp_dsp_standalone-dsp_test.o: ${XRP_SRC}/xrp-example/dsp_test.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

dspbld/xrp_dsp_standalone-dsp_main.o: ${XRP_SRC}/xrp-example/dsp_main.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

xrp-dsp-standalone%: dspbld/xrp_dsp_standalone-dsp_test.o dspbld/xrp_dsp_standalone-dsp_main.o
	$(XRP_DSP_CC) \
	  -mlsp=lspbld/package/cores/DSP_${*}/xtensa-elf/lib/sim-stacklocal \
	  -Wl,--defsym,_memmap_cacheattr_reset=${CACHE_ATTR} \
	  -Wl,--defsym,xrp_dsp_comm_base_magic=${DSP_${*}_DEVICE_COMM_BASE_MAGIC} \
	  -o $@ -Wl,--start-group $^ ${XRP_DSP_LIBS} -Wl,--end-group

hostbld:
	mkdir -p $@

hostbld/xrp_rb_file.o: ${XRP_SRC}/xrp-common/xrp_rb_file.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_ns.o: ${XRP_SRC}/xrp-common/xrp_ns.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_host_common.o: ${XRP_SRC}/xrp-host/xrp_host_common.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o: ${XRP_SRC}/xrp-host/xrp_${XRP_HOST_QUEUE_TYPE}_queue.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_host.o: ${XRP_SRC}/xrp-host/standalone/xrp_host.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_linux.o: ${XRP_SRC}/xrp-host/standalone/xrp_linux.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp_alloc.o: ${XRP_SRC}/xrp-common/xrp_alloc.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

hostbld/xrp.dtb: sysbld/xrp/TestSubSys.dts
	${DTC} -o $@ -O dtb $<

hostbld/xrp_dtb.o: ${XRP_SRC}/xrp-example/xrp_dtb.s hostbld/xrp.dtb
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) \
	  -I./hostbld \
	  -o $@ $<

hostbld/host_main.o: ${XRP_SRC}/xrp-example/host_main.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -I${XRP_SRC} \
	  -o $@ $<

xrp-host-standalone: \
  hostbld/xrp_rb_file.o hostbld/xrp_ns.o \
  hostbld/xrp_host_common.o hostbld/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o \
  hostbld/xrp_host.o hostbld/xrp_linux.o hostbld/xrp_alloc.o \
  hostbld/xrp_dtb.o hostbld/host_main.o
	$(XRP_HOST_CC) $(XRP_HOST_CFLAGS) \
	  -o $@ $^ \
	  -pthread -L${LIBFDT_PATH}/lib -lfdt -lrt


.PHONY: run
run:
	./xrp-host-standalone.sh ${XTSC_RUN_BINARY_DEF}


.PHONY: clean
clean:
	rm -rf subsys.* sysbld lspbld
	rm -rf dspbld ${XRP_DSP_BINARIES}
	rm -rf hostbld xrp-host-standalone
