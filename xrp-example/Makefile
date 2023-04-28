
-include Makefile.common

.PHONY: all
all: sysbld lspbld \
  dspbld ${XRP_DSP_BINARIES} \
  hostbld xrp-host-standalone

## Build subsystem and DTS
sysbld:
	cp ${XTSUBSYS_SRC}/subsys.yml .
	${XTENSA_TOOLS}/libexec/xt-sysbuilder \
	  -subsys subsys.yml \
	  -swtools ${XTENSA_TOOLS} \
	  -build sysbld
	cp sysbld/xrp/XRP_Controller.lua sysbld/xtsc-run/TestBenchMaster.vec

## Build LSPs
lspbld:
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
	  -L${LIBFDT_PATH}/lib -Wl,-rpath ${LIBFDT_PATH}/lib \
	  -pthread -lfdt -lrt


.PHONY: run
run:
	./xrp-host-standalone.sh ${XTSC_RUN_BINARY_DEF}


.PHONY: clean
clean:
	rm -rf subsys.* sysbld lspbld
	rm -rf dspbld ${XRP_DSP_BINARIES}
	rm -rf hostbld xrp-host-standalone
