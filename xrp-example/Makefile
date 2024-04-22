
-include Makefile.common

.PHONY: all
all: xrpdsp xrphost

.PHONY: dsplibs
dsplibs: ${DSPBLD}/.stmp ${DSPBLD}/libxrp-common.a ${DSPBLD}/libxrp-dsp-hw-simple.a ${DSPBLD}/libxrp-dsp-hw-simple-xos.a ${DSPBLD}/libxrp-dsp.a

.PHONY: xrpdsp
xrpdsp: ${DSPBLD}/.stmp $(if ${SUBSYS_XLD_EXIST},${LSPBLD}) ${XRP_DSP_BINARIES}

.PHONY: xrphost
xrphost: ${HOSTBLD}/.stmp ${SYSBLD} ${BLDDIR}/xrp-host-${XRP_HOST_MODE}

.PHONY: xrphosted
xrphosted:
	make XRP_HOST_MODE=hosted ${BLDDIR}/xrp-host-hosted

.PHONY: xrpsingle
xrpsingle:
	make XRP_HOST_MODE=single ${BLDDIR}/xrp-host-single

## Build subsystem and DTS
${SYSBLD}:
	[ -d "${XT_SUBSYS_SRC}" ] && cp ${XT_SUBSYS_SRC}/subsys.yml ${BLDDIR}
	${XTENSA_TOOLS}/libexec/xt-sysbuilder \
	  -add_xrp_shmem_pid \
	  -subsys ${BLDDIR}/subsys.yml \
	  -swtools ${XTENSA_TOOLS} \
	  -build ${SYSBLD}
	cp ${SYSBLD}/xrp/XRP_Controller.lua ${SYSBLD}/xtsc-run/TestBenchMaster.vec

## Build LSPs
${LSPBLD}:
	[ -d "${XT_SUBSYS_SRC}" ] && cp ${XT_SUBSYS_SRC}/subsys.xld ${BLDDIR}
	${XTENSA_TOOLS}/libexec/xt-mbuild \
	  -root ${LSPBLD} \
	  -syspkg ${LSPBLD}/package \
	  -socfile ${BLDDIR}/subsys.xld \
	  -preclean \
	  -build sw \
	  -lsps sim,sim-stacklocal

${DSPBLD}/.stmp:
	mkdir -p $(shell dirname $@)
	touch $@

${DSPBLD}/xrp_rb_file.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp_rb_file.o: ${XRP_SRC}/xrp-common/xrp_rb_file.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/xrp_ns.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp_ns.o: ${XRP_SRC}/xrp-common/xrp_ns.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/libxrp-common.a: ${DSPBLD}/xrp_rb_file.o ${DSPBLD}/xrp_ns.o
	$(XRP_DSP_AR) cru $@ $^
	$(XRP_DSP_RANLIB) $@

${DSPBLD}/xrp-dsp-hw-simple.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp-dsp-hw-simple.o: ${XRP_SRC}/xrp-dsp/simple/xrp_dsp_hw_simple.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/libxrp-dsp-hw-simple.a: ${DSPBLD}/xrp-dsp-hw-simple.o
	$(XRP_DSP_AR) cru $@ $^
	$(XRP_DSP_RANLIB) $@

${DSPBLD}/xrp-dsp-hw-simple-xos.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp-dsp-hw-simple-xos.o: ${XRP_SRC}/xrp-dsp/simple-xos/xrp_dsp_hw_simple-xos.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/libxrp-dsp-hw-simple-xos.a: ${DSPBLD}/xrp-dsp-hw-simple-xos.o
	$(XRP_DSP_AR) cru $@ $^
	$(XRP_DSP_RANLIB) $@

${DSPBLD}/xrp-dsp.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp-dsp.o: ${XRP_SRC}/xrp-dsp/xrp_dsp.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/libxrp-dsp.a: ${DSPBLD}/xrp-dsp.o
	$(XRP_DSP_AR) cru $@ $^
	$(XRP_DSP_RANLIB) $@

${DSPBLD}/xrp_dsp_standalone-dsp_test.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp_dsp_standalone-dsp_test.o: ${XRP_SRC}/xrp-example/dsp_test.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${DSPBLD}/xrp_dsp_standalone-dsp_main.o: ${DSPBLD}/.stmp
${DSPBLD}/xrp_dsp_standalone-dsp_main.o: ${XRP_SRC}/xrp-example/dsp_main.c
	$(XRP_DSP_CC) -c $(XRP_DSP_CFLAGS) $(XRP_DSP_CPPFLAGS) \
	  -o $@ $<

${BLDDIR}/xrp-dsp-standalone%: ${XRP_DSP_LIBS_OBJS} ${DSPBLD}/xrp_dsp_standalone-dsp_test.o ${DSPBLD}/xrp_dsp_standalone-dsp_main.o
	$(XRP_DSP_CC) \
	  $(if ${SUBSYS_XLD_EXIST},-mlsp=${LSPBLD}/package/cores/${CORE_NAME_PREFIX}${*}/xtensa-elf/lib/sim-stacklocal) \
	  -Wl,--defsym,_memmap_cacheattr_reset=${CACHE_ATTR} \
	  -Wl,--defsym,xrp_dsp_comm_base_magic=${${CORE_NAME_PREFIX}${*}_DEVICE_COMM_BASE_MAGIC} \
	  -o $@ $^ -Wl,--start-group ${XRP_DSP_LDFLAGS} -Wl,--end-group

${HOSTBLD}/.stmp:
	mkdir -p $(shell dirname $@)
	touch $@

${HOSTBLD}/xrp_rb_file.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_rb_file.o: ${XRP_SRC}/xrp-common/xrp_rb_file.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_ns.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_ns.o: ${XRP_SRC}/xrp-common/xrp_ns.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_host_common.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_host_common.o: ${XRP_SRC}/xrp-host/xrp_host_common.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o: ${XRP_SRC}/xrp-host/xrp_${XRP_HOST_QUEUE_TYPE}_queue.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_host.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_host.o: ${XRP_SRC}/xrp-host/standalone/xrp_host.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_linux.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_linux.o: ${XRP_SRC}/xrp-host/standalone/xrp_linux.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp_alloc.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_alloc.o: ${XRP_SRC}/xrp-kernel/xrp_alloc.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $<

${HOSTBLD}/xrp.dtb: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp.dtb: ${SYSBLD}/xrp/SubSystem.dts
	${DTC} -o $@ -O dtb $<

${HOSTBLD}/xrp_dtb.o: ${HOSTBLD}/.stmp
${HOSTBLD}/xrp_dtb.o: ${XRP_SRC}/xrp-example/xrp_dtb.s ${HOSTBLD}/xrp.dtb
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) \
	  -I${HOSTBLD} \
	  -o $@ $<

${HOSTBLD}/host_main.o: ${HOSTBLD}/.stmp
${HOSTBLD}/host_main.o: ${XRP_SRC}/xrp-example/host_main.c
	$(XRP_HOST_CC) -c $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -I${XRP_SRC} \
	  -o $@ $<

${BLDDIR}/xrp-host-standalone: \
  ${HOSTBLD}/xrp_rb_file.o ${HOSTBLD}/xrp_ns.o \
  ${HOSTBLD}/xrp_host_common.o ${HOSTBLD}/xrp_${XRP_HOST_QUEUE_TYPE}_queue.o \
  ${HOSTBLD}/xrp_host.o ${HOSTBLD}/xrp_linux.o ${HOSTBLD}/xrp_alloc.o \
  ${HOSTBLD}/xrp_dtb.o ${HOSTBLD}/host_main.o
	$(XRP_HOST_CC) $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $^ \
	  -L${LIBFDT_PATH}/lib -Wl,-rpath ${LIBFDT_PATH}/lib \
	  -pthread -lfdt -lrt

${BLDDIR}/xrp-host-hosted: \
  ${XRP_SRC}/xrp-common/xrp_rb_file.c \
  ${XRP_SRC}/xrp-common/xrp_ns.c \
  ${XRP_SRC}/xrp-host/xrp_host_common.c \
  ${XRP_SRC}/xrp-host/xrp_${XRP_HOST_QUEUE_TYPE}_queue.c \
  ${XRP_SRC}/xrp-host/hosted/xrp_hosted.c \
  ${XRP_SRC}/xrp-example/host_main.c
	$(XRP_HOST_CC) $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $^ \
	  -pthread -lrt

${BLDDIR}/xrp-host-single: \
  ${XRP_SRC}/xrp-common/xrp_rb_file.c \
  ${XRP_SRC}/xrp-common/xrp_ns.c \
  ${XRP_SRC}/xrp-host/xrp_host_common.c \
  ${XRP_SRC}/xrp-host/xrp_${XRP_HOST_QUEUE_TYPE}_queue.c \
  ${XRP_SRC}/xrp-host/single/xrp_single.c \
  ${XRP_SRC}/xrp-example/host_main.c \
  ${XRP_SRC}/xrp-example/dsp_test.c
	$(XRP_HOST_CC) $(XRP_HOST_CFLAGS) $(XRP_HOST_CPPFLAGS) \
	  -o $@ $^


.PHONY: run
run:
	BUILD_DIR=${BLDDIR} ./xrp-host-standalone.sh ${XTSC_RUN_BINARY_DEF}


.PHONY: clean
clean:
	rm -rf ${BLDDIR}/subsys.* ${SYSBLD} ${LSPBLD}
	rm -rf ${DSPBLD} ${XRP_DSP_BINARIES}
	rm -rf ${HOSTBLD} ${BLDDIR}/xrp-host-{standalone,hosted,single}
