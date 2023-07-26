# Use from PATH or relative to XTENSA_SYSTEM
XT_RUN := $(shell PATH=$(XTENSA_SYSTEM)/../bin:$(PATH) which xt-run)

$(info XTENSA_SYSTEM set to $(XTENSA_SYSTEM))
$(info XTENSA_CORE set to $(XTENSA_CORE))

XTOOLS_DIR := $(shell $(XT_RUN) --show-config=xttools)
XTCONFIG_DIR := $(shell $(XT_RUN) --show-config=config)
TCTOOLS := $(shell $(XT_RUN) --show-config=tctools)

SUBSYSTEM_BUILD_DIR=Subsystem

# Path to pre-generated subsystem description files
TARGET_SYSBUILD_EX_DIR?=$(XTCONFIG_DIR)/examples/MP_Subsystem/xt_sysbuilder_mp

# Paths to subsystem spec files for xt-mbuild. These are generated at
# config build time.
# Subsystem spec with X86 host + multi-core DSP subsystem
XLD_FILE=$(TARGET_SYSBUILD_EX_DIR)/subsys.xld

# Paths to subsystem spec files for xt-sysbuilder. These are generated at
# config build time.
# Subsystem spec with X86 host + multi-core DSP subsystem
YML_FILE=$(TARGET_SYSBUILD_EX_DIR)/subsys.yml

# Platform specific cache attributes + XRP communication base address
PLATFORM_MAKEFILE=src/Makefile.platform

# XRP for host
HOST_XRP_SRC=xrp_standalone/xrp_src

# XRP host libraries build/install dir
BUILD=xrp_build_dir
INSTALL=xrp_install_dir

default: build test

build: $(SUBSYSTEM_BUILD_DIR)/LSP $(SUBSYSTEM_BUILD_DIR)/xtsc-run.sim $(PLATFORM_MAKEFILE) xrp_build

xrp_build: $(HOST_XRP_SRC)
	rm -rf $(BUILD) $(INSTALL)
	mkdir -p $(BUILD)
	cd $(BUILD) &&                                \
		CC=gcc CXX=g++ cmake ..                     \
      -DXTENSA_TOOLS_DIR=$(XTENSA_TOOLS)        \
      -DCMAKE_BUILD_TYPE=Release                \
      -DCMAKE_INSTALL_PREFIX=../$(INSTALL) &&   \
    make -j16 install                        && \
  cd ..
	rm -rf $(BUILD)

# Build the LSPs for the DSP subsystem with X86 and Xtensa/Linux host
$(SUBSYSTEM_BUILD_DIR)/LSP: $(SUBSYSTEM_BUILD_DIR) $(XLD_FILE)
	rm -rf $(SUBSYSTEM_BUILD_DIR)/LSP $(SUBSYSTEM_BUILD_DIR)/LSP_build 
	mkdir $(SUBSYSTEM_BUILD_DIR)/LSP
	$(XTOOLS_DIR)/libexec/xt-mbuild -root $(SUBSYSTEM_BUILD_DIR)/LSP_build -syspkg $(SUBSYSTEM_BUILD_DIR)/LSP_build/package -tctools $(TCTOOLS) -socfile $(XLD_FILE) -preclean -build sw -lsps sim,sim-stacklocal
	cp -r $(SUBSYSTEM_BUILD_DIR)/LSP_build/package/cores/* $(SUBSYSTEM_BUILD_DIR)/LSP
	rm -rf $(SUBSYSTEM_BUILD_DIR)/LSP_build

# Build the xtsc model and xrp spec for the DSP subsystem with X86 host
$(SUBSYSTEM_BUILD_DIR)/xtsc-run.sim: $(SUBSYSTEM_BUILD_DIR) $(YML_FILE)
	rm -rf $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild $(SUBSYSTEM_BUILD_DIR)/xtsc-run.sim
	$(XTOOLS_DIR)/libexec/xt-sysbuilder -subsys $(YML_FILE) -swtools $(XTOOLS_DIR) -build $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild -xtensa-system $(XTENSA_SYSTEM)
	cp -r $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild/xtsc-run $(SUBSYSTEM_BUILD_DIR)/xtsc-run.sim
	cp -r $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild/xrp/XRP_Controller.lua $(SUBSYSTEM_BUILD_DIR)/xtsc-run.sim/TestBenchMaster.vec
	cp -r $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild/xrp/TestSubSys.dts $(SUBSYSTEM_BUILD_DIR)/xrp.dts
	rm -rf $(SUBSYSTEM_BUILD_DIR)/dsp_sysbuild

# Copy over the XRP host sources
$(HOST_XRP_SRC): 
	rm -rf $(HOST_XRP_SRC)
	mkdir -p $(HOST_XRP_SRC)
	cp -rf $(XTOOLS_DIR)/xtensa-elf/src/xrp/xrp_api.h $(HOST_XRP_SRC)
	cp -rf $(XTOOLS_DIR)/xtensa-elf/src/xrp/xrp-common $(HOST_XRP_SRC)
	cp -rf $(XTOOLS_DIR)/xtensa-elf/src/xrp/xrp-host $(HOST_XRP_SRC)
	cp -rf $(XTOOLS_DIR)/xtensa-elf/src/xrp/xrp-kernel $(HOST_XRP_SRC)

$(PLATFORM_MAKEFILE):
	cp -f $(TARGET_SYSBUILD_EX_DIR)/Makefile.attr $(PLATFORM_MAKEFILE)

BUILD_DIR=build
INSTALL_DIR=install

$(SUBSYSTEM_BUILD_DIR):
	mkdir -p $(SUBSYSTEM_BUILD_DIR)

test:
	make -C src

.PHONY: all clean spotless test

clean:
	rm -rf $(BUILD) $(INSTALL)
	make -C src clean

spotless: clean
	rm -rf $(SUBSYSTEM_BUILD_DIR)
	rm -rf $(HOST_XRP_SRC)
	rm -rf $(PLATFORM_MAKEFILE)
