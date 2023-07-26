CC = gcc
XT_RUN := $(shell PATH=$(XTENSA_SYSTEM)/../bin:$(PATH) which xt-run)

# If using gcc/g++ from tools, use rpath from the lib under tools
BUILD_CC := $(shell which gcc)
XTENSA_TOOLS_CC := $(shell echo "${XTENSA_TOOLS}/bin/gcc" | sed -e "s/^\(\/\.\)\+//g")
ifeq ($(LIB64_PATH), )
  ifeq ($(BUILD_CC), ${XTENSA_TOOLS_CC})
    LIB64_PATH ?= $(shell $(XT_RUN) --show-config=xttools)/Tools/lib64
  else
    LIB64_PATH =
  endif
endif

# Conditionally add -L if using libraries from tools (eg: libfdt)
ifneq ($(LIB64_PATH), )
  L_LIB64 = -L$(LIB64_PATH)
else
  L_LIB64 =
endif

# Conditional add path to libfdt if externally defined
ifneq ($(LIB_FDT_PATH), )
  L_LIB_FDT = -L$(LIB_FDT_PATH)
else
  L_LIB_FDT =
endif

XTSC_RUN=$(XTENSA_SYSTEM)/../bin/xtsc-run
ifeq (,$(wildcard $(XTSC_RUN)))
  # Fall back to xtsc-run from PATH
  XTSC_RUN=xtsc-run
endif

XTTOOLS = $(shell ${XT_RUN} --show-config=xttools)

-include Makefile.platform

CORE_NUMS = 0 $(shell seq `expr $(NUM_CORES) - 1`)

CORES = $(addprefix DSP_,$(CORE_NUMS))
BINARIES = $(addsuffix .exe,$(CORES))
XTSC_RUN_BINARY_DEF = $(addprefix --define=,$(join \
                        $(addsuffix _BINARY=,$(CORES)), $(BINARIES)))
XTSC_INC_FILE = ../Subsystem/xtsc-run.sim/TestSubSys.inc
HOST_EXE = host.exe

HOST_OBJS=host.o

HOST_LDFLAGS = -L ../xrp_install_dir/lib -lxrp-standalone \
               ../xrp_install_dir/lib/xrp.dts.o \
               -lpthread -lfdt -lrt $(L_LIB64) $(L_LIB_FDT) -Wl,-rpath=$(LIB64_PATH) -Wl,-rpath=$(LIB_FDT_PATH)

all: test

$(BINARIES): %.exe: dsp.c
	$(XTTOOLS)/bin/xt-clang -O2 $< -o $@ \
            -lxrp-dsp -lxrp-dsp-hw-simple -lxrp-common \
            -Wl,--defsym,xrp_dsp_comm_base_magic=$($*_DEVICE_COMM_BASE_MAGIC) \
            -Wl,--defsym,_memmap_cacheattr_reset=${CACHE_ATTR} \
            -mlsp=../Subsystem/LSP/$*/xtensa-elf/lib/sim

$(HOST_OBJS): %.o: %.c
	$(CC) -I ../xrp_standalone/xrp_src/ -O2 -c $< -o $@

$(HOST_EXE): $(HOST_OBJS)
	$(CC) $^ -o $@ $(HOST_LDFLAGS)

define run_pre
  rm -rf run_sim.sh; \
  cat ./run_prologue.sh > run_sim.sh; \
  echo "set -x" >> run_sim.sh; \
  echo "./$(1) & pids[0]=\$$!" >> run_sim.sh; \
  echo "sleep 1" >> run_sim.sh
endef 

define run_post
  chmod 755 run_sim.sh; \
  ./run_sim.sh; \
  rm -rf run_sim.sh
endef

test: $(BINARIES) $(HOST_EXE)
	@$(call run_pre,$(HOST_EXE))
	@echo "$(XTSC_RUN) \
         --set_xtsc_parm=turbo=true \
         --set_xtsc_parm=turbo_max_relaxed_cycles=10000000 \
         $(XTSC_RUN_BINARY_DEF) \
         --include=$(XTSC_INC_FILE) & pids[1]=\$$!" >> run_sim.sh
	@echo "wait" >> run_sim.sh
	@$(call run_post)

clean:
	-rm -rf $(BINARIES) $(HOST_EXE) $(HOST_OBJS)
