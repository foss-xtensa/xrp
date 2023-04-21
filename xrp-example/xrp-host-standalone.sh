#!/bin/bash

# Print script lines as they are read.
#set -v

# Enable job control.
set -m

( kill -STOP ${BASHPID}; exec ./xrp-host-standalone; ) & XRP_HOST_STANDALONE_PID=$!

xtsc-run \
--set_xtsc_parm=turbo=true \
--define=Host_BINARY= \
--define=Host_BINARY_ARGS= \
--define=DSP_0_BINARY=xrp-dsp-standalone0 \
--define=DSP_1_BINARY=xrp-dsp-standalone1 \
--define=SHARED_RAM_L_NAME=SharedRAM_L.${XRP_HOST_STANDALONE_PID} \
--include=./sysbld/xtsc-run/SubSystem.inc & XTSC_RUN_PID=$!

while [ ! -e /dev/shm/SharedRAM_L.${XRP_HOST_STANDALONE_PID} ]; do true; done

# Resume paused xrp-host-standalone process and make it the foreground process.
fg %1

kill -TERM ${XTSC_RUN_PID}
rm /dev/shm/SharedRAM_L.${XRP_HOST_STANDALONE_PID}
