# XRP rtos-hosted example

This example builds upon the "standalone" mode example described in xrp-example/README.md.
It consists of an example XTSC model describing:

- One "Host" config serving as the XRP host - by default, "sample_controller"
- One "DSP" config serving as the XRP DSP - by default, "Vision_P6_AO"
- Shared sysram accessible by both cores - by default, 16MB at 0x63000000
- A SubSystemMMIO block mapping interrupts between both cores

In this example, the Xtensa "Host" core runs FreeRTOS, which is configured
in single-core mode with static memory allocation.  This example creates one
task that manages the XRP driver and test code.  Timer tick interrupts are
handled by FreeRTOS.

The XRP library is configured in threaded mode such that the thread-freertos
host API implementation allows FreeRTOS to create threads for each XRP queue.

The Xtensa "DSP" core runs the "simple-xos" example described in 
xrp-example/README.md, which uses XOS to provide thread support for 
servicing multiple queues at different priorities (multiqueues).



# Relevant files:

- subsys-rtos-hosted.xld :
  subsys-rtos-hosted.yml :
    Description of the XTSC subsystem; used by xt-mbuild and xt-sysbuilder

- Makefile.attr :
    Describes DSP parameters, notably the where the DSP core can find
    the shared XRP memory; e.g. 0x63000000 in this example

- FreeRTOSConfig.h :
    Various parameters describing the example FreeRTOS configuration

- host_main_freertos.c :
  xrp_host_freertos.c :
    Example test code and initialization logic


## Makefile parameters:

- **Mandatory:**
    - `FREERTOS_SOURCE`: Path to the FreeRTOS-Kernel to build into this example
        - e.g. cloned git client from https://github.com/foss-xtensa/FreeRTOS-Kernel
        - Note: Ensure the git submodule instantiated in
          <FreeRTOS-Kernel>/portable/ThirdParty/Partner-Supported-Ports/ is included.

- **Optional:**
    - See xrp-example/README.md

- **Default values:** (for multiqueue support)
    - XRP_HOST_MODE       = rtos_hosted
    - XRP_HOST_QUEUE_TYPE = threaded
    - XRP_DSP_HW_PORT     = simple-xos
    - XRP_DSP_USE_SRCS    = 1 


## Building example:

- Set environments `XTENSA_CORE`, `XTENSA_SYSTEM` and `PATH`:
```
setenv XTENSA_SYSTEM '/<YOUR_TOOLS_PATH>/xtensa/XtDevTools/install/tools/RJ-2025.5-linux/XtensaTools/config'
setenv XTENSA_CORE 'sample_controller'
setenv PATH "${XTENSA_SYSTEM}/../bin:${PATH}"
```

- Build using:
```
make FREERTOS_SOURCE=<YOUR_FREERTOS_PATH> all
```


## Running example:

```
make FREERTOS_SOURCE=/<YOUR_FREERTOS_PATH>/FreeRTOS/FreeRTOS/Source run
```
Expected output:
```
        SystemC 2.3.3-Accellera --- Oct  1 2025 10:59:30
        Copyright (c) 1996-2018 by all Contributors,
        ALL RIGHTS RESERVED

FreeRTOS XRP example on Xtensa running...
==== f1 test start ====================================
==== f1 test finish ===================================
==== f2 test start ====================================
==== f2 test finish ===================================
==== f3 test start ====================================
f3: sz = 2048
comparing 0x63001000 vs 0x63002000
comparing 0x6012a7e0 vs 0x63001000
comparing 0x63001000 vs 0x6012a7e0
comparing 0x6012a7e0 vs 0x6012afe8
f3: sz = 4096
comparing 0x63001000 vs 0x63002000
comparing 0x6012a800 vs 0x63001000
comparing 0x63001000 vs 0x6012a800
comparing 0x6012a800 vs 0x6012b958
f3: sz = 8192
comparing 0x63001000 vs 0x63003000
comparing 0x6012a898 vs 0x63001000
comparing 0x63001000 vs 0x6012a7e0
comparing 0x6012a7e0 vs 0x6012c990
==== f3 test finish ===================================
==== f4 test start ====================================
==== f4 test finish ===================================
==== f5 test start ====================================
==== f5 test finish ===================================
==== f6 test start ====================================
==== f6 test finish ===================================
==== f7 test start ====================================
==== f7 test finish ===================================
==== f8 test start ====================================
==== f8 test finish ===================================
==== f9 test start ====================================
count[0] = 11
count[1] = 12
count[2] = 12
count[3] = 13
count[4] = 8
count[5] = 10
count[6] = 7
count[7] = 8
count[8] = 10
count[9] = 9
==== f9 test finish ===================================
==== f10 test start ===================================
f10 doesn't test anything for devid < 2
==== f10 test finish ==================================
XRP tests complete
```


## Additional notes

- This example has been verified to build and run on Linux.
  It may require changes in the makefiles to work on Windows.
