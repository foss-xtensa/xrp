# XRP example

## Makefile parameters:

- **Mandatory:**
    - `XTENSA_SYSTEM`
    - `XTENSA_CORE`
- **Optional:**
    - `XT_SUBSYS_SRC`: Path to location where to pull yml and xld files. Its default value is set to `$(shell xt-clang --show-config=config)/examples/MP_Subsystem/xt_sysbuilder_mp/`
    - `XRP_DSP_USE_SRCS`: When defined, use xrp-dsp sources instead of installed prebuilt xrp-dsp libraries.
    - `XRP_DSP_HW_PORT`: Select hardware port to build. Hardware port is a hardware-specific DSP library. In this release there are two ports bundled with the XRP code called `simple` and `simple-xos`.
        - `simple`: **(default)** XTSC model with MMIO regions for each DSP.
        - `simple-xos`: Variant of `simple` port that internally uses XOS and supports the multiqueue feature. It has the same hardware requirements as the `simple` port.
    - `XRP_HOST_QUEUE_TYPE`: Select whether to use HOST thread library for asynchronous processing. Without thread support, asynchronous operations like xrp_enqueue_command() will act synchronously.
        - `sync`: **(default)** Synchronous processing.
        - `threaded`: Enable thread support for asynchronous processing.
    - `XRP_HOST_MODE`: Select host configuration mode.
        - `standalone`: **(default)** Standalone Mode.
        - `hosted`: Hosted Mode. `XRP_HOST_CC` can be adjusted to the host-hosted compiler to use.
    - `XRP_DSP_DEBUG`: When defined, build DSP sources with CPPFLAGS -DDEBUG, which enables debug outputs through pr_debug().
    - `XRP_HOST_DEBUG`: When defined, build HOST sources with CPPFLAGS -DDEBUG, which enables debug outputs through pr_debug().
    - `BUILD_DIR`: When defined, it is the path where build outputs are generated.

## Building example:

- Set environments `XTENSA_CORE`, `XTENSA_SYSTEM` and `PATH`:
```
setenv XTENSA_SYSTEM '/<YOUR_TOOLS_PATH>/xtensa/XtDevTools/install/tools/RI-2022.10-linux/XtensaTools/config'
setenv XTENSA_CORE 'visionp6_ao'
setenv PATH "${XTENSA_SYSTEM}/../bin:${PATH}"
```

- Build using:
```
make all
```

## Running example:

```
make run
```
Expected output:
```
        SystemC 2.3.2-Accellera --- Nov 30 2022 16:02:58
        Copyright (c) 1996-2017 by all Contributors,
        ALL RIGHTS RESERVED
( kill -STOP ${BASHPID}; exec ./xrp-host-standalone )
=======================================================
=======================================================
f3: sz = 2048
comparing 0x7fcd700ec000 vs 0x7fcd700ed000
comparing 0x21b7460 vs 0x7fcd700ec000
comparing 0x7fcd700ec000 vs 0x21b7460
comparing 0x21b7460 vs 0x21b7c70
f3: sz = 4096
comparing 0x7fcd700ec000 vs 0x7fcd700ed000
comparing 0x21b7230 vs 0x7fcd700ec000
comparing 0x7fcd700ec000 vs 0x21b7230
comparing 0x21b7230 vs 0x21b8570
f3: sz = 8192
comparing 0x7fcd700ec000 vs 0x7fcd700ee000
comparing 0x21b72b0 vs 0x7fcd700ec000
comparing 0x7fcd700ec000 vs 0x21b72b0
comparing 0x21b72b0 vs 0x21b92c0
=======================================================
=======================================================
=======================================================
=======================================================
=======================================================
=======================================================
count[0] = 10
count[1] = 10
count[2] = 10
count[3] = 10
count[4] = 10
count[5] = 10
count[6] = 10
count[7] = 10
count[8] = 10
count[9] = 10
=======================================================
f10 doesn't test anything for devid < 2
=======================================================
```
