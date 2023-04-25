# XRP example

## Makefile parameters:

- **Mandatory:**
    - `XTENSA_SYSTEM`
    - `XTENSA_CORE`
- **Optional:**
    - `XTSUBSYS_SRC`: Path to location where to pull yml and xld files.
    - `XRP_DSP_HW_PORT`
        - `simple` : default
        - `simple-xos`
    - `XRP_HOST_QUEUE_TYPE`
        - `sync` : default
        - `threaded`

## Building example:

- Set environments `XTENSA_CORE` and `XTENSA_SYSTEM`:
```
setenv XTENSA_SYSTEM '/path/xtensa/XtDevTools/install/tools/RI-2022.10-linux/XtensaTools/config'
setenv XTENSA_CORE 'visionp6_ao'
```

- Set environments `PATH` and `LD_LIBRARY_PATH`:
```
setenv PATH "${XTENSA_SYSTEM}/../bin:${PATH}"
setenv LD_LIBRARY_PATH "${XTENSA_SYSTEM}/../Tools/lib:${LD_LIBRARY_PATH}"
```

- Build using:
```
make all
```

## Running example:

```
make run
```
