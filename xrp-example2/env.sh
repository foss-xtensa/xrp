# Needs XTENSA_SYSTEM, XTENSA_CORE to be set
# Eg: 
#   export XTENSA_CORE=visionp6_ao
#   export XTENSA_SYSTEM=/opt/xtensa/XtDevTools/install/tools/<release>-linux/XtensaTools/config

if [ -z ${XTENSA_SYSTEM+x} ]
then
  echo "Environment variable XTENSA_SYSTEM is not defined"
  return 1
fi

if [ -z ${XTENSA_CORE+x} ]
then
  echo "Environment variable XTENSA_CORE is not defined"
  return 1
fi

# Use xt-run from PATH or relative to XTENSA_SYSTEM
if [ -x "$(command -v xt-run)" ]; then
  XT_RUN=xt-run
else
  XT_RUN=${XTENSA_SYSTEM}/../bin/xt-run
fi

TOOLS=`${XT_RUN} --show-config=xttools`/Tools

export XTENSA_TOOLS=${TOOLS}
# Note, if the system tools (gcc, cmake, etc.) are newer than the ones under
# ${TOOLS}/bin, add ${TOOLS}/bin to end of $PATH.
# If using a custom tools installation, set PATH to your location of gcc/g++
# and also set LIB_FDT_PATH to point to your location of libfdt.* and LIB64_PATH
# to point to your location gcc's lib64
export PATH=${TOOLS}/bin:$PATH
