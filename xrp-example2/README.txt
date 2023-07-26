This directory contains a simple example that demonstrates xrp standalone use
case. It automatically builds the multi-core subsystem using config build
time generated subsystem description files. To build and run:

a) Set XTENSA_SYSTEM and XTENSA_CORE
b) source env.sh
c) make
   This builds the host side XRP library and the subsystem and runs
   the example under the 'src' directory.

Note, the config build time generated subsystem description files are 
available under the release specific config build directory. For ex:

/opt/xtensa/XtDevTools/install/builds/<release>/<config>/examples/MP_Subsystem/xt_sysbuilder_mp/

Also note that for the subsystem files to be auto-generated, the config must 
have at a minimum the following options selected:

a) Relocatable vector
b) Processor id 

To override, the auto-generated subsystem files (the xt_sysbuilder_mp
directory) from above, create a copy of the same in your current directory
and modify the subsys.yml, subsys.xld, and the Makefile.attr files to
match your custom subsystem and re-run step (c) above with

'make TARGET_SYSBUILD_EX_DIR=<you customized xt_sysbuilder_mp directory>'
