#! /bin/bash -ex

if [ "$1" = "-c" ] ; then RECONFIG=1 ; fi

DIR=build-linux
[ -z "$RECONFIG" ] || ( rm -rf $DIR ; mkdir $DIR ; cd $DIR ; ../configure --prefix=`pwd`/root --disable-dsp --disable-sim --enable-example )
make -C $DIR

DIR=build-linux-sim
[ -z "$RECONFIG" ] || ( rm -rf $DIR ; mkdir $DIR ; cd $DIR ; ../configure --prefix=`pwd`/root --disable-dsp --enable-sim --enable-example )
make -C build-linux-sim

export PATH=/opt/xtensa/XtDevTools/install/tools/RG-2017.7-linux/XtensaTools/bin:$PATH
export XTENSA_CORE=visionp6cnn_ao_exls

DIR=build-dsp
[ -z "$RECONFIG" ] || ( rm -rf $DIR ; mkdir $DIR ; cd $DIR ; ../configure --prefix=`pwd`/root --host=xtensa-elf --enable-dsp --disable-sim --enable-example DSP_CORE=visionp6cnn_ao_exls CC=xt-xcc )
make -C $DIR \
	DSP_LSP=`pwd`/xrp-example/MW-MP/P6_0/xtensa-elf/lib/sim-stacklocal

DIR=build-dsp-sim
[ -z "$RECONFIG" ] || ( rm -rf $DIR ; mkdir $DIR ; cd $DIR ; ../configure --prefix=`pwd`/root --host=xtensa-elf --enable-dsp --enable-sim --enable-example DSP_CORE=visionp6cnn_ao_exls CC=xt-xcc )
make -C $DIR \
	DSP_LSP=`pwd`/xrp-example/MW-MP/P6_0/xtensa-elf/lib/sim-stacklocal \
	DSP_COMM_BASE=0xf0000000
mv $DIR/xrp-example/xrp-dsp-sim{,0}

make -C $DIR \
	DSP_LSP=`pwd`/xrp-example/MW-MP/P6_1/xtensa-elf/lib/sim-stacklocal \
	DSP_COMM_BASE=0xf4000000
mv $DIR/xrp-example/xrp-dsp-sim{,1}
