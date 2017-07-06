xrp-y += xvp_main.o

obj-m += xrp.o

KSRC ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KSRC) M=`pwd` modules

%:
	$(MAKE) -C $(KSRC) M=`pwd` $@
