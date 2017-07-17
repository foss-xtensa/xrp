xrp-y += xvp_main.o xrp_address_map.o xrp_alloc.o xrp_firmware.o

obj-m += xrp.o
obj-$(XRP_HW_SIMPLE) += xrp_hw_simple.o

KSRC ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KSRC) M=`pwd` modules

%:
	$(MAKE) -C $(KSRC) M=`pwd` $@
