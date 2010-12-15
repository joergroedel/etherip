ifneq ($(KERNELRELEASE),)
  obj-m := etherip.o
else
  KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  MODULEDIR ?= /lib/modules/$(shell uname -r)/
  PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(MAKE) ethiptunnel

ethiptunnel: ethiptunnel.c
	$(CC) -Wall -O3 -o ethiptunnel ethiptunnel.c

install:
	cp etherip.ko $(MODULEDIR)/kernel/net/ipv4/
	mkdir -p $(HOME)/bin
	cp ethiptunnel $(HOME)/bin/
	depmod -a

clean:
	@rm -f etherip.ko etherip.mod.c etherip.mod.o etherip.o
	@rm -f ethiptunnel Module.symvers
	@find -type f -name "\.*"|xargs rm -f
	@rm -rf .tmp_versions
	@rm -f modules.order

.PHONY: clean

endif
