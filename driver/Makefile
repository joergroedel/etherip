ifneq ($(KERNELRELEASE),)
  obj-m := etherip.o
else
  KVERS	     ?= $(shell uname -r)
  KERNEL_DIR ?= /lib/modules/$(KVERS)/build
  MODULE_DIR ?= /lib/modules/$(KVERS)/misc
  PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

install:
	mkdir -p $(DESTDIR)/$(MODULE_DIR)
	cp etherip.ko $(DESTDIR)/$(MODULE_DIR)/
	depmod -a
clean:
	@rm -f etherip.ko etherip.mod.c etherip.mod.o etherip.o
	@rm -f Module.symvers
	@find -type f -name "\.*"|xargs rm -f
	@rm -rf .tmp_versions
	@rm -f modules.order

.PHONY: clean

endif
