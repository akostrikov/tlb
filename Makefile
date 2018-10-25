CURRDIR = $(shell pwd)
KERNEL_BUILD_PATH=/lib/modules/$(shell uname -r)/build

KCOR_MOD = kcor
KCOR_MOD_KO = $(KCOR_MOD).ko

kcor-y +=	kcor_module.o

obj-m = $(KCOR_MOD).o

KBUILD_EXTRA_SYMBOLS = $(KERNEL_BUILD_PATH)/Module.symvers

ccflags-y := -I$(src) -g3

all:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) modules
clean:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) clean
	rm -f *.o
	rm -rf temp/
