#
#Desgin of Netlink
#

ifneq ($(KERNELRELEASE),)
obj-m := netlink_kernel.o
tracert-objs += netlink_kernel.o
else
PWD := $(shell pwd)

modules:clean
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) modules -Wall
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers
endif
