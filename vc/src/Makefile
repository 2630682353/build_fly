#
#Desgin of Netlink
#

ifneq ($(KERNELRELEASE),)
obj-m := vc.o
tracert-objs += vc.o
else
PWD := $(shell pwd)

modules:clean
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) modules -Wall
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers
endif
