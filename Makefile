
obj-m += canToEthMod.o

CFLAGS = -Wall -g
ccflags-y += $(CFLAGS)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean