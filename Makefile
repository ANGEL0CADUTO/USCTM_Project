obj-m += sc_throttler.o
sc_throttler-objs += sc_throttler_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc user.c -o user_cli

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f user_cli