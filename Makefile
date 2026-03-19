obj-m += sc_throttler.o
sc_throttler-objs += sc_throttler_module.o

TESTS_DIR := tests

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc user.c -o user_cli
	gcc $(TESTS_DIR)/test_barrier.c -o test_barrier -pthread
	gcc $(TESTS_DIR)/test_identity.c -o test_identity
	gcc $(TESTS_DIR)/test_uid.c -o test_uid
	gcc $(TESTS_DIR)/test_wallclock.c -o test_wallclock
	gcc $(TESTS_DIR)/test_getpid.c -o test_getpid
	gcc $(TESTS_DIR)/test_mkdir.c -o test_mkdir
	gcc $(TESTS_DIR)/test_stress.c -o test_stress

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f user_cli test_barrier test_identity test_uid test_wallclock test_getpid test_mkdir test_stress