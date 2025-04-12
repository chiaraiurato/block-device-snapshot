obj-m += the_block-device-snapshot.o
the_block-device-snapshot-objs += block-device-snapshot.o lib/scth.o utils/auth.o register/register.o

SYS_CALL_TABLE = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address 2>/dev/null)
LOG_DIRECTORY_PATH = /tmp/bdevsnap.log
SECR3T = $(shell cat ./s3cr3t)
USER_APP = user/user.out
USER_SRC = user/user.c
SINGLEFILE_FS_DIR = singlefile-FS

all: compile mount compile-user 

compile:
	@echo "Compiling modules..."
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm modules
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@gcc $(SINGLEFILE_FS_DIR)/singlefilemakefs.c -o singlefilemakefs
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/singlefile-FS modules
	@echo "Compilation completed successfully"

create_singlefilefs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir $(LOG_DIRECTORY_PATH)

mount:
	@echo "Mounting modules..."
	@if ! lsmod | grep -q the_usctm; then \
		sudo insmod the_usctm/the_usctm.ko; \
		echo "usctm module loaded"; \
	else \
		echo "usctm module already loaded"; \
	fi
	@if [ -z "$(SYS_CALL_TABLE)" ]; then \
		echo "Error: SYS_CALL_TABLE is empty. Ensure the_usctm module is loaded correctly."; \
		exit 1; \
	fi
	@sudo insmod the_block-device-snapshot.ko the_syscall_table=$(SYS_CALL_TABLE) the_snapshot_secret=$(SECR3T) || \
		(echo "Failed to load block-device-snapshot module"; exit 1)
	
	
mount_fs:
	sudo insmod $(SINGLEFILE_FS_DIR)/singlefilefs.ko
	sudo mount -o loop -t singlefilefs image $(LOG_DIRECTORY_PATH)/
	@echo "Modules mounted successfully"

unmount_fs:
	sudo umount $(LOG_DIRECTORY_PATH)/ -f

compile-user:
	@echo "Compiling user application..."
	@gcc $(USER_SRC) -o $(USER_APP)
	@echo "User application compiled successfully"

run-user: compile-user
	@echo "Running user application with sudo..."
	@sudo $(USER_APP)
	@echo "User application execution completed"

clean: unmount unmount_fs clean-compile clean-fs

clean-compile:
	@echo "Cleaning up..."
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm clean
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rmdir $(LOG_DIRECTORY_PATH)
	@echo "Cleanup completed"
	
clean-fs:
	@rm -f singlefile-FS/singlefilemakefs singlefile-FS/image
	@echo "Single file system cleanup completed"


unmount:
	@echo "Unmounting modules..."
	@-sudo rmmod the_block-device-snapshot 2>/dev/null && echo "block-device-snapshot module unloaded" || echo "block-device-snapshot module not loaded"
	# @-sudo rmmod the_usctm 2>/dev/null && echo "usctm module unloaded" || echo "usctm module not loaded"
	@-sudo rmmod ./singlefile-FS/singlefilefs.ko
	@echo "Unmount completed"

.PHONY: all compile mount clean clean-compile unmount
