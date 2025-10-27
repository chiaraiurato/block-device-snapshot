obj-m += the_block-device-snapshot.o
the_block-device-snapshot-objs += block-device-snapshot.o lib/scth.o utils/auth.o register/register.o snapshot/snapshot.o

MOUNT_PATH = mount
USER_APP = user/user.out
USER_SRC = user/user.c
RESTORE_APP = restore/restore.out
RESTORE_SRC = restore/restore.c
SINGLEFILE_FS_DIR = singlefile-FS
ATTACK_APP = test/attack.out
ATTACK_SRC = test/attack.c
TEST_DIR = test/example_files

all: compile mount compile-user 

compile:
	@echo "Compiling modules..."
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm modules
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@gcc $(SINGLEFILE_FS_DIR)/singlefilemakefs.c -o singlefilemakefs
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/singlefile-FS modules
	mkdir $(MOUNT_PATH)
	@echo "Compilation completed successfully"

create-singlefilefs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image

create-ext4:
	dd if=/dev/zero of=ext4 bs=1M count=100
	mkfs.ext4 -b 4096 ext4

mount:
	@echo "Mounting modules..."
	@if ! lsmod | grep -q '^the_usctm'; then \
		echo "[mount] loading the_usctm.ko"; \
		sudo insmod the_usctm/the_usctm.ko || { echo "ERROR: failed to load the_usctm"; exit 1; }; \
	else \
		echo "[mount] the_usctm already loaded"; \
	fi; \
	\
	SYSFS_FILE=/sys/module/the_usctm/parameters/sys_call_table_address; \
	echo "[mount] waiting for $$SYSFS_FILE"; \
	for i in $$(seq 1 100); do \
		if [ -e "$$SYSFS_FILE" ]; then \
			SYS_CALL_TABLE=$$(sudo cat "$$SYSFS_FILE" 2>/dev/null); \
			[ -n "$$SYS_CALL_TABLE" ] && break; \
		fi; \
		sleep 0.05; \
	done; \
	if [ -z "$$SYS_CALL_TABLE" ]; then \
		echo "ERROR: SYS_CALL_TABLE is empty (cannot read $$SYSFS_FILE)"; \
		exit 1; \
	fi; \
	echo "[mount] sys_call_table=$$SYS_CALL_TABLE"; \
	\
	if [ ! -f ./s3cr3t ]; then \
		echo "ERROR: ./s3cr3t not found"; \
		exit 1; \
	fi; \
	SECR3T_VAL=$$(cat ./s3cr3t); \
	if [ -z "$$SECR3T_VAL" ]; then \
		echo "ERROR: ./s3cr3t is empty"; \
		exit 1; \
	fi; \
	echo "[mount] loading the_block-device-snapshot.ko"; \
	sudo insmod the_block-device-snapshot.ko \
		the_syscall_table=$$SYS_CALL_TABLE \
		the_snapshot_secret=$$SECR3T_VAL use_bio_layer=1 || { echo "ERROR: failed to load snapshot"; exit 1; }

load-fs:
	sudo insmod $(SINGLEFILE_FS_DIR)/singlefilefs.ko
	@echo "Insmod singlefilefs module successfully"
	
mount-fs:
	sudo mount -o loop -t singlefilefs image ./$(MOUNT_PATH)/
	@echo "Singlefile-fs mounted successfully"

unmount:
	sudo umount $(MOUNT_PATH)/ -f
	@echo "Singlefile-fs unmounted successfully"

mount-ext4:
	sudo mount -o loop -t ext4 ext4 ./$(MOUNT_PATH)/

compile-user:
	@echo "Compiling user application..."
	@gcc $(USER_SRC) -o $(USER_APP)
	@echo "User application compiled successfully"

run-user: compile-user
	@echo "Running user application with sudo..."
	@sudo $(USER_APP)
	@echo "User application execution completed"

compile-restore:
	@echo "Compiling restore application..."
	@gcc $(RESTORE_SRC) -o $(RESTORE_APP) -Wall -Wextra
	@echo "Restore application compiled successfully"

compile-attack:
	@gcc $(ATTACK_SRC) -o $(ATTACK_APP) -O2 -Wall -Wextra -D_FILE_OFFSET_BITS=64
	@echo "Attack application compiled successfully"

setup-test-files:
	@echo "Copying test files to mount point"
	@sudo cp -v "$(TEST_DIR)"/* "$(MOUNT_PATH)/"
	@sudo chmod 644 "$(MOUNT_PATH)"/*
	@echo ""
	@echo "Files ready in $(MOUNT_PATH)"
	@sudo ls -lh "$(MOUNT_PATH)"

ransom-attack:
	@echo "Executing ransomware attack"
	@if [ ! -f ./$(ATTACK_APP) ]; then \
		echo "Error: compile first with 'make compile-attack'"; \
		exit 1; \
	fi
	@echo "Encrypting all files in $(MOUNT_PATH)..."
	@for file in $(MOUNT_PATH)/*; do \
		if [ -f "$$file" ]; then \
			echo "  [ENCRYPT] $$file"; \
			sudo ./$(ATTACK_APP) "$$file"; \
		fi \
	done
	@echo ""
	@echo "Attack completed"
	@sudo ls -lh "$(MOUNT_PATH)"


clean: unmount-mod clean-compile

clean-compile:
	@echo "Cleaning up..."
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm clean
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -rf $(MOUNT_PATH)
	@echo "Cleanup completed"
	
clean-fs:
	@rm -f singlefile-FS/singlefilemakefs singlefile-FS/image
	@echo "Single file system cleanup completed"


unmount-mod:
	@echo "Unmounting modules..."
	@-sudo rmmod the_block-device-snapshot 2>/dev/null && echo "block-device-snapshot module unloaded" || echo "block-device-snapshot module not loaded"
	# @-sudo rmmod the_usctm 2>/dev/null && echo "usctm module unloaded" || echo "usctm module not loaded"
	@echo "Unmount completed"

rmmod-fs:
	@-sudo rmmod singlefilefs
	@echo "Unmounted single file system"


.PHONY: all compile mount create-singlefilefs create-ext4 \
        load-fs mount-fs unmount mount-ext4 \
        compile-user compile-restore compile-attack \
        clean clean-compile clean-fs unmount-mod rmmod-fs \
		setup-test-files ransom-attack
