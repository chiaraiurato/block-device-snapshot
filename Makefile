obj-m += block-device-snapshot.o
block-device-snapshot-objs += block-device-snapshot.o lib/scth.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(uname -r)/build M=$(PWD)/the_usctm modules 
	make -C /lib/modules/$(uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(uname -r)/build M=$(PWD)/the_usctm clean
	make -C /lib/modules/$(uname -r)/build M=$(PWD) clean
mount:
	cd the_usctm && insmod the_usctm.ko
	insmod block-device-snapshot.ko the_syscall_table=$$(cat /sys/module/the_usctm/parameters/sys_call_table_address)
unmount:
	cd the_usctm && rmmod the_usctm.ko
	rmmod block-device-snapshot.ko
 
# enable_rec_on:
# 	echo "1" > /sys/module/the_reference-monitor/parameters/enable_rec_on 
# enable_rec_off:
# 	echo "1" > /sys/module/the_reference-monitor/parameters/enable_rec_off 
# disable_rec_on:
# 	echo "0" > /sys/module/the_queuing_service/parameters/enable_rec_on 
# disable_rec_off:
# 	echo "0" > /sys/module/the_queuing_service/parameters/enable_rec_off 
	