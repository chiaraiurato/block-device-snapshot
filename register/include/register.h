#ifndef _REGISTER_H
#define _REGISTER_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include "../../snapshot/include/snapshot.h"

/* Maximum number of devices supported */
#define MAX_DEVICES 32

/* Size of loop device file name buffer */
#define LO_NAME_SIZE 64

/**
 * struct loop_device - Mirror of kernel's internal loop device structure
 * 
 * This local declaration is necessary because the kernel doesn't export
 * the complete loop device structure in any public header. We must maintain
 * identical member types and ordering to ensure correct offset calculations
 * when working with loop device objects through indirect access.
 *
 * WARNING: THIS STRUCTURE IS ONLY VALID FOR KERNEL VERSIONS 5.16 AND LATER.
 *
 * @lo_number: Loop device number
 * @lo_offset: Offset in the backing file
 * @lo_sizelimit: Size limit of the loop device
 * @lo_flags: Configuration flags for the loop device
 * @lo_file_name: Name of the backing file
 * @lo_backing_file: Pointer to the backing file structure
 * @lo_device: Pointer to the block device structure
 */
struct loop_device {
    int         lo_number;
    loff_t      lo_offset;
    loff_t      lo_sizelimit;
    int         lo_flags;
    char        lo_file_name[LO_NAME_SIZE];
    struct file *lo_backing_file;
    struct block_device *lo_device;
};

/**
 * register_device - Register a new device
 * @devname: Name of the device to register
 * Return: 0 on success, error code on failure
 */
int register_device(const char *devname);

/**
 * unregister_device - Unregister a device
 * @devname: Name of the device to unregister
 * Return: 0 on success, error code on failure
 */
int unregister_device(const char *devname);

/**
 * find_device - Find a registered device by name
 * @devname: Name of the device to find
 * Return: Pointer to the device if found, NULL otherwise
 */
snapshot_device *find_device(const char *devname);

/**
 * Create /snapshot directory if it doesn't exist
 */
int ensure_snapshot_root_directory(void);
/**
 * find_device_for_bdev - Try to find device using bdev
 */
snapshot_device *find_device_for_bdev(struct block_device *bdev);
/* Kernel Probe Functions */

/**
 * install_mount_hook - Install the mount event hook
 * Return: 0 on success, error code on failure
 */
int install_mount_hook(void);

/**
 * remove_mount_hook - Remove the mount event hook
 */
void remove_mount_hook(void);

#endif /* _REGISTER_H */