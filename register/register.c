#include "include/register.h"
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/loop.h> 
#include <linux/kprobes.h>
#include <linux/buffer_head.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/major.h> 

// Global list to track active snapshot devices with spinlock protection
static LIST_HEAD(active_devices);
static DEFINE_SPINLOCK(devices_lock);

#include <linux/namei.h>
#include <linux/timekeeping.h>

// Ensure device names are sanitized for filesystem use
static void sanitize_devname(char *dst, const char *src)
{
    int i;
    for (i = 0; i < MAX_DEV_LEN - 1 && src[i]; i++) {
        dst[i] = (src[i] == '/') ? '_' : src[i];
    }
    dst[i] = '\0';
}
static int ensure_snapshot_root_directory(void) {
    struct path root_path;
    struct dentry *dentry;
    int err;

    // Verify if /snapshot already exists
    err = kern_path("/snapshot", LOOKUP_DIRECTORY, &root_path);
    if (!err) {
        path_put(&root_path); 
        return 0;
    }

    // Create /snapshot directory if it doesn't exist
    dentry = kern_path_create(AT_FDCWD, "/snapshot", &root_path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry)) {
        pr_err("SNAPSHOT: Failed to prepare /snapshot path: %ld\n", PTR_ERR(dentry));
        return PTR_ERR(dentry);
    }

    err = vfs_mkdir(mnt_idmap(root_path.mnt), d_inode(root_path.dentry), dentry, 0755);
    if (err && err != -EEXIST) {
        pr_err("SNAPSHOT: mkdir /snapshot failed: %d\n", err);
    } else {
        pr_info("SNAPSHOT: /snapshot created.\n");
    }

    done_path_create(&root_path, dentry);
    return err;
}

// Create /snapshot/devname_timestamp 
static void create_snapshot_subdirectory(const char *raw_devname) {
    char devname[MAX_DEV_LEN];
    char path[PATH_MAX];
    struct path parent_path;
    struct dentry *dentry;
    struct timespec64 ts;
    int err;

    sanitize_devname(devname, raw_devname);

    err = ensure_snapshot_root_directory();
    if (err) {
        pr_err("SNAPSHOT: Unable to ensure /snapshot exists\n");
        return;
    }

    // Get current time for timestamp
    ktime_get_real_ts64(&ts);

    // Craft the full path
    snprintf(path, sizeof(path), "/snapshot/%s_%lld", devname, ts.tv_sec);
    pr_info("SNAPSHOT: Creating snapshot directory: %s\n", path);

    // Create the subdirectory
    dentry = kern_path_create(AT_FDCWD, path, &parent_path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry)) {
        pr_err("SNAPSHOT: kern_path_create failed: %ld\n", PTR_ERR(dentry));
        return;
    }

    err = vfs_mkdir(mnt_idmap(parent_path.mnt), d_inode(parent_path.dentry), dentry, 0755);
    if (err && err != -EEXIST) {
        pr_err("SNAPSHOT: mkdir failed: %d\n", err);
    } else {
        pr_info("SNAPSHOT: Snapshot directory created: %s\n", path);
    }

    done_path_create(&parent_path, dentry);
}


#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
void handle_mount_event(struct block_device *bd) {
    pr_warn("SNAPSHOT: handle_mount_event not supported for kernel < 5.16\n");
}
#else
void handle_mount_event(struct block_device *bdev) {
    char devname[MAX_DEV_LEN] = {0};
    
    if (!bdev) return;

    // Handle regular block devices vs loop devices differently
    if (MAJOR(bdev->bd_dev) != LOOP_MAJOR) {
        // For regular block devices, just get the disk name
        snprintf(devname, MAX_DEV_LEN, "%s", bdev->bd_disk->disk_name);
    } else {
        // For loop devices, get the backing file path
        struct loop_device *ldev = (struct loop_device *)bdev->bd_disk->private_data;
        struct file *backing_file = ldev->lo_backing_file;
        if (backing_file) {
            char *tmp;
            tmp = d_path(&backing_file->f_path, devname, MAX_DEV_LEN);
            if (!IS_ERR(tmp)) {
                snprintf(devname, MAX_DEV_LEN, "%s", tmp);
            } else {
                pr_err("SNAPSHOT: Failed to get backing file path\n");
                return;
            }
        } else {
            pr_err("SNAPSHOT: No backing file found\n");
            return;
        }
    }
    pr_info("SNAPSHOT: Mount event hooked for device: %s\n", devname);
   
    // Check if this device is registered for snapshotting
    if (find_device(devname) != NULL) {
        pr_info("SNAPSHOT: Snapshot activated for: %s\n", devname);
        //initalize snapshot directory
        create_snapshot_subdirectory(devname);
        pr_info("SNAPSHOT: Created subdir for: %s\n", devname);
    } else {
        pr_info("SNAPSHOT: Snapshot didn't find any device for: %s\n", devname);
    }
}
#endif

/*
 * kretprobe handler for mount_bdev function
 * This gets called after mount_bdev completes and can inspect its return value
 */
static int mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs) {
    struct dentry *dentry;
    pr_info("SNAPSHOT: mount_bdev_handler called!\n");

    // Get return value from registers
    void *ret = (void *)regs_return_value(regs);

    if (IS_ERR_OR_NULL(ret)) {
        pr_err("SNAPSHOT: mount_bdev returned error or NULL\n");
        return -1;
    }

    // Get dentry from return value
    dentry = dget((struct dentry *)ret);
    if (!dentry) {
        pr_err("SNAPSHOT: dget returned NULL\n");
        return -1;
    }

    if (IS_ERR(dentry)) {
        pr_err("SNAPSHOT: Failed to get dentry\n");
        return -1;
    }
    
    // Debug info: Print filesystem type if available
    if (dentry->d_sb && dentry->d_sb->s_type && dentry->d_sb->s_type->name) {
        pr_info("SNAPSHOT: filesystem type: %s\n", dentry->d_sb->s_type->name);
    }
    
    // Debug info: Print block device info if available
    if (dentry->d_sb && dentry->d_sb->s_bdev) {
        pr_info("SNAPSHOT: block device: %s\n", dentry->d_sb->s_bdev->bd_disk->disk_name);
    }
    
    // Handle the mount event if we have a block device
    if (dentry->d_sb->s_bdev) {
        struct block_device *bdev = dentry->d_sb->s_bdev;
        handle_mount_event(bdev);
        return 0;
    } else {
        pr_err("SNAPSHOT: No block device found\n");
        return -1;
    }
    return 0;
}

// kretprobe structure for hooking mount_bdev function
static struct kretprobe mount_bdev_kp = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_handler, // Function to call after mount_bdev returns
};

/*
 * Install the mount hook by registering the kretprobe
 */
int install_mount_hook(void) {
    return register_kretprobe(&mount_bdev_kp);
}

/*
 * Remove the mount hook by unregistering the kretprobe
 */
void remove_mount_hook(void) {
    unregister_kretprobe(&mount_bdev_kp);
}

/*
 * Register a new device for snapshotting
 * @devname: Name of the device to register
 * Returns 0 on success, negative error code on failure
 */
int register_device(const char *devname) {
    snapshot_device *new_dev;

    // Check if device already exists
    if (find_device(devname))
        return -EEXIST;

    // Allocate memory for new device
    new_dev = kmalloc(sizeof(*new_dev), GFP_KERNEL);
    if (!new_dev)
        return -ENOMEM;

    // Initialize device structure
    strscpy(new_dev->name, devname, MAX_DEV_LEN);
    new_dev->snapshot_active = true;
    INIT_LIST_HEAD(&new_dev->list);

    // Add to global list with lock protection
    spin_lock(&devices_lock);
    list_add_tail_rcu(&new_dev->list, &active_devices);
    spin_unlock(&devices_lock);

    pr_info("SNAPSHOT: Device %s registered\n", new_dev->name);
    return 0;
}

/*
 * Unregister a device from snapshotting
 * @devname: Name of the device to unregister
 * Returns 0 on success, -ENODEV if device not found
 */
int unregister_device(const char *devname) {
    snapshot_device *dev = NULL;

    spin_lock(&devices_lock);
    // Search for device in list
    list_for_each_entry(dev, &active_devices, list) {
        if (strcmp(dev->name, devname) == 0) {
            // Remove device if found
            list_del_rcu(&dev->list);
            spin_unlock(&devices_lock);
            synchronize_rcu(); // Wait for any RCU readers
            kfree(dev);
            pr_info("SNAPSHOT: Device %s unregistered\n", devname);
            return 0;
        }
    }
    spin_unlock(&devices_lock);
    return -ENODEV;
}

/*
 * Find a registered device by name
 * @devname: Name of the device to find
 * Returns pointer to device if found, NULL otherwise
 * Uses RCU for safe lockless read access
 */
snapshot_device *find_device(const char *devname) {
    snapshot_device *dev;

    rcu_read_lock();
    list_for_each_entry_rcu(dev, &active_devices, list) {
        if (strcmp(dev->name, devname) == 0) {
            rcu_read_unlock();
            return dev;
        }
    }
    rcu_read_unlock();
    return NULL;
}