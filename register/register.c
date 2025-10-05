#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/loop.h> 
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/major.h> 
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/limits.h>
#include "include/register.h"
#include "../snapshot/include/snapshot.h"

/* Global list to track active snapshot devices */
static LIST_HEAD(active_devices);
static DEFINE_SPINLOCK(devices_lock);

/**
 * ensure_snapshot_root_directory - Create /snapshot if it doesn't exist
 */
int ensure_snapshot_root_directory(void)
{
    struct path root_path;
    struct dentry *dentry;
    int err;

    /* Check if directory already exists */
    err = kern_path("/snapshot", LOOKUP_DIRECTORY, &root_path);
    if (!err) {
        path_put(&root_path);
        return 0;
    }

    /* Create the directory */
    dentry = kern_path_create(AT_FDCWD, "/snapshot", &root_path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry)) {
        pr_err("SNAPSHOT: Failed to prepare /snapshot path: %ld\n", PTR_ERR(dentry));
        return PTR_ERR(dentry);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    err = vfs_mkdir(mnt_idmap(root_path.mnt), d_inode(root_path.dentry), dentry, 0755);
#else
    err = vfs_mkdir(d_inode(root_path.dentry), dentry, 0755);
#endif

    if (err && err != -EEXIST) {
        pr_err("SNAPSHOT: Failed to create /snapshot: %d\n", err);
    } else {
        pr_info("SNAPSHOT: /snapshot directory ready\n");
        err = 0;
    }

    done_path_create(&root_path, dentry);
    return err;
}

/**
 * validate_user_path - Validate and normalize user-provided path
 * @userspec: User-provided path (e.g., /dev/loop0 or image file)
 * @out: Output buffer for path
 * @len: Length of output buffer
 */
int validate_user_path(const char *userspec, char *out, size_t len) {
    struct path p;
    char *tmp;
    int err;

    if (!userspec || !out || len == 0) {
        pr_err("SNAPSHOT: Invalid parameters\n");
        return -EINVAL;
    }

    err = kern_path(userspec, LOOKUP_FOLLOW, &p);
    if (err) {
        pr_err("SNAPSHOT: kern_path failed for '%s': %d\n", userspec, err);
        return err;
    }

    if (!p.dentry || !d_inode(p.dentry)) {
        pr_err("SNAPSHOT: Invalid path structure\n");
        path_put(&p);
        return -EINVAL;
    }

    /* Get canonical path - works for both block devices and regular files */
    tmp = d_path(&p, out, len);
    path_put(&p);
    
    if (IS_ERR(tmp)) {
        pr_err("SNAPSHOT: d_path failed: %ld\n", PTR_ERR(tmp));
        return PTR_ERR(tmp);
    }
    
    /* Compact path to start of buffer if necessary */
    if (tmp != out)
        memmove(out, tmp, strlen(tmp) + 1);

    return 0;
}
/**
 * get_loop_backing_file - Extract backing file path from loop device bdev
 * @bdev: Block device
 * @out: Output buffer for backing file path
 * @len: Length of output buffer
 */
int get_loop_backing_file(struct block_device *bdev, char *out, size_t len) {
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
        struct gendisk *disk;
        struct loop_device *lo;
        char *tmp;
        
        if (!bdev || !out) {
            return -EINVAL;
        }
        
        disk = bdev->bd_disk;
        if (!disk) {
            return -EINVAL;
        }
        
        /* Check if this is a loop device */
        if (disk->major != LOOP_MAJOR) {
            return -ENOTTY;  /* Not a loop device */
        }
        
        lo = disk->private_data;
        if (!lo || !lo->lo_backing_file) {
            return -ENOENT;  /* No backing file */
        }
        
        /* Extract backing file path */
        tmp = d_path(&lo->lo_backing_file->f_path, out, len);
        if (IS_ERR(tmp)) {
            return PTR_ERR(tmp);
        }
        
        if (tmp != out)
            memmove(out, tmp, strlen(tmp) + 1);
        
        return 0;
    #else
        return -ENOTSUP;
    #endif
    }
    
/**
 * get_device_name_from_bdev - Get /dev/xxx name from bdev
 * @bdev: Block device
 * @out: Output buffer for device name
 * @len: Length of output buffer
 */
int get_device_name_from_bdev(struct block_device *bdev, char *out, size_t len) {
    struct gendisk *disk;
    
    if (!bdev || !out) {
        return -EINVAL;
    }
    
    disk = bdev->bd_disk;
    if (!disk) {
        return -EINVAL;
    }
    
    snprintf(out, len, "/dev/%s", disk->disk_name);
    return 0;
}

/**
 * find_device_for_bdev - Try to find device using bdev
 */
snapshot_device *find_device_for_bdev(struct block_device *bdev)
{
    struct inode *inode;
    snapshot_device *sdev = NULL;
    char *key = kmalloc(PATH_MAX, GFP_KERNEL);
    int ret;

    if (!bdev)
        return NULL;

    /* Block device */
    if (MAJOR(bdev->bd_dev) != LOOP_MAJOR) {
        ret = get_device_name_from_bdev(bdev, key, PATH_MAX);
        if (ret == 0)
            sdev = find_device(key);
    }
    /* Loop device */
    else {
        ret = get_loop_backing_file(bdev, key, PATH_MAX);
        if (ret == 0)
            sdev = find_device(key);
    }

    return sdev;
}
/**
 * handle_mount_event - Process a mount event
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
void handle_mount_event(struct block_device *bd) {
    pr_warn("SNAPSHOT: Mount events not supported for kernel < 5.16\n");
}
#else
void handle_mount_event(struct block_device *bdev) {
    snapshot_device *sdev;
    u64 timestamp;
    int ret;

    if (!bdev) {
        pr_warn("SNAPSHOT: Device not yet mounted\n");
        return;  
    }

    sdev = find_device_for_bdev(bdev);
    if (!sdev) {
        pr_debug("SNAPSHOT: No registered device found for this mount\n");
        return;
    }

    if (!sdev->snapshot_active) {
        pr_info("SNAPSHOT: Device %s registered but snapshot inactive\n", sdev->name);
        return;
    }

    pr_info("SNAPSHOT: Mount event matched device: %s\n", sdev->name);

    /* Set bdev if not already set */
    spin_lock(&sdev->lock);
    if (!sdev->bdev) {
        sdev->bdev = bdev;
        pr_info("SNAPSHOT: Attached bdev to device %s\n", sdev->name);
    }
    spin_unlock(&sdev->lock);

    /* Start a new session */
    ret = start_session_for_bdev(sdev, bdev, &timestamp);
    if (ret) {
        pr_err("SNAPSHOT: Failed to start session: %d\n", ret);
        return;
    }

    pr_info("SNAPSHOT: Session queued for device: %s\n", sdev->name);
}

#endif

/**
 * mount_bdev_handler - Kretprobe handler for mount_bdev
 * 
 * Extract the block device and queue work to workqueue.
 */
static int mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs)
{
    struct dentry *dentry;
    void *ret;
    
    /* Get return value (should be dentry) */
    ret = (void *)regs_return_value(regs);
    
    if (IS_ERR_OR_NULL(ret)) {
        /* Mount failed, nothing to do */
        return 0;
    }
    
    dentry = (struct dentry *)ret;
    
    /* Validate dentry structure */
    if (!dentry->d_sb) {
        pr_err("SNAPSHOT: Invalid dentry - no superblock\n");
        return 0;
    }
    
    /* Check if this mount has a block device */
    if (!dentry->d_sb->s_bdev) {
        /* Not a block device mount (e.g., tmpfs, proc) */
        return 0;
    }
    
    /* Log mount info */
    if (dentry->d_sb->s_type && dentry->d_sb->s_type->name) {
        pr_debug("SNAPSHOT: Mount detected - fs: %s, dev: %s\n",
                dentry->d_sb->s_type->name,
                dentry->d_sb->s_bdev->bd_disk->disk_name);
    }
    
    /* Handle the mount event (will queue to workqueue) */
    handle_mount_event(dentry->d_sb->s_bdev);
    
    return 0;
}

/* Kretprobe structure for hooking mount_bdev */
static struct kretprobe mount_bdev_kp = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_handler,
    .maxactive = 20, /* Handle up to 20 concurrent mounts */
};

/**
 * install_mount_hook - Install the mount event hook
 */
int install_mount_hook(void)
{
    int ret;
    
    ret = register_kretprobe(&mount_bdev_kp);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to register kretprobe on mount: %d\n", ret);
        return ret;
    }
    return 0;
}

/**
 * remove_mount_hook - Remove the mount event hook
 */
void remove_mount_hook(void)
{
    unregister_kretprobe(&mount_bdev_kp);
    pr_info("SNAPSHOT: Mount hook removed (missed %d probes)\n", 
            mount_bdev_kp.nmissed);
}

/**
 * register_device - Register a new device for snapshotting
 * @devname: User provided device name
 */
int register_device(const char *devname) {
    int ret;
    char *key = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!key)
        return -ENOMEM;
    snapshot_device *new_dev;
    
    pr_info("SNAPSHOT: Registering device: %s\n", devname);

    /* Validate user string */
    ret = validate_user_path(devname, key, PATH_MAX);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to validate path '%s': %d\n", devname, ret);
        return -EINVAL;
    }

    /* Check if already registered */
    if (find_device(key)) {
        pr_info("SNAPSHOT: Device %s already registered\n", key);
        return -EEXIST;
    }

    /* Allocate device structure */
    new_dev = kzalloc(sizeof(*new_dev), GFP_KERNEL);
    if (!new_dev) {
        return -ENOMEM;
    }

    /* Initialize device - store the key provided from user */
    strscpy(new_dev->name, key, MAX_DEV_LEN);
    new_dev->snapshot_active = true;
    new_dev->bdev = NULL;
    INIT_LIST_HEAD(&new_dev->list);
    INIT_LIST_HEAD(&new_dev->sessions);
    spin_lock_init(&new_dev->lock);

    /* Add to global list */
    spin_lock(&devices_lock);
    list_add_tail_rcu(&new_dev->list, &active_devices);
    spin_unlock(&devices_lock);
    pr_info("SNAPSHOT: Device registered as %s\n", key);
    kfree(key);
    return 0;
}


/**
 * unregister_device - Unregister a device from snapshotting
 * @devname: User provided device name
 */
int unregister_device(const char *devname) {
    snapshot_device *dev;
    char *key = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!key)
        return -ENOMEM;
    int ret;

    /* Normalize the path to match registration */
    ret = validate_user_path(devname, key, PATH_MAX);
    if (ret < 0) {
        return -EINVAL;
    }

    spin_lock(&devices_lock);
    list_for_each_entry(dev, &active_devices, list) {
        if (strcmp(dev->name, key) == 0) {
            dev->snapshot_active = false;
            list_del_rcu(&dev->list);
            spin_unlock(&devices_lock);

            stop_sessions_for_bdev(dev);
            synchronize_rcu();
            kfree(dev);
            
            pr_info("SNAPSHOT: Device unregistered: %s\n", key);
            return 0;
        }
    }
    spin_unlock(&devices_lock);
    pr_warn("SNAPSHOT: Device not found: %s\n", key);
    kfree(key);
    return -ENODEV;
}

/**
 * find_device - Find a registered device by its key
 * @devname: Key to search for
 */
snapshot_device *find_device(const char *devname)
{
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

struct snapshot_device *find_device_by_bdev(struct block_device *bdev)
{
    struct snapshot_device *dev;
    rcu_read_lock();
    list_for_each_entry_rcu(dev, &active_devices, list) {
        if (READ_ONCE(dev->bdev) == bdev) {
            rcu_read_unlock();
            return dev;
        }
    }
    rcu_read_unlock();
    return NULL;
}