#include "include/register.h"
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/loop.h> 
#include <linux/kprobes.h>
#include <linux/buffer_head.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/major.h> 

static LIST_HEAD(active_devices);
static DEFINE_SPINLOCK(devices_lock);


#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
void handle_mount_event(struct block_device *bd) {
    pr_warn("SNAPSHOT: handle_mount_event not supported for kernel < 5.16\n");
}
#else
void handle_mount_event(struct block_device *bdev) {
    char devname[MAX_DEV_LEN] = {0};
    pr_info("SNAPSHOT: hooked mount_bdev\n");
    if (!bdev) return;

    if (MAJOR(bdev->bd_dev) != LOOP_MAJOR) {
        snprintf(devname, MAX_DEV_LEN, "%s", bdev->bd_disk->disk_name);
    } else {
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
   
    spin_lock(&devices_lock);
    if (find_device(devname)) {
        pr_info("SNAPSHOT: Snapshot activated for: %s\n", devname);
    }
    spin_unlock(&devices_lock);
}
#endif

static int mount_bdev_handler(struct kretprobe_instance *kp, struct pt_regs *regs) {
    struct dentry *dentry;
    char path_buf[PATH_MAX];
    pr_info("SNAPSHOT: mount_bdev_handler called!\n");

    void *ret = (void *)regs_return_value(regs);

    if (IS_ERR_OR_NULL(ret)) {
        pr_err("SNAPSHOT: mount_bdev returned error or NULL\n");
        return -1;
    }

    dentry = dget((struct dentry *)ret);
    if (!dentry) {
        pr_err("SNAPSHOT: dget returned NULL\n");
        return -1;
    }

    if (IS_ERR(dentry)){
        pr_err("SNAPSHOT: Failed to get dentry\n");
        return -1;
    }
    //Print the superblock’s filesystem type
    if (dentry->d_sb && dentry->d_sb->s_type && dentry->d_sb->s_type->name) {
        pr_info("SNAPSHOT: filesystem type: %s\n", dentry->d_sb->s_type->name);
    }
    //Print block device info
    if (dentry->d_sb && dentry->d_sb->s_bdev) {
        pr_info("SNAPSHOT: block device: %s\n", dentry->d_sb->s_bdev->bd_disk->disk_name);
    }
    
    // if (dentry->d_sb->s_bdev) {
    //     pr_info("SNAPSHOT: inside dentry called\n");
    //     struct block_device *bdev = dentry->d_sb->s_bdev; //dentry->superblock->blockdevice
    //     handle_mount_event(bdev);
    //     return 0;
    // }else{
    //     pr_err("SNAPSHOT: No block device found\n");
    //     return -1;
    // }
    return 0;
}

static struct kretprobe mount_bdev_kp = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_handler, //Tail hook handler
};


int install_mount_hook(void) {
    return register_kretprobe(&mount_bdev_kp);
}

void remove_mount_hook(void) {
    unregister_kretprobe(&mount_bdev_kp);
}


int register_device(const char *devname)
{
    snapshot_device *new_dev;
    
    if (find_device(devname))
        return -EEXIST;

    new_dev = kmalloc(sizeof(*new_dev), GFP_KERNEL);
    if (!new_dev)
        return -ENOMEM;

    strscpy(new_dev->name, devname, MAX_DEV_LEN);
    new_dev->snapshot_active = true;
    INIT_LIST_HEAD(&new_dev->list);

    spin_lock(&devices_lock);
    list_add_tail(&new_dev->list, &active_devices);
    spin_unlock(&devices_lock);

    pr_info("SNAPSHOT: Device %s registered\n", new_dev->name);
    return 0;
}

int unregister_device(const char *devname)
{
    snapshot_device *dev = find_device(devname);
    
    if (!dev)
        return -ENODEV;

    spin_lock(&devices_lock);
    list_del(&dev->list);
    spin_unlock(&devices_lock);
    pr_info("SNAPSHOT: Device %s unregistered\n", dev->name);
    kfree(dev);
    return 0;
}

snapshot_device *find_device(const char *devname)
{
    snapshot_device *dev;
    
    spin_lock(&devices_lock);
    list_for_each_entry(dev, &active_devices, list) {
        if (strcmp(dev->name, devname) == 0) {
            spin_unlock(&devices_lock);
            return dev;
        }
    }
    spin_unlock(&devices_lock);
    return NULL;
}  