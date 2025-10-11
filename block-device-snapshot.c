/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @file block-device-snapshot.c 
* @brief This is the main source for the Linux Kernel Module which implements
*        a snapshot service for block devices hosting file systems
*
* @author Iurato Chiara
*
* @date September, 2025
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include "lib/include/scth.h"
#include "utils/include/auth.h"
#include "register/include/register.h"
#include "snapshot/include/snapshot.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Iurato Chiara <chiara.iurat@gmail.com>");
MODULE_DESCRIPTION("block device snapshot");

#define MODNAME "SNAPSHOT"

static struct salted_hash *password_digest;

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0);


unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0,0x0}; //please set to sys_activate_snapshot and sys_deactivate_snapshot at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};


#define AUDIT if(1)

#define CURRENT_EUID current->cred->euid.val
#define MAX_DEV_LEN 256  /* Maximum device name length */
#define MAX_PWD_LEN 128  /* Maximum password length */

static char the_snapshot_secret[HASH_LEN]; 
module_param_string(the_snapshot_secret, the_snapshot_secret, HASH_LEN, 0);
MODULE_PARM_DESC(the_snapshot_secret, "Password used for authentication");

static bool use_bio_layer = true;
module_param_named(use_bio_layer, use_bio_layer, bool, 0644);
MODULE_PARM_DESC(use_bio_layer, "Use BIO-layer kprobe (true) or buffer-cache kprobes (false)");

static int handle_snapshot_operation(const char __user *devname, 
                                     const char __user *passwd,
                                     bool activate)
{
    AUDIT
    printk("%s: sys_%s_snapshot called from thread %d\n", 
          MODNAME, activate ? "activate" : "deactivate", current->pid);
    
    int ret;
    char *k_devname = NULL;
    char *k_passwd = NULL;
    size_t devname_len, passwd_len;

    /* Common validation logic */
    if (!devname || !passwd) {
        pr_warn("%s: Null pointer passed\n", MODNAME);
        return -EINVAL;
    }

    devname_len = strnlen_user(devname, MAX_DEV_LEN) + 1;
    passwd_len = strnlen_user(passwd, MAX_PWD_LEN) + 1;

    if (devname_len > MAX_DEV_LEN || passwd_len > MAX_PWD_LEN) {
        pr_warn("%s: Input string too long\n", MODNAME);
        return -ENAMETOOLONG;
    }

    k_devname = kmalloc(devname_len, GFP_KERNEL);
    k_passwd = kmalloc(passwd_len, GFP_KERNEL);
    if (!k_devname || !k_passwd) {
        ret = -ENOMEM;
        pr_err("%s: Memory allocation failed\n", MODNAME);
        goto cleanup;
    }

    if (copy_from_user(k_devname, devname, devname_len) || 
        copy_from_user(k_passwd, passwd, passwd_len)) {
        ret = -EFAULT;
        pr_err("%s: Failed to copy from userspace\n", MODNAME);
        goto cleanup;
    }

    k_devname[devname_len - 1] = '\0';
    k_passwd[passwd_len - 1] = '\0';

    /* Common auth checks */
    if (CURRENT_EUID != 0) {
        ret = -EPERM;
        pr_notice("%s: Non-root access denied (PID: %d)\n",
                MODNAME, current->pid);
        goto cleanup;
    }

    if (authenticate(k_passwd, password_digest) != 0) {
        ret = -EACCES;
        pr_notice("%s: Invalid credentials for device %s\n",
                MODNAME, k_devname);
        goto cleanup;
    }
    /* Init /snapshot dir */
    int err = ensure_snapshot_root_directory();
    if (err) {
        pr_err("SNAPSHOT: Unable to check if /snapshot exists\n");
        goto cleanup;
    }
    /* Operation-specific logic */
    if (activate) {
        ret = register_device(k_devname);
        if (ret == -EEXIST) {
             printk("%s: Device %s already registered\n", MODNAME, k_devname);
             ret = 0;
         }
        
    } else {
        ret = unregister_device(k_devname);
        if (ret == -ENODEV) {
            printk("%s: Device %s not found\n", MODNAME, k_devname);
            ret = 0;
        }
    }
    
cleanup:
    kfree(k_devname);
    kfree(k_passwd);
    return ret;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _activate_snapshot, const char  __user *, devname,const char __user *, passwd){
#else
asmlinkage long sys_activate_snapshot(const char  __user *devname, const char __user *passwd){
#endif

        return handle_snapshot_operation(devname, passwd, true);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, const char  __user *, devname,const char __user *, passwd){
#else
asmlinkage long sys_deactivate_snapshot(const char  __user *devname, const char __user *passwd){
#endif
        return handle_snapshot_operation(devname, passwd, false);

}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_activate_snapshot = (unsigned long) __x64_sys_activate_snapshot;       
long sys_deactivate_snapshot = (unsigned long) __x64_sys_deactivate_snapshot;       
#else
#endif


int init_module(void) {

        int i;
        int ret;
        printk("%s: Initializing module...\n", MODNAME);
        password_digest = kmalloc(sizeof(struct salted_hash), GFP_KERNEL);
        if(!password_digest){
                pr_err("%s: memory allocation failed for storing password digest\n",MODNAME);
                return -ENOMEM;
        }
        memset(password_digest, 0, sizeof(struct salted_hash)); // Initialize to zero
        // Compute hash of the input password
        
        ret = compute_salted_hash(the_snapshot_secret, strlen(the_snapshot_secret), password_digest);
        if (ret < 0) {
                printk("%s: Error computing password hash\n", MODNAME);
                kfree(password_digest);
                password_digest = NULL;
                return -1;
        }
        printk("%s: Password hash computed successfully with return code: %d\n", MODNAME, ret);

        //To avoid leak of pwd just wipe it from memory
        memzero_explicit(the_snapshot_secret, strlen(the_snapshot_secret));
        
        if (the_syscall_table == 0x0){
           printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
           return -1;
        }

        AUDIT{
           printk("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
           printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
        }

        new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
        new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;

        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);


        if (ret != HACKED_ENTRIES){
                printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret);
                return -1;
        }

        unprotect_memory();

        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        printk("all new system-calls correctly installed on sys-call table\n");

        if (use_bio_layer) {
            ret = install_bio_kprobe();
            if (ret < 0) {
                printk("%s: BIO kprobe install error\n", MODNAME);
                return ret;
            }
            printk("%s: BIO kprobe installed\n", MODNAME);
            ret = install_get_tree_bdev_hook();
            if (ret < 0) {
                printk("%s: get_tree_bdev kprobe install error\n", MODNAME);
                return ret;
            }
            printk("%s: BIO kprobe installed\n", MODNAME);
        } else {
            ret = install_mount_hook();
            if (ret < 0) {
                printk("%s: Error while hooking mount_bdev()\n", MODNAME);
                return ret;
            }
            printk("%s: register mount_bdev() hook successfully\n", MODNAME);

            ret = install_write_hook();
            if (ret < 0) { printk("%s: write hook err\n", MODNAME); return ret; }
            printk("%s: register write_dirty_buffer() hook successfully\n", MODNAME);
        
            ret = install_read_hook();
            if (ret < 0) { printk("%s: read hook err\n", MODNAME); return ret; }
            printk("%s: register __bread_gfp() hook successfully\n", MODNAME);

            ret = install_unmount_hook();
            if (ret < 0) {
                printk("%s: Error while hooking kill_superblock\n", MODNAME);
                return ret;
            }
            printk("%s: register kill_super_block() hook successfully\n", MODNAME);
        }
        
        /* create workqueue for mounting sdev*/
        snapshot_init();

        return 0;

}


void cleanup_module(void) {
        // snapshot_device *dev, *tmp;
        printk("%s: shutting down\n",MODNAME);
        //remove all hooks
        // TODO : refactor to remove all hooks in a single function
        if (use_bio_layer) {
            remove_bio_kprobe();
            remove_get_tree_bdev_hook();
        } else {
            remove_mount_hook();
            remove_unmount_hook();
            remove_write_hook();
            remove_read_hook();
        }

        unprotect_memory();
        for(int i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        pr_info("%s: sys-call table restored to its original content\n",MODNAME);

        if (password_digest) {
            kfree(password_digest);
            password_digest = NULL;
        }

        snapshot_exit();   
}