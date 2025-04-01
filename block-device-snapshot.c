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
* @date March, 2025
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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Iurato Chiara <chiara.iurat@gmail.com>");
MODULE_DESCRIPTION("block device snapshot");



#define MODNAME "SNAPSHOT"


typedef struct _bdev_snapshot {
        spinlock_t lock;  
        char *password_digest;     
} bdev_snapshot;

static bdev_snapshot snapshot;

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0);


unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0,0x0}; //please set to sys_activate_snapshot and sys_deactivate_snapshot at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};


#define AUDIT if(1)

#define CURRENT_EUID current->cred->euid.val
#define HASH_LEN 32
#define MAX_DEV_LEN 256  /* Maximum device name length */
#define MAX_PWD_LEN 128  /* Maximum password length */

unsigned char the_snaphot_secret[HASH_LEN]; 
module_param_string(the_snapshot_secret, the_snaphot_secret, 32, 0);
MODULE_PARM_DESC(the_snapshot_secret, "Password used for authentication");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _activate_snapshot, const char  __user *, devname,const char __user *, passwd){
#else
asmlinkage long sys_activate_snapshot(const char  __user *devname, const char __user *passwd){
#endif

        AUDIT
        printk("%s: sys_active_snapshot called from thread %d\n",MODNAME,current->pid);
        int ret;
        char *k_devname = NULL;
        char *k_passwd = NULL;
        size_t devname_len, passwd_len;

        /* Basic sanity check */
        if (!devname || !passwd) {
                pr_warn("%s: Null pointer passed\n", MODNAME);
                return -EINVAL;
        }

        /* Calculate string lengths safely */
        devname_len = strnlen_user(devname, MAX_DEV_LEN) + 1;
        passwd_len = strnlen_user(passwd, MAX_PWD_LEN) + 1;

        /* Check length validity */
        if (devname_len > MAX_DEV_LEN || passwd_len > MAX_PWD_LEN) {
                pr_warn("%s: Input string too long\n", MODNAME);
                return -ENAMETOOLONG;
        }

        /* Allocate kernel buffers */
        k_devname = kmalloc(devname_len, GFP_KERNEL);
        k_passwd = kmalloc(passwd_len, GFP_KERNEL);
        if (!k_devname || !k_passwd) {
                ret = -ENOMEM;
                pr_err("%s: Memory allocation failed\n", MODNAME);
                goto cleanup;
        }


        /* Copy data from userspace */
        if (copy_from_user(k_devname, devname, devname_len) || 
                copy_from_user(k_passwd, passwd, passwd_len)) {
                ret = -EFAULT;
                pr_err("%s: Failed to copy from userspace\n", MODNAME);
                goto cleanup;
        }

        /* Ensure null termination */
        k_devname[devname_len - 1] = '\0';
        k_passwd[passwd_len - 1] = '\0';

       /* Authorization check */
        if (CURRENT_EUID != 0) {
                ret = -EPERM;
                pr_notice("%s: Non-root access denied (PID: %d)\n",
                        MODNAME, current->pid);
                goto unlock;
        }

        /* Authentication check */
        if (authenticate(k_passwd, snapshot.password_digest) != 0) {
                ret = -EACCES;
                pr_notice("%s: Invalid credentials for device %s\n",
                        MODNAME, k_devname);
                goto unlock;
        }

        // /* Main operation */
        // ret = activate_device_snapshot(k_devname);
        // if (ret < 0) {
        //         pr_err("%s: Snapshot activation failed for %s (err: %d)\n",
        //         MODNAME, k_devname, ret);
        // } else {
        //         pr_info("%s: Snapshot activated for %s\n",
        //         MODNAME, k_devname);
        // }
        printk("%s: Snapshot activation for %s successful\n", MODNAME, k_devname);
unlock:
        spin_unlock(&snapshot.lock);
cleanup:
        kfree(k_devname);
        kfree(k_passwd);
        return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, const char  __user *, devname,const char __user *, passwd){
#else
asmlinkage long sys_deactivate_snapshot(const char  __user *devname, const char __user *passwd){
#endif
	AUDIT
        printk("%s: sys_deactivate_snapshot called from thread %d\n",MODNAME,current->pid);

        spin_lock(&snapshot.lock);
        
        if(CURRENT_EUID != 0 ){
                printk("%s: %s\n",MODNAME, "Permission denied");
        // }else if (authenticate(passwd, snapshot.password_digest) != 0)
        // {
        //         printk("%s: %s\n",MODNAME, "Authentication failed");
        }
        printk("%s: %s\n",MODNAME, "Deactivating snapshot successfully");
        spin_unlock(&snapshot.lock);
        return 0;

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
        snapshot.password_digest = kmalloc(32, GFP_KERNEL);
        if(!snapshot.password_digest){
                pr_err("%s: memory allocation failed for storing password digest\n",MODNAME);
                return -ENOMEM;
        }
        // Compute hash of the input password
        
        ret = compute_hash_password(the_snaphot_secret, strlen(the_snaphot_secret), snapshot.password_digest);
        if (ret < 0) {
        printk("%s: Error computing password hash\n", MODNAME);
        return -1;
        }

        printk("%s: Password hash computed successfully with return code: %d\n", MODNAME, ret);
       
        printk("%s: Password hash: %s ", MODNAME, snapshot.password_digest);
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

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

        return 0;

}


void cleanup_module(void) {

        int i;

        printk("%s: shutting down\n",MODNAME);

        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);

}