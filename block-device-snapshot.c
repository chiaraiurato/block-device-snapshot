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
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Iurato Chiara <chiara.iurat@gmail.com>");
MODULE_DESCRIPTION("block device snapshot");



#define MODNAME "BLOCKDEVSNAP"


unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);


unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0,0x0};//please set to sys_got_sleep and sys_awake at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};


#define AUDIT if(1)

// #define NO (0)
// #define YES (NO+1)

// static int enable_rec_on = 0;// this can be configured at run time via the sys file system - 1 meas any sleeping thread is freezed
// module_param(enable_rec_on,int,0660);

// static int enable_rec_off = 0;// this can be configured at run time via the sys file system - 1 meas any sleeping thread is freezed
// module_param(enable_rec_off,int,0660);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _activate_snapshot, int, unused){
#else
asmlinkage long sys_activate_snapshot(int unused){
#endif

        AUDIT
        printk("%s: sys_active_snapshot called from thread %d\n",MODNAME,current->pid);
        return 0;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _deactivate_snapshot, int, unused){
#else
asmlinkage long sys_deactivate_snapshot(int unused){
#endif
	AUDIT
        printk("%s: sys_deactivate_snapshot called from thread %d\n",MODNAME,current->pid);
        return 0;

}

int init_module(void) {

        int i;
        int ret;

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