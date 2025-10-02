#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/timekeeping.h>
#include <linux/version.h>
#include <linux/limits.h>
#include "include/snapshot.h"
#include "../register/include/register.h"

/* Workqueue for handling mount events */
static struct workqueue_struct *snapshot_wq;

/**
 * store_key_from_bdev - Extract canonical key from block device
 * 
 * For loop devices: returns backing file path
 * For other devices: returns /dev/xxx path
 */
void store_key_from_bdev(struct block_device *bdev, char *out, size_t len)
{
    struct gendisk *disk;
    
    if (!bdev || !out) {
        pr_err("SNAPSHOT: Invalid parameters to store_key_from_bdev\n");
        return;
    }

    disk = bdev->bd_disk;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
    /* Check if this is a loop device */
    if (disk->major == LOOP_MAJOR) {
        struct loop_device *lo = disk->private_data;
        
        if (lo && lo->lo_backing_file) {
            /* Get the backing file path */
            char *tmp;
            struct path *path = &lo->lo_backing_file->f_path;
            
            tmp = d_path(path, out, len);
            if (IS_ERR(tmp)) {
                pr_err("SNAPSHOT: Failed to get loop backing file path\n");
                snprintf(out, len, "/dev/%s", disk->disk_name);
            } else if (tmp != out) {
                memmove(out, tmp, strlen(tmp) + 1);
            }
            pr_info("SNAPSHOT: Loop device key: %s\n", out);
            return;
        }
    }
#endif

    /* For non-loop devices or when backing file is unavailable */
    pr_info("SNAPSHOT: fallback store_key_from_bdev for device: %s\n", bdev->bd_disk->disk_name);
    strscpy(out, bdev->bd_disk->disk_name, len); 
}

/**
 * create_session - Create a new snapshot session
 */
snapshot_session *create_session(snapshot_device *sdev, u64 timestamp)
{
    snapshot_session *session;
    
    session = kzalloc(sizeof(*session), GFP_KERNEL);
    if (!session)
        return NULL;
    
    session->timestamp = timestamp;
    session->sdev = sdev;
    session->snapshot_dir[0] = '\0';
    
    mutex_init(&session->dir_mtx);
    xa_init(&session->saved_blocks);
    INIT_LIST_HEAD(&session->list);
    atomic_set(&session->ref_count, 1);
    
    pr_info("SNAPSHOT: Created session with timestamp %llu\n", timestamp);
    return session;
}

/**
 * destroy_session - Cleanup a snapshot session
 */
void destroy_session(snapshot_session *session)
{
    struct block_data *bdata;
    unsigned long index;
    
    if (!session)
        return;
    
    pr_info("SNAPSHOT: Destroying session %llu\n", session->timestamp);
    
    /* Free all saved blocks */
    xa_for_each(&session->saved_blocks, index, bdata) {
        if (bdata) {
            kfree(bdata->data);
            kfree(bdata);
        }
    }
    
    xa_destroy(&session->saved_blocks);
    mutex_destroy(&session->dir_mtx);
    kfree(session);
}

/**
 * save_block_to_session - Save a block's original content
 * 
 * This is called BEFORE a write operation to preserve the original data
 */
int save_block_to_session(snapshot_session *session, sector_t sector,
                          const void *data, size_t size)
{
    struct block_data *bdata;
    int ret;
    
    /* Check if block is already saved (copy-on-write semantics) */
    if (xa_load(&session->saved_blocks, sector)) {
        return 0; /* Already saved, nothing to do */
    }
    
    /* Allocate block data structure */
    bdata = kzalloc(sizeof(*bdata), GFP_KERNEL);
    if (!bdata)
        return -ENOMEM;
    
    /* Allocate and copy block content */
    bdata->data = kmalloc(size, GFP_KERNEL);
    if (!bdata->data) {
        kfree(bdata);
        return -ENOMEM;
    }
    
    memcpy(bdata->data, data, size);
    bdata->sector = sector;
    bdata->size = size;
    
    /* Store in XArray */
    ret = xa_err(xa_store(&session->saved_blocks, sector, bdata, GFP_KERNEL));
    if (ret) {
        kfree(bdata->data);
        kfree(bdata);
        pr_err("SNAPSHOT: Failed to store block %llu: %d\n", 
               (unsigned long long)sector, ret);
        return ret;
    }
    
    pr_debug("SNAPSHOT: Saved block %llu (size: %zu) for session %llu\n",
             (unsigned long long)sector, size, session->timestamp);
    
    return 0;
}

/**
 * is_block_saved - Check if a block has been saved in this session
 */
bool is_block_saved(snapshot_session *session, sector_t sector)
{
    return xa_load(&session->saved_blocks, sector) != NULL;
}

/**
 * create_snapshot_subdirectory - Create timestamped directory for session
 * 
 * Called from workqueue context - safe to use blocking operations
 */
static int create_snapshot_subdirectory(snapshot_session *session, 
                                       const char *raw_devname)
{
    char basename_only[MAX_DEV_LEN];
    struct path parent_path;
    struct dentry *dentry;
    struct timespec64 ts;
    const char *base;
    size_t i;
    int err;

    char *path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path) return -ENOMEM;
    
    /* Sanitize device name (extract basename) */
    base = strrchr(raw_devname, '/');
    base = base ? base + 1 : raw_devname;
    
    for (i = 0; base[i] && i < sizeof(basename_only) - 1; i++) {
        char c = base[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            c = '_';
        basename_only[i] = c;
    }
    basename_only[i] = '\0';
    
    /* Avoid problematic names */
    if (basename_only[0] == '\0' || 
        (basename_only[0] == '.' && 
         (basename_only[1] == '\0' || 
          (basename_only[1] == '.' && basename_only[2] == '\0')))) {
        strscpy(basename_only, "dev", sizeof(basename_only));
    }
    
    /* Create path: /snapshot/devname_timestamp */
    ktime_get_real_ts64(&ts);
    snprintf(path, PATH_MAX, "/snapshot/%s_%lld",
             basename_only, (long long)ts.tv_sec);
    
    pr_info("SNAPSHOT: Creating directory: %s\n", path);
    
    /* Create the directory */
    dentry = kern_path_create(AT_FDCWD, path, &parent_path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry)) {
        pr_err("SNAPSHOT: kern_path_create failed: %ld\n", PTR_ERR(dentry));
        return PTR_ERR(dentry);
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    err = vfs_mkdir(mnt_idmap(parent_path.mnt), 
                    d_inode(parent_path.dentry), dentry, 0755);
#else
    err = vfs_mkdir(d_inode(parent_path.dentry), dentry, 0755);
#endif
    
    if (err && err != -EEXIST) {
        pr_err("SNAPSHOT: mkdir failed: %d\n", err);
    } else {
        /* Store the path in the session */
        mutex_lock(&session->dir_mtx);
        strscpy(session->snapshot_dir, path, PATH_MAX);
        mutex_unlock(&session->dir_mtx);
        
        pr_info("SNAPSHOT: Directory created: %s\n", path);
        err = 0;
    }
    
    done_path_create(&parent_path, dentry);
    kfree(path);
    return err;
}

/**
 * mount_work_handler - Workqueue handler for mount events
 * 
 */
static void mount_work_handler(struct work_struct *work)
{
    struct mount_work *mw = container_of(work, struct mount_work, work);
    snapshot_device *sdev;
    snapshot_session *session;
    u64 timestamp;
    int ret;
    
    store_key_from_bdev(mw->bdev, mw->key, sizeof(mw->key));
    pr_info("SNAPSHOT: Mount event for: %s\n", mw->key);
    /* Find the registered device */
    sdev = find_device(mw->key);
    if (!sdev) {
        pr_info("SNAPSHOT: No registered device for: %s\n", mw->key);
        goto cleanup;
    }
    
    /* Check if snapshot is active */
    if (!sdev->snapshot_active) {
        pr_info("SNAPSHOT: Snapshot not active for: %s\n", mw->key);
        goto cleanup;
    }
    
    /* Create new session */
    timestamp = ktime_get_real_ns();
    session = create_session(sdev, timestamp);
    if (!session) {
        pr_err("SNAPSHOT: Failed to create session for: %s\n", mw->key);
        goto cleanup;
    }
    
    /* Create snapshot subdirectory */
    ret = create_snapshot_subdirectory(session, mw->key);
    if (ret) {
        pr_err("SNAPSHOT: Failed to create directory: %d\n", ret);
        destroy_session(session);
        goto cleanup;
    }
    
    /* Add session to device */
    spin_lock(&sdev->lock);
    sdev->bdev = mw->bdev;
    list_add_tail(&session->list, &sdev->sessions);
    spin_unlock(&sdev->lock);
    
    pr_info("SNAPSHOT: Session %llu started for device: %s\n", 
            timestamp, mw->key);
    
cleanup:
    kfree(mw);
}

/**
 * start_session_for_bdev - Queue work to start a session
 * 
 * Called from kprobe handler
 */
int start_session_for_bdev(snapshot_device *sdev, struct block_device *bdev, 
                           u64 *out_ts)
{
    struct mount_work *mw;
    
    /* Allocate work structure */
    mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw)
        return -ENOMEM;
    
    /* Initialize work */
    INIT_WORK(&mw->work, mount_work_handler);
    mw->bdev = bdev;
    // store_key_from_bdev(bdev, mw->key, sizeof(mw->key));
    
    /* Queue the work */
    if (!queue_work(snapshot_wq, &mw->work)) {
        pr_err("SNAPSHOT: Failed to queue mount work\n");
        kfree(mw);
        return -EAGAIN;
    }
    
    if (out_ts)
        *out_ts = ktime_get_real_ns();
    
    return 0;
}

/**
 * stop_sessions_for_bdev - Stop all sessions for a device
 */
int stop_sessions_for_bdev(snapshot_device *sdev)
{
    snapshot_session *session, *tmp;
    
    if (!sdev)
        return -EINVAL;
    
    pr_info("SNAPSHOT: Stopping all sessions for: %s\n", sdev->name);
    
    spin_lock(&sdev->lock);
    
    /* Remove and destroy all sessions */
    list_for_each_entry_safe(session, tmp, &sdev->sessions, list) {
        list_del(&session->list);
        spin_unlock(&sdev->lock);
        
        destroy_session(session);
        
        spin_lock(&sdev->lock);
    }
    
    sdev->bdev = NULL;
    spin_unlock(&sdev->lock);
    
    return 0;
}

/**
 * snapshot_init - Initialize snapshot subsystem
 */
int snapshot_init(void)
{
    /* Create workqueue for handling mount events */
    snapshot_wq = alloc_workqueue("snapshot_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!snapshot_wq) {
        pr_err("SNAPSHOT: Failed to create workqueue\n");
        return -ENOMEM;
    }
    
    pr_info("SNAPSHOT: Subsystem initialized\n");
    return 0;
}

/**
 * snapshot_exit - Cleanup snapshot subsystem
 */
void snapshot_exit(void)
{
    if (snapshot_wq) {
        flush_workqueue(snapshot_wq);
        destroy_workqueue(snapshot_wq);
        snapshot_wq = NULL;
    }
    
    pr_info("SNAPSHOT: Subsystem cleaned up\n");
}