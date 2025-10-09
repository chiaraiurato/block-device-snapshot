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
#include <linux/kprobes.h>
#include <linux/buffer_head.h>
#include "include/snapshot.h"
#include <linux/mnt_idmapping.h>
#include "../register/include/register.h"

#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/bitops.h>

static bool snap_trace = true;             /* master on/off */
module_param_named(trace, snap_trace, bool, 0644);
MODULE_PARM_DESC(trace, "Enable verbose snapshot tracing");

static int snap_dump_bytes = 64;           /* hexdump N bytes (0 = off) */
module_param_named(dump_bytes, snap_dump_bytes, int, 0644);
MODULE_PARM_DESC(dump_bytes, "Number of bytes to hex dump per block");

static unsigned int snap_log_every = 1;    /* log 1 of every N events */
module_param_named(log_every, snap_log_every, uint, 0644);
MODULE_PARM_DESC(log_every, "Log only 1 out of N write events");

static atomic64_t snap_evt_count = ATOMIC_INIT(0);

static void snap_dump_bh(const char *tag, struct buffer_head *bh,
                         sector_t sector_key, bool is_new)
{
    if (!snap_trace) return;
    if (snap_log_every > 1) {
        u64 c = atomic64_inc_return(&snap_evt_count);
        if ((c % snap_log_every) != 0) return;
    }

    /* buffer_head state bits */
    bool dirty    = test_bit(BH_Dirty,    &bh->b_state);
    bool uptodate = test_bit(BH_Uptodate, &bh->b_state);
    bool mapped   = test_bit(BH_Mapped,   &bh->b_state);
    bool locked   = test_bit(BH_Lock,     &bh->b_state);

    pr_info("SNAPSHOT:%s dev=%s blk=%llu (%zu bytes, %llu sectors) key=%llu "
            "state{D=%d,U=%d,M=%d,L=%d} pid=%d comm=%s %s\n",
            tag,
            bh->b_bdev && bh->b_bdev->bd_disk ? bh->b_bdev->bd_disk->disk_name : "?",
            (unsigned long long)bh->b_blocknr,
            bh->b_size,
            (unsigned long long)(bh->b_size >> 9),
            (unsigned long long)sector_key,
            dirty, uptodate, mapped, locked,
            current->pid, current->comm,
            is_new ? "NEW_DATA (about-to-be-written)"
                   : "OLD_DATA (read-from-disk via __bread)");

    if (snap_dump_bytes > 0 && bh->b_data) {
        size_t dump = min_t(size_t, bh->b_size, (size_t)snap_dump_bytes);
        print_hex_dump(KERN_INFO, "SNAPSHOT:bytes ",
                       DUMP_PREFIX_OFFSET, 16, 1, bh->b_data, dump, true);
    }
}

/* Workqueue for handling mount events */
static struct workqueue_struct *snapshot_wq;

struct snapshot_rec {
    u64 sector;   /* key (512B) */
    u32 size;     /* bytes */
    u64 offset;   /* offset inside blocks.dat */
} __packed;

struct cow_mem_work {
    struct work_struct work;
    snapshot_session *session;
    sector_t sector_key;     
    unsigned int size;       
    void *data;               
};


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
    xa_init(&session->pending_block);
    INIT_LIST_HEAD(&session->list);
    atomic_set(&session->ref_count, 1);
    atomic64_set(&session->blocks_count, 0);
    
    pr_info("SNAPSHOT: Created session with timestamp %llu\n", timestamp);
    return session;
}

/**
 * destroy_session - Cleanup a snapshot session
 */
void destroy_session(snapshot_session *session)
{
    unsigned long index;
    void *entry;
    
    if (!session)
        return;
    
    pr_info("SNAPSHOT: Destroying session %llu\n", 
            session->timestamp);
    
    /* Close files if still open */
    if (session->data_file) {
        filp_close(session->data_file, NULL);
        session->data_file = NULL;
    }
    if (session->map_file) {
        filp_close(session->map_file, NULL);
        session->map_file = NULL;
    }
    
    /* Free XArrays (using sentinel values, nothing to free) */
    xa_for_each(&session->saved_blocks, index, entry) {
        /* Sentinel values don't need freeing */
    }
    
    xa_destroy(&session->saved_blocks);
    xa_destroy(&session->pending_block);
    mutex_destroy(&session->dir_mtx);
    kfree(session);
}


/**
 * update_metadata_file - Update meta.json with final statistics
 */
static int update_metadata_file(snapshot_session *session, const char *raw_devname)
{
    char *pmeta = kmalloc(PATH_MAX, GFP_KERNEL);
    char meta[1024];
    size_t mlen;
    struct file *mf;
    loff_t pos = 0;
    //TODO: find a way to retrieve the filesystem type
    const char *fs_type = "singlefile-fs";
    int ret = 0;

    if (!pmeta)
        return -ENOMEM;

    snprintf(pmeta, PATH_MAX, "%s/meta.json", session->snapshot_dir);


    /* Generate JSON metadata */
    mlen = scnprintf(meta, sizeof(meta),
                     "{\n"
                     "  \"device\": \"%s\",\n"
                     "  \"timestamp\": %llu,\n"
                     "  \"block_size\": %u,\n"
                     "  \"fs_type\": \"%s\",\n"
                     "  \"total_blocks_saved\": %lld,\n"
                     "  \"snapshot_type\": \"COW\"\n"
                     "}\n",
                     raw_devname,
                     session->timestamp,
                     DEFAULT_BLOCK_SIZE,
                     fs_type,
                     atomic64_read(&session->blocks_count));

    mf = filp_open(pmeta, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(mf)) {
        ret = PTR_ERR(mf);
        pr_err("SNAPSHOT: Failed to create meta.json: %d\n", ret);
        goto out;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    kernel_write(mf, meta, mlen, &pos);
#else
    {
        mm_segment_t oldfs = get_fs();
        set_fs(KERNEL_DS);
        vfs_write(mf, meta, mlen, &pos);
        set_fs(oldfs);
    }
#endif

    filp_close(mf, NULL);
    pr_info("SNAPSHOT: Updated %s\n", pmeta);

out:
    kfree(pmeta);
    return ret;
}

/**
 * create_files_and_meta_for_session - Create snapshot files
 */
static int create_files_and_meta_for_session(snapshot_session *session, const char *raw_devname)
{
    char *pmap = kmalloc(PATH_MAX, GFP_KERNEL);
    char *pdat = kmalloc(PATH_MAX, GFP_KERNEL);
    int err = 0;

    if (!pmap || !pdat) {
        err = -ENOMEM;
        goto cleanup;
    }

    session->map_file = NULL;
    session->data_file = NULL;
    session->map_pos = 0;
    session->data_pos = 0;

    snprintf(pmap, PATH_MAX, "%s/blocks.map", session->snapshot_dir);
    snprintf(pdat, PATH_MAX, "%s/blocks.dat", session->snapshot_dir);

    /* Create blocks.map */
    session->map_file = filp_open(pmap, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(session->map_file)) {
        err = PTR_ERR(session->map_file);
        session->map_file = NULL;
        pr_err("SNAPSHOT: Failed to create blocks.map: %d\n", err);
        goto cleanup;
    }

    /* Create blocks.dat */
    session->data_file = filp_open(pdat, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(session->data_file)) {
        err = PTR_ERR(session->data_file);
        filp_close(session->map_file, NULL);
        session->map_file = NULL;
        session->data_file = NULL;
        pr_err("SNAPSHOT: Failed to create blocks.dat: %d\n", err);
        goto cleanup;
    }

    /* Create initial metadata */
    update_metadata_file(session, raw_devname);

    pr_info("SNAPSHOT: Created snapshot files in %s\n", session->snapshot_dir);

cleanup:
    kfree(pmap);
    kfree(pdat);
    return err;
}


/**
 * create_snapshot_subdirectory - Create timestamped directory for session
 * 
 * Called from workqueue context 
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
    
    /* Sanitize device name (extract the last part of path) */
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
    err = create_files_and_meta_for_session(session, raw_devname);
    if (err) {
        pr_err("SNAPSHOT: creation/open files/meta failed: %d\n", err);
        return err;
    }
    done_path_create(&parent_path, dentry);
    kfree(path);
    return err;
}


/**
 * mount_work_handler - Workqueue handler for mount events
 * 
 */
static void mount_work_handler(struct work_struct *work) {
    struct mount_work *mw = container_of(work, struct mount_work, work);
    snapshot_device *sdev;
    snapshot_session *session;
    u64 timestamp;
    int ret;

    /* Device was already found in handle_mount_event, it's passed via work */
    sdev = mw->sdev;
    
    if (!sdev) {
        pr_err("SNAPSHOT: No device in mount_work\n");
        goto cleanup;
    }
    if (mw->action == SNAP_WORK_START) {

        /* Check if snapshot is still active */
        if (!sdev->snapshot_active) {
            pr_info("SNAPSHOT: Snapshot no longer active for: %s\n", sdev->name);
            goto cleanup;
        }

        /* Create new session */
        timestamp = ktime_get_real_ns();
        session = create_session(sdev, timestamp);
        if (!session) {
            pr_err("SNAPSHOT: Failed to create session for: %s\n", sdev->name);
            goto cleanup;
        }

        /* Create snapshot subdirectory - use the device name from sdev */
        ret = create_snapshot_subdirectory(session, sdev->name);
        if (ret) {
            pr_err("SNAPSHOT: Failed to create directory: %d\n", ret);
            destroy_session(session);
            goto cleanup;
        }

        /* Add session to device */
        spin_lock(&sdev->lock);
        list_add_tail(&session->list, &sdev->sessions);
        spin_unlock(&sdev->lock);

        /*Assign active session for device*/
        rcu_assign_pointer(sdev->active_session, session); 

        pr_info("SNAPSHOT: Session %llu started for device: %s\n", timestamp, sdev->name);

    } else { 
        pr_info("SNAPSHOT: Unmount work -> stopping sessions for %s\n", sdev->name);
        stop_sessions_for_bdev(sdev);
    }
    cleanup:
        kfree(mw);
}

/**
 * start_session_for_bdev - Queue work to start a session
 * 
 * Called from kprobe handler
 */
int start_session_for_bdev(snapshot_device *sdev, struct block_device *bdev, u64 *out_ts) {
    struct mount_work *mw;

    /* Allocate work structure */
    mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw)
        return -ENOMEM;

    /* Initialize work */
    INIT_WORK(&mw->work, mount_work_handler);
    mw->bdev = bdev;
    mw->sdev = sdev; 
    mw->action = SNAP_WORK_START;

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
    LIST_HEAD(to_free);
    snapshot_session *session, *tmp;
    /* Return if there isn't a device attached*/
    if (!sdev || !sdev->bdev)
        return -EINVAL;

    pr_info("SNAPSHOT: Stopping all sessions for: %s\n", sdev->name);

    /* Detach under spinlock */
    spin_lock(&sdev->lock);
    RCU_INIT_POINTER(sdev->active_session, NULL);

    /* Move all sessions to a private list so we can free them later */
    list_for_each_entry_safe(session, tmp, &sdev->sessions, list) {
        list_move_tail(&session->list, &to_free);
    }
    sdev->bdev = NULL;
    spin_unlock(&sdev->lock);

    synchronize_rcu();

    /* Destroy sessions*/
    list_for_each_entry_safe(session, tmp, &to_free, list) {
        list_del_init(&session->list);
        destroy_session(session);
    }
    return 0;
}
static void cow_mem_worker(struct work_struct *w)
{
    struct cow_mem_work *mw = container_of(w, struct cow_mem_work, work);
    snapshot_session *session = mw->session;
    struct snapshot_rec rec;
    ssize_t wrc;

    if (!session->data_file || !session->map_file) {
        pr_warn_ratelimited("SNAPSHOT: no files open, drop key=%llu\n",
                            (unsigned long long)mw->sector_key);
        goto out;
    }

    mutex_lock(&session->dir_mtx);
    /* Write original block data to blocks.dat */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    wrc = kernel_write(session->data_file, mw->data, mw->size, &session->data_pos);
#else
    { 
        mm_segment_t oldfs = get_fs(); 
        set_fs(KERNEL_DS);
        wrc = vfs_write(session->data_file, mw->data, mw->size, &session->data_pos);
        set_fs(oldfs); 
    }
#endif
    pr_info("SNAPSHOT: I'm writing block data");
    if (wrc != mw->size) {
        pr_warn_ratelimited("SNAPSHOT: data write incomplete (%zd/%u)\n", wrc, mw->size);
    }

    /* Write record to blocks.map */
    rec.sector = mw->sector_key;
    rec.size   = mw->size;
    rec.offset = session->data_pos - mw->size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    wrc = kernel_write(session->map_file, (void *)&rec, sizeof(rec), &session->map_pos);
#else
    { 
        mm_segment_t oldfs = get_fs(); 
        set_fs(KERNEL_DS);
        wrc = vfs_write(session->map_file, (void *)&rec, sizeof(rec), &session->map_pos);
        set_fs(oldfs); 
    }
#endif

    if (wrc != sizeof(rec)) {
        pr_warn_ratelimited("SNAPSHOT: map write incomplete (%zd/%zu)\n", wrc, sizeof(rec));
    }

    /* Update block counter */
    atomic64_inc(&session->blocks_count);

    pr_info("SNAPSHOT: COW saved sector=%llu size=%u offset=%llu (total_blocks=%lld)\n",
            (unsigned long long)rec.sector, rec.size,
            (unsigned long long)rec.offset,
            atomic64_read(&session->blocks_count));

    mutex_unlock(&session->dir_mtx);

    /* Mark as saved */
    xa_store(&session->saved_blocks, mw->sector_key, xa_mk_value(1), GFP_KERNEL);

out:
    xa_erase(&session->pending_block, mw->sector_key);
    put_session(session);
    kfree(mw->data);
    kfree(mw);
}

static int enqueue_cow_mem(snapshot_session *session,
                           sector_t sector_key,
                           const void *src,
                           unsigned int size)
{
    struct cow_mem_work *mw;
    void *copy;
    int ret;

    /* Here we assume block is not saved, already checked in the caller */

    /* Try to mark as pending (atomic insert) */
    ret = xa_insert(&session->pending_block, sector_key, xa_mk_value(1), GFP_ATOMIC);
    if (ret == -EBUSY) {
        /* Already being processed by another thread */
        return 0;
    }
    if (ret) {
        pr_err_ratelimited("SNAPSHOT: xa_insert failed: %d\n", ret);
        return ret;
    }

    /* Allocate memory copy of original data */
    copy = kmemdup(src, size, GFP_ATOMIC);
    if (!copy) {
        xa_erase(&session->pending_block, sector_key);
        return -ENOMEM;
    }

    /* Allocate work structure */
    mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw) {
        kfree(copy);
        xa_erase(&session->pending_block, sector_key);
        return -ENOMEM;
    }

    INIT_WORK(&mw->work, cow_mem_worker);
    mw->session    = session;
    mw->sector_key = sector_key;
    mw->size       = size;
    mw->data       = copy;

    /* Increment session refcount */
    atomic_inc(&session->ref_count);

    /* Queue work */
    if (!queue_work(snapshot_wq, &mw->work)) {
        xa_erase(&session->pending_block, sector_key);
        put_session(session);
        kfree(copy);
        kfree(mw);
        return -EAGAIN;
    }

    return 1;  /* Queued successfully */
}

/**
 * write_dirty_buffer_handler - Kretprobe handler for write_dirty_buffer
 *     
 * NB: The write is intercepted here 2 times : block=2 → data block and block=1 → inode block
 * 
 */
static int write_dirty_buffer_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct buffer_head *bh = (struct buffer_head *)regs->di;
    snapshot_device *sdev;
    snapshot_session *ses;
    sector_t key;
    //void *orig_data;
    int ret;

    if (!bh || !bh->b_bdev)
        return 0;

    /* Trova il device registrato */
    sdev = find_device_for_bdev(bh->b_bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) ||
        READ_ONCE(sdev->bdev) != bh->b_bdev)
        return 0;

    ses = get_active_session_rcu(sdev);
    if (!ses)
        return 0;

    key = (sector_t)bh->b_blocknr * (bh->b_size >> 9);

    /* Skip if already saved */
    if (xa_load(&ses->saved_blocks, key)) {
        pr_info("SNAPSHOT: Block already saved key=%llu\n", 
                (unsigned long long)key);
        put_session(ses);
        return 0;
    }

    snap_dump_bh("WRITE_CONFIRMED", bh, key, true);

    void *entry = xa_load(&ses->pending_block, key);
    if (!entry) {
        /* Write without caching */
        pr_warn_ratelimited("SNAPSHOT: Write without caching blk=%llu key=%llu\n",
                            (unsigned long long)bh->b_blocknr, (unsigned long long)key);
        put_session(ses);
        return 0;
    }
    if (xa_is_value(entry)) {
        pr_info("SNAPSHOT: COW already pending key=%llu\n", (unsigned long long)key);
        put_session(ses);
        return 0;
    }

    void *old_data = xa_erase(&ses->pending_block, key);
    if (old_data && !xa_is_value(old_data)) {
        /* Persist block on disk*/
        int ret = enqueue_cow_mem(ses, key, old_data, bh->b_size);
        kfree(old_data);

        if (ret > 0) {
            pr_info("SNAPSHOT: COW confirmed and queued blk=%llu key=%llu\n",
                    (unsigned long long)bh->b_blocknr, (unsigned long long)key);
        } else if (ret && ret != -EBUSY) {
            pr_warn_ratelimited("SNAPSHOT: COW enqueue failed key=%llu err=%d\n",
                                (unsigned long long)key, ret);
        }
    }
    put_session(ses);
    return 0;
}



struct bread_ctx { struct block_device *bdev; sector_t block; unsigned int size; };

static int bread_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
#if defined(CONFIG_X86_64)
    struct bread_ctx *c =  (struct bread_ctx *)ri->data;
    c->bdev  = (struct block_device *)regs->di;
    c->block = (sector_t)regs->si;
    c->size  = (unsigned int)regs->dx;
#endif
    return 0;
}

/**
 * __bread_gfp_handler - Main COW hook
 * 
 * Intercepts block reads and saves original content BEFORE any write occurs
 */
static int __bread_gfp_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct bread_ctx *c = (struct bread_ctx *)(ri->data);
    struct buffer_head *bh = (struct buffer_head *)regs_return_value(regs);
    snapshot_device *sdev;
    snapshot_session *ses;
    sector_t key;

    if (!bh || IS_ERR(bh) || !c->bdev)
        return 0;

    /* Find registered device for this bdev */
    sdev = find_device_for_bdev(c->bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) || READ_ONCE(sdev->bdev) != c->bdev)
        return 0;

    /* Get active session */
    ses = get_active_session_rcu(sdev);
    if (!ses)
        return 0;

    /* Calculate sector key (512B units) */
    key = (sector_t)bh->b_blocknr * (bh->b_size >> 9);

    snap_dump_bh("COW_CAPTURE", bh, key, false);

    if (xa_load(&ses->saved_blocks, key) || xa_load(&ses->pending_block, key)) {
        put_session(ses);
        return 0;
    }
    snap_dump_bh("COW_CAPTURE", bh, key, false);

    /* Copy old data */
    void *copy = kmemdup(bh->b_data, bh->b_size, GFP_ATOMIC);
    if (!copy) {
        put_session(ses);
        return 0;
    }

    /* Only the first thread can do the inser the other do kfree */
    if (xa_insert(&ses->pending_block, key, copy, GFP_ATOMIC)) {
        kfree(copy);
    } else {
        pr_info("SNAPSHOT: Block cached blk=%llu size=%zu key=%llu\n",
                (unsigned long long)bh->b_blocknr,
                (size_t)bh->b_size,
                (unsigned long long)key);
    }
    put_session(ses);
    return 0;
}



static int kill_block_super_entry(struct kprobe *p, struct pt_regs *regs)
{
    struct super_block *sb;
    struct block_device *bdev;
    snapshot_device *sdev;

    sb = (struct super_block *)regs->di;

    if (!sb)
        return 0;

    
    bdev = READ_ONCE(sb->s_bdev);
    if (!bdev)
        return 0;

    sdev = find_device_for_bdev(bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) || READ_ONCE(sdev->bdev) != bdev)
        return 0;

    struct mount_work *mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw) return -ENOMEM;

    INIT_WORK(&mw->work, mount_work_handler);
    mw->bdev   = NULL;
    mw->sdev   = sdev;
    mw->action = SNAP_WORK_STOP;

    if (!queue_work(snapshot_wq, &mw->work)) {
        kfree(mw);
        return -EAGAIN;
    }

    pr_info("SNAPSHOT: kill_block_super() detected for %s\n",
        sdev->name);

    return 0;
}

/**
 * Hook for __sbread_gfp to log read operations
 * NB: sb_bread can't be hooked because it is inlined
 */
static struct kprobe write_dirty_buffer_kp = {
    .symbol_name = "write_dirty_buffer",
    .pre_handler = write_dirty_buffer_handler,
};

/**
 * install_write_hook - Install the write event hook
 */
int install_write_hook(void)
{
    int ret;
    
    ret = register_kprobe(&write_dirty_buffer_kp);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to register kprobe on write: %d\n", ret);
        return ret;
    }
    return 0;
}

/**
 * remove_write_hook - Remove the write event hook
 */
void remove_write_hook(void)
{
    unregister_kprobe(&write_dirty_buffer_kp);
}

/* Kretprobe structure for hooking __sbread */
static struct kretprobe __bread_gfp_kp = {
    .kp.symbol_name = "__bread_gfp",
    .entry_handler  = bread_entry,
    .handler = __bread_gfp_handler,
    .data_size      = sizeof(struct bread_ctx),
    .maxactive = 64, 
};

/**
 * install_read_hook - Install the read event hook
 */
int install_read_hook(void)
{
    int ret;
    
    ret = register_kretprobe(&__bread_gfp_kp);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to register kretprobe on read: %d\n", ret);
        return ret;
    }
    return 0;
}

/**
 * remove_read_hook - Remove the read event hook
 */
void remove_read_hook(void)
{
    unregister_kretprobe(&__bread_gfp_kp);
    pr_info("SNAPSHOT: Read hook removed (missed %d probes)\n", 
        __bread_gfp_kp.nmissed);
}

/* Kretprobe structure for hooking kill_block_super */
static struct kprobe kill_block_super_kp = {
    .symbol_name = "kill_block_super",
    .pre_handler  = kill_block_super_entry,
};

/**
 * install_unmount_hook - Install the unmount event hook
 */
int install_unmount_hook(void)
{
    int ret;
    
    ret = register_kprobe(&kill_block_super_kp);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to register kprobe on unmount: %d\n", ret);
        return ret;
    }
    return 0;
}

/**
 * remove_unmount_hook - Remove the unmount event hook
 */
void remove_unmount_hook(void)
{
    unregister_kprobe(&kill_block_super_kp);
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