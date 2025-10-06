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
    u64 sector;   /* chiave in settori (512B) */
    u32 size;     /* bytes */
    u64 offset;   /* offset dentro blocks.dat */
} __packed;

static void cow_work_handler(struct work_struct *w)
{
    struct cow_work *cw = container_of(w, struct cow_work, work);
    snapshot_session *session = cw->session;
    struct buffer_head *bh = NULL;
    struct snapshot_rec rec;
    ssize_t wrc;
    int ret;

    pr_info("SNAPSHOT: cow_work start blk=%llu size=%u key=%llu dir=%s\n",
        (unsigned long long)cw->blocknr, cw->size,
        (unsigned long long)cw->sector_key,
        session->snapshot_dir);

    /* If it is already save exit */
    if (xa_load(&session->saved_blocks, cw->sector_key))
        goto out_done;

    bh = __bread(cw->bdev, cw->blocknr, cw->size);
    if (!bh) {
        pr_info("SNAPSHOT: __bread failed blk=%llu size=%u\n",
                            (unsigned long long)cw->blocknr, cw->size);
        goto out_done;
    }
    snap_dump_bh("cow_read", bh, cw->sector_key, false);
    /* Serialize I/O on files */
    mutex_lock(&session->dir_mtx);

    /* Append data in blocks.dat */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    wrc = kernel_write(session->data_file, bh->b_data, cw->size, &session->data_pos);
#else
    {
        mm_segment_t oldfs = get_fs(); set_fs(KERNEL_DS);
        wrc = vfs_write(session->data_file, bh->b_data, cw->size, &session->data_pos);
        set_fs(oldfs);
    }
#endif
    if (wrc != cw->size) {
        pr_info("SNAPSHOT: data append short write (%zd/%u)\n", wrc, cw->size);
    }

    /* Append record in blocks.map */
    rec.sector = cw->sector_key;
    rec.size   = cw->size;
    rec.offset = session->data_pos - cw->size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    wrc = kernel_write(session->map_file, (void *)&rec, sizeof(rec), &session->map_pos);
#else
    {
        mm_segment_t oldfs = get_fs(); set_fs(KERNEL_DS);
        wrc = vfs_write(session->map_file, (void *)&rec, sizeof(rec), &session->map_pos);
        set_fs(oldfs);
    }
#endif
    if (wrc != sizeof(rec)) {
        pr_warn_ratelimited("SNAPSHOT: map append short write (%zd/%zu)\n", wrc, sizeof(rec));
    }
    pr_info("SNAPSHOT: map<= {sector=%llu size=%u offset=%llu}  dir=%s  map_pos=%lld data_pos=%lld\n",
        (unsigned long long)rec.sector, rec.size,
        (unsigned long long)rec.offset,
        session->snapshot_dir,
        (long long)session->map_pos, (long long)session->data_pos);
    mutex_unlock(&session->dir_mtx);

    /* Mark copy-once in saved_blocks */
    ret = xa_err(xa_store(&session->saved_blocks, cw->sector_key, xa_mk_value(1), GFP_KERNEL));
    if (ret && ret != -EBUSY) {
        pr_warn_ratelimited("SNAPSHOT: xa_store(sentinella) err=%d\n", ret);
    }

out_done:
    if (bh) brelse(bh);
    xa_erase(&session->pending_block, cw->sector_key);
    pr_info("SNAPSHOT: cow_work end   blk=%llu key=%llu\n",
        (unsigned long long)cw->blocknr, (unsigned long long)cw->sector_key);
    put_session(session);
    kfree(cw);
}

/* called from the write hook to enqueue the COW once per sector_key */
//1 = queued; 0 = pending/saved; 
int enqueue_block_work(snapshot_session *session,
    struct block_device *bdev,
    sector_t blocknr,
    unsigned int size,
    sector_t sector_key)
{
    struct cow_work *cw;
    int ret;

    if (xa_load(&session->saved_blocks, sector_key))
        return 0;

    ret = xa_insert(&session->pending_block, sector_key, xa_mk_value(1), GFP_ATOMIC);
    if (ret == -EBUSY)
        return 0;
    if (ret)
        return ret;

    cw = kzalloc(sizeof(*cw), GFP_ATOMIC);
    if (!cw) {
        xa_erase(&session->pending_block, sector_key);
        return -ENOMEM;
    }

    INIT_WORK(&cw->work, cow_work_handler);
    cw->bdev = bdev;
    cw->session = session;
    cw->blocknr = blocknr;
    cw->size = size;
    cw->sector_key = sector_key;

    atomic_inc(&session->ref_count);

    if (!queue_work(snapshot_wq, &cw->work)) {
        xa_erase(&session->pending_block, sector_key);
        put_session(session);
        kfree(cw);
        return -EAGAIN;
    }
return 1;
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
    xa_init(&session->pending_block);
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
    xa_destroy(&session->pending_block);
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


static int create_files_and_meta_for_session(snapshot_session *session, const char *raw_devname)
{
    char *pmap = kmalloc(PATH_MAX, GFP_KERNEL);
    char *pdat = kmalloc(PATH_MAX, GFP_KERNEL);
    char *pmeta = kmalloc(PATH_MAX, GFP_KERNEL);
    int err = 0;
    loff_t pos = 0;
    char meta[512];
    size_t mlen;

    session->map_file = NULL;
    session->data_file = NULL;
    session->map_pos = 0;
    session->data_pos = 0;

    snprintf(pmap,  PATH_MAX, "%s/blocks.map", session->snapshot_dir);
    snprintf(pdat,  PATH_MAX, "%s/blocks.dat", session->snapshot_dir);
    snprintf(pmeta, PATH_MAX, "%s/meta.json",  session->snapshot_dir);

    session->map_file = filp_open(pmap, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(session->map_file)) {
        err = PTR_ERR(session->map_file);
        session->map_file = NULL;
        return err;
    }

    session->data_file = filp_open(pdat, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(session->data_file)) {
        err = PTR_ERR(session->data_file);
        filp_close(session->map_file, NULL);
        session->map_file = NULL;
        return err;
    }

    /* Scrivi un meta minimale (dev + timestamp) */
    mlen = scnprintf(meta, sizeof(meta),
                     "{ \"device\": \"%s\", \"timestamp\": %llu }\n",
                     raw_devname, session->timestamp);

    {
        struct file *mf = filp_open(pmeta, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (!IS_ERR(mf)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
            kernel_write(mf, meta, mlen, &pos);
#else
            {
                mm_segment_t oldfs = get_fs(); set_fs(KERNEL_DS);
                vfs_write(mf, meta, mlen, &pos);
                set_fs(oldfs);
            }
#endif
            filp_close(mf, NULL);
        }
    }

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
    snapshot_session *session;
    sector_t key;
    int ret;
    pr_info("SNAPSHOT: Inside hook write_dirty_buffer\n");
    if (!bh){
        pr_info("SNAPSHOT: bh is NULL\n");
        return 0;
    } 

    /* Search if the write is coming for the device mounted before*/
    sdev = find_device_for_bdev(bh->b_bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) ||
        READ_ONCE(sdev->bdev) != bh->b_bdev){
        pr_info("SNAPSHOT: No active snapshot for device %s\n", bh->b_bdev->bd_disk->disk_name);
        return 0;
    }
    
    session = get_active_session_rcu(sdev);
    if (!session) return 0;
    key = (sector_t)bh->b_blocknr * (bh->b_size >> 9);

    pr_info("SNAPSHOT: Adding block dev=%s block=%llu size=%zu\n",
            bh->b_bdev->bd_disk->disk_name,
            (unsigned long long)bh->b_blocknr,
            (size_t)bh->b_size);
    snap_dump_bh("write_hook", bh, key, true); 

    ret = enqueue_block_work(session, bh->b_bdev, bh->b_blocknr, bh->b_size, key);
    if (ret && ret != -EBUSY) {
        pr_info("SNAPSHOT: enqueue COW failed blk=%llu size=%u key=%llu err=%d\n",
                            (unsigned long long)bh->b_blocknr, bh->b_size,
                            (unsigned long long)key, ret);
    } else if (!ret) {
        pr_info("SNAPSHOT: COW queued blk=%llu size=%zu key=%llu\n",
                (unsigned long long)bh->b_blocknr, bh->b_size, (unsigned long long)key);
    } else {
        pr_info("SNAPSHOT: COW already pending/saved key=%llu\n",
                 (unsigned long long)key);
    }

    put_session(session);
    return 0;

}


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