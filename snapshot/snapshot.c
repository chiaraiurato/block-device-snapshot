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
#include <linux/bio.h>
#include <linux/buffer_head.h>
#include "include/snapshot.h"
#include <linux/mnt_idmapping.h>
#include "../register/include/register.h"

#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/bitops.h>
#include <linux/blk_types.h> 
#include <linux/mm.h> 
#include <linux/pagemap.h>

#define COW_SECT_PER_BLK    (COW_BLK_SZ / COW_SECT_SZ)
#define ALIGN_DOWN_SECT(s)  ((s) & ~((sector_t)COW_SECT_PER_BLK - 1))
#define ALIGN_UP_SECT(s)    (((s) + COW_SECT_PER_BLK - 1) & ~((sector_t)COW_SECT_PER_BLK - 1))

DEFINE_PER_CPU(unsigned long, BRUTE_START);//redundant you might use the below per-cpu variable to setup the initial search address
DEFINE_PER_CPU(unsigned long *, kprobe_context_pointer);//this is used for steady state operations 
static struct kprobe setup_probe;

struct kprobe *the_probe = &setup_probe;

static atomic_t successful_search_counter = ATOMIC_INIT(0); //number of CPUs that succesfully found the address of the per-CPU variable that keeps the reference to the current kprobe context 
unsigned long *reference_offset = 0x0;

void run_on_cpu(void *x) { //this is here just to enable a kprobe on it 
    pr_info("SNAPSHOT: block device snapshot setup - running on CPU %d\n", smp_processor_id()); 
}


static bool snap_trace = true;             /* on/off trace for buffer cache*/
static bool snap_trace_bio = false;        /* on/off trace for bio*/
static int snap_dump_bytes = 64;           /* hexdump N bytes (0 = off) */
static unsigned int snap_log_every = 1;    /* log 1 of every N events */

static atomic64_t snap_evt_count = ATOMIC_INIT(0);

typedef typeof(((struct bio *)0)->bi_opf) snap_opf_t;

static inline struct address_space *snap_page_mapping(struct page *page)
{
#ifdef PAGE_MAPPING_FLAGS
    return (struct address_space *)(
        (unsigned long)READ_ONCE(page->mapping) & ~PAGE_MAPPING_FLAGS
    );
#else
    return (struct address_space *)READ_ONCE(page->mapping);
#endif
}

static const char *snap_op_name(unsigned int op)
{
    switch (op) {
    case REQ_OP_READ:          return "READ";
    case REQ_OP_WRITE:         return "WRITE";
    case REQ_OP_FLUSH:         return "FLUSH";
    case REQ_OP_DISCARD:       return "DISCARD";
    case REQ_OP_WRITE_ZEROES:  return "WRITE_ZEROES";
    case REQ_OP_ZONE_APPEND:   return "ZONE_APPEND";
    case REQ_OP_ZONE_RESET:    return "ZONE_RESET";
    default:                   return "OP?";
    }
}

static void snap_flags_to_str(snap_opf_t opf, char *buf, size_t sz)
{
    int n = 0;
#define ADD(_cond, _name) do { if (_cond) n += scnprintf(buf + n, sz - n, "%s" _name, n ? "|" : ""); } while (0)
#ifdef REQ_SYNC
    ADD(opf & REQ_SYNC, "SYNC");
#endif
#ifdef REQ_META
    ADD(opf & REQ_META, "META");
#endif
#ifdef REQ_FUA
    ADD(opf & REQ_FUA, "FUA");
#endif
#ifdef REQ_PREFLUSH
    ADD(opf & REQ_PREFLUSH, "PREFLUSH");
#endif
#ifdef REQ_RAHEAD
    ADD(opf & REQ_RAHEAD, "RAHEAD");
#endif
#ifdef REQ_BACKGROUND
    ADD(opf & REQ_BACKGROUND, "BACKGROUND");
#endif
#ifdef REQ_NOWAIT
    ADD(opf & REQ_NOWAIT, "NOWAIT");
#endif
#ifdef REQ_PRIO
    ADD(opf & REQ_PRIO, "PRIO");
#endif
#undef ADD
    if (n == 0) strscpy(buf, "-", sz);
}

static struct inode *snap_bio_inode(struct bio *bio)
{
    struct bio_vec bvec;
    struct bvec_iter iter;

    rcu_read_lock();
    bio_for_each_segment(bvec, bio, iter) {
        struct page *page = bvec.bv_page;
        struct address_space *mapping = snap_page_mapping(page);
        if (!mapping) continue;

        if (READ_ONCE(mapping->host)) {
            struct inode *inode = mapping->host;
            rcu_read_unlock();
            return inode;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static void snap_decode_ioprio(u16 ioprio, unsigned int *classp, unsigned int *datap)
{
#ifdef IOPRIO_PRIO_CLASS
    *classp = IOPRIO_PRIO_CLASS(ioprio);
    *datap  = IOPRIO_PRIO_DATA(ioprio);
#else
    *classp = 0; *datap = 0;
#endif
}
static void snap_log_submit_bio(const char *tag, struct bio *bio)
{
    const char *disk = (bio->bi_bdev && bio->bi_bdev->bd_disk) ? bio->bi_bdev->bd_disk->disk_name : "?";
    snap_opf_t opf   = bio->bi_opf;
    unsigned int op  = bio_op(bio);
    char flags[96];  flags[0] = '\0';
    unsigned int iclass = 0, idata = 0;
    struct inode *inode = snap_bio_inode(bio);
    unsigned long ino   = inode ? inode->i_ino : 0;
    const char *fs_id   = (inode && inode->i_sb) ? inode->i_sb->s_id : "-";

#ifdef CONFIG_BLOCK
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
    u16 ioprio = bio->bi_ioprio;
#else
    u16 ioprio = 0;
#endif
#else
    u16 ioprio = 0;
#endif

    snap_flags_to_str(opf, flags, sizeof(flags));
    snap_decode_ioprio(ioprio, &iclass, &idata);

    pr_info_ratelimited(
        "SNAPSHOT:%s dev=%s op=%s flags=%s sector=%llu bytes=%u pid=%d comm=%s ioprio=%u/%u hint=%u inode=%lu fs=%s end_io=%ps\n",
        tag, disk, snap_op_name(op), flags,
        (unsigned long long)bio->bi_iter.bi_sector,
        bio->bi_iter.bi_size,
        current->pid, current->comm,
        iclass, idata,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        bio->bi_write_hint,
#else
        0U,
#endif
        ino, fs_id, bio->bi_end_io
    );

    if (snap_trace_bio)
        dump_stack();
}

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

/* Workqueue for handling events */
static struct workqueue_struct *snapshot_wq;
static struct workqueue_struct *snapshot_bio_wq;

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

struct cow_mem_work_bio { 
    struct work_struct work; 
    snapshot_session *ses; 
    struct block_device *bdev; 
    sector_t key; 
    unsigned int size; 
};

static int snap_unlink_path(const char *path)
{
    struct path p;
    struct dentry *parent;
    struct inode *dir;
    int err;

    err = kern_path(path, LOOKUP_FOLLOW, &p);
    if (err)
        return err;

    parent = dget_parent(p.dentry);
    dir = d_inode(parent);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    err = vfs_unlink(mnt_idmap(p.mnt), dir, p.dentry, NULL);
#else
    err = vfs_unlink(dir, p.dentry, NULL);
#endif

    dput(parent);
    path_put(&p);
    return err;
}

static int snap_rmdir_path(const char *dirpath)
{
    struct path p;
    struct dentry *parent;
    struct inode *dir;
    int err;

    err = kern_path(dirpath, LOOKUP_DIRECTORY, &p);
    if (err)
        return err;

    parent = dget_parent(p.dentry);  
    dir = d_inode(parent);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    err = vfs_rmdir(mnt_idmap(p.mnt), dir, p.dentry);
#else
    err = vfs_rmdir(dir, p.dentry);
#endif

    dput(parent);
    path_put(&p);
    return err;
}

/**
 * cleanup_empty_session - If no write occur to mounted device, then we can clean the directory
 */
static void cleanup_empty_session(snapshot_session *session)
{
    char *path;

    if (session->data_file) { filp_close(session->data_file, NULL); session->data_file = NULL; }
    if (session->map_file)  { filp_close(session->map_file,  NULL); session->map_file  = NULL; }

    path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path) {
        pr_err("SNAPSHOT: kmalloc(PATH_MAX) failed in cleanup_empty_session\n");
        return;
    }
    snprintf(path, PATH_MAX, "%s/blocks.dat", session->snapshot_dir);
    if (snap_unlink_path(path))
        pr_debug("SNAPSHOT: unlink failed : %s\n", path);

    snprintf(path, PATH_MAX, "%s/blocks.map", session->snapshot_dir);
    if (snap_unlink_path(path))
        pr_debug("SNAPSHOT: unlink failed : %s\n", path);

    snprintf(path, PATH_MAX, "%s/meta.json", session->snapshot_dir);
    if (snap_unlink_path(path))
        pr_debug("SNAPSHOT: unlink failed : %s\n", path);

    /* remove finally the directory */
    if (snap_rmdir_path(session->snapshot_dir))
        pr_debug("SNAPSHOT: rmdir failed : %s\n", session->snapshot_dir);
    
    kfree(path);
    pr_info("SNAPSHOT: Removed empty snapshot dir %s\n", session->snapshot_dir);
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
    atomic_set(&session->ref_cleanup, 1);
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
    
    
    if (atomic64_read(&session->blocks_count) == 0) {
        /* No blocks saved: remove directory */
        cleanup_empty_session(session);
    } else {
        /* Close files if still open */
        if (session->data_file) { filp_close(session->data_file, NULL); session->data_file = NULL; }
        if (session->map_file)  { filp_close(session->map_file,  NULL); session->map_file  = NULL; }
    }
    
    xa_for_each(&session->pending_block, index, entry) {
        if (entry && !xa_is_value(entry))
            kfree(entry);
    }
    
    xa_destroy(&session->saved_blocks);
    xa_destroy(&session->pending_block);
    mutex_destroy(&session->dir_mtx);
    kfree(session);
}


/**
 * update_metadata_file - Update meta.json with final statistics
 */
static int update_metadata_file(snapshot_session *session,
    const char *raw_devname,
    const char *fs_type)
{
    char *pmeta = NULL;
    char *meta  = NULL;
    size_t mlen;
    struct file *mf;
    loff_t pos = 0;
    int ret = 0;

    if (!session || !raw_devname || !fs_type)
    return -EINVAL;

    pmeta = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pmeta)
        return -ENOMEM;

    meta = kmalloc(1024, GFP_KERNEL);           
    if (!meta) { ret = -ENOMEM; goto out_free_pmeta; }

    snprintf(pmeta, PATH_MAX, "%s/meta.json", session->snapshot_dir);

    mlen = scnprintf(meta, 1024,
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
    COW_BLK_SZ,
    fs_type,
    atomic64_read(&session->blocks_count));

    mf = filp_open(pmeta, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (IS_ERR(mf)) {
        ret = PTR_ERR(mf);
        pr_err("SNAPSHOT: Failed to create meta.json: %d\n", ret);
        goto out_free_meta;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
        ret = kernel_write(mf, meta, mlen, &pos);
    #else
    {
        mm_segment_t oldfs = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_write(mf, meta, mlen, &pos);
        set_fs(oldfs);
    }
    #endif
    filp_close(mf, NULL);
    if (ret < 0) {
        pr_err("SNAPSHOT: write meta.json failed: %d\n", ret);
        goto out_free_meta;
    }

    pr_info("SNAPSHOT: Updated %s\n", pmeta);
    ret = 0;

out_free_meta:
    kfree(meta);
out_free_pmeta:
    kfree(pmeta);
    return ret;
}


/**
 * create_files_and_meta_for_session - Create snapshot files
 */
static int create_files_and_meta_for_session(snapshot_session *session, const char *raw_devname, const char *fs_type)
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
    update_metadata_file(session, raw_devname, fs_type);

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
                                       const char *raw_devname, const char *fs_type)
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
    err = create_files_and_meta_for_session(session, raw_devname, fs_type);
    if (err) {
        pr_err("SNAPSHOT: creation/open files/meta failed: %d\n", err);
    }
    done_path_create(&parent_path, dentry);
    kfree(path);
    return err;
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
    /* Remove as pending */
    xa_erase(&session->pending_block, mw->sector_key);

out:
    put_session(session); //release the ref count after work is done
    kfree(mw->data);
    kfree(mw);
}

static int enqueue_cow_mem(snapshot_session *session,
                           sector_t sector_key,
                           void *src,
                           unsigned int size)
{
    struct cow_mem_work *mw;

    /* Allocate work structure */
    mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw) {
        return -ENOMEM;
    }

    INIT_WORK(&mw->work, cow_mem_worker);
    mw->session    = session;
    mw->sector_key = sector_key;
    mw->size       = size;
    mw->data       = src;
    //before queueing the work we need to increment the ref count
    get_session(session);
    /* Queue work */
    if (!queue_work(snapshot_wq, &mw->work)) {
        //release the ref count if failed
        put_session(session);
        kfree(mw);
        return -EAGAIN;
    }

    return 1;  /* Queued successfully */
}

/**
 * flush_pending_blocks - After creation of files flush blocks to disk if captured 
 * before the reference counter "ref_files_ready" was 0
 */
static void flush_pending_blocks(snapshot_session *ses)
{
    unsigned long index;
    void *entry;

    xa_for_each(&ses->pending_block, index, entry) {
        if (!entry) continue;

        if (!xa_is_value(entry)) {
            if (enqueue_cow_mem(ses, (sector_t)index, entry, COW_BLK_SZ) <= 0) {
                pr_warn("SNAPSHOT: flush enqueue failed key=%lu\n", index);
            }
        }
    }
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

        if (!mw->bdev || !mw->bdev->bd_disk) {
            pr_info("SNAPSHOT: Device no longer valid\n");
            goto cleanup;
        }

        /* Create new session */
        timestamp = ktime_get_real_ns();
        session = create_session(sdev, timestamp);
        if (!session) {
            pr_err("SNAPSHOT: Failed to create session for: %s\n", sdev->name);
            goto cleanup;
        }
        /* Add session to device */
        spin_lock(&sdev->lock);
        list_add_tail(&session->list, &sdev->sessions);
        spin_unlock(&sdev->lock);

        /*Assign active session for device*/
        rcu_assign_pointer(sdev->active_session, session); 

        atomic_set(&session->ref_files_ready, 0);

        /* Create snapshot subdirectory - use the device name from sdev */
        ret = create_snapshot_subdirectory(session, sdev->name, mw->fs_type);
        if (ret) {
            pr_err("SNAPSHOT: Failed to create directory: %d\n", ret);
            destroy_session(session);
            goto cleanup;
        }

        atomic_set(&session->ref_files_ready, 1);
        smp_wmb();  // Memory barrier

        flush_pending_blocks(session);
        pr_info("SNAPSHOT: Session %llu started\n",
            timestamp);

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
int start_session_for_bdev(snapshot_device *sdev, struct block_device *bdev, u64 *out_ts, const char *fs_type) {
    struct mount_work *mw;

    /* Allocate work structure */
    mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
    if (!mw)
        return -ENOMEM;

    /* Initialize work */
    INIT_WORK(&mw->work, mount_work_handler);
    mw->bdev = bdev;
    mw->sdev = sdev; 
    mw->fs_type = fs_type;
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
    snapshot_session *session;
    /* Return if there isn't a device attached*/
    if (!sdev || !sdev->bdev)
        return -EINVAL;

    pr_info("SNAPSHOT: Stopping all sessions for: %s\n", sdev->name);

    /* Get active session*/
    rcu_read_lock();
    session = rcu_dereference(sdev->active_session);
    rcu_read_unlock();

    if (!session)
        return 0;

    /* Detach under spinlock */
    spin_lock(&sdev->lock);
    RCU_INIT_POINTER(sdev->active_session, NULL);
    list_del_init(&session->list);
    spin_unlock(&sdev->lock);

    /* Wait all RCU readers before destroying session */
    synchronize_rcu();

    /* Do not destroy session here, we must let finish our workers*/
    //release the main ref that was added when the session was created
    put_session(session);
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
    snapshot_session *ses;
    sector_t key;
    int ret;

    if (!bh || !bh->b_bdev)
        return 0;

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
        return 0;
    }

    //snap_dump_bh("WRITE_CONFIRMED", bh, key, true);
    /*Take old data and replace data with a sentinel*/
    void *prev = xa_store(&ses->pending_block, key, xa_mk_value(1), GFP_ATOMIC);
    if (xa_err(prev)) {
        pr_warn_ratelimited("SNAPSHOT: xa_store err=%ld key=%llu\n",
                            PTR_ERR(prev), (unsigned long long)key);
        return 0;
    }
    if (!prev || xa_is_value(prev)) {
        return 0;
    }
    /* Enqueue work to save old data */
    ret = enqueue_cow_mem(ses, key, prev, bh->b_size);
    if (ret < 0) {
        void *rb = xa_store(&ses->pending_block, key, prev, GFP_ATOMIC);
        if (xa_err(rb)) {
            kfree(prev);
        }
        pr_warn_ratelimited("SNAPSHOT: enqueue failed key=%llu err=%d\n",
                            (unsigned long long)key, ret);
    } else {
        pr_info("SNAPSHOT: COW confirmed and queued blk=%llu key=%llu\n",
                (unsigned long long)bh->b_blocknr, (unsigned long long)key);
    }
    return 0;
}



struct bread_ctx { 
    struct block_device *bdev; 
    sector_t block; 
    unsigned int size; 
};

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
 * Intercepts block reads and insert old data into pending_block XArray
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

    //snap_dump_bh("COW_CAPTURE", bh, key, false);

    if (xa_load(&ses->saved_blocks, key) || xa_load(&ses->pending_block, key)) {
        return 0;
    }

    /* Copy old data */
    //100 blocks with 4096 bytes = ~400KB not a big deal 
    void *copy = kmemdup(bh->b_data, bh->b_size, GFP_ATOMIC);
    if (!copy) {
        return 0;
    }

    /* Only the first thread can do the insert, the other do kfree */
    if (xa_insert(&ses->pending_block, key, copy, GFP_ATOMIC)) {
        kfree(copy);
    } else {
        pr_info("SNAPSHOT: Block cached blk=%llu size=%zu key=%llu\n",
                (unsigned long long)bh->b_blocknr,
                (size_t)bh->b_size,
                (unsigned long long)key);
    }
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
 * Hook for write_dirty_buffer
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
/**
 * Hook for __sbread_gfp to log read operations
 * NB: sb_bread can't be hooked because it is inlined
 */
static struct kretprobe __bread_gfp_kp = {
    .kp.symbol_name = "__bread_gfp",
    .entry_handler  = bread_entry,
    .handler = __bread_gfp_handler,
    .data_size      = sizeof(struct bread_ctx),
    .maxactive = -1, 
};

/**
 * read_old_block - Read from bio the old block
 */
static int read_old_block(struct block_device *bdev, sector_t key, void *buf, unsigned int size)
{
    struct page *page;
    int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    struct bio *bio = bio_alloc(bdev, 1, REQ_OP_READ, GFP_KERNEL);
#else
    struct bio *bio = bio_alloc(GFP_KERNEL, 1);
    bio = bio_alloc(GFP_KERNEL, 1);
    if (!bio) return -ENOMEM;
    bio_set_dev(bio, bdev);
    bio_set_op_attrs(bio, REQ_OP_READ, 0);
#endif
    if (!bio) return -ENOMEM;

    bio->bi_iter.bi_sector = key;
    bio->bi_opf = REQ_OP_READ | REQ_SYNC;

    page = alloc_page(GFP_KERNEL);
    if (!page) { bio_put(bio); return -ENOMEM; }

    if (bio_add_page(bio, page, size, 0) != size) {
        __free_page(page);
        bio_put(bio);
        return -EINVAL;
    }

    ret = submit_bio_wait(bio);
    if (!ret) {
        void *k = kmap_local_page(page);
        memcpy(buf, k, size);
        kunmap_local(k);
    }

    __free_page(page);
    //release ref
    bio_put(bio);
    return ret;
}

static sector_t inode_bmap_block(struct inode *inode, sector_t lblock)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
    if (inode->i_mapping && inode->i_mapping->a_ops && inode->i_mapping->a_ops->bmap)
        /* bmap(mapping, lblock) : pblock (sector_t) */
        return inode->i_mapping->a_ops->bmap(inode->i_mapping, lblock);
#endif
    /* bmap(inode, sector_t *), 0 = success */
    {
        sector_t pblock = lblock;
        if (bmap(inode, &pblock) == 0)
            return pblock; 
        return 0;     
    }
}

static int cow_schedule(struct file *file,
                                 loff_t start, size_t count,
                                 snapshot_session *ses)
{
    struct inode *inode = file->f_inode;
    struct super_block *sb = inode->i_sb;
    unsigned int blksize      = sb->s_blocksize;
    unsigned int blksize_bits = sb->s_blocksize_bits;
    loff_t end = start + count - 1;
    sector_t lfirst = (sector_t)(start >> blksize_bits);
    sector_t llast  = (sector_t)(end   >> blksize_bits);
    int scheduled = 0;

    for (sector_t l = lfirst; l <= llast; ++l) {
        sector_t pblock = inode_bmap_block(inode, l);
        sector_t key;
        void *ptr;

        if (!pblock)
            continue;

        key = (sector_t)pblock * (blksize >> 9);

        ptr = xa_store(&ses->pending_block, key, xa_mk_value(1), GFP_ATOMIC);
        if (!ptr || xa_is_value(ptr))
            continue;

        if (enqueue_cow_mem(ses, key, ptr, blksize) <= 0) {
            kfree(ptr);
            xa_erase(&ses->pending_block, key);
        } else {
            scheduled++;
        }
    }
    return scheduled;
}

/* cow_capture */
static int cow_capture(struct file *file,
                            loff_t start, size_t count,
                            snapshot_session *ses)
{
    struct inode *inode = file->f_inode;
    struct super_block *sb = inode->i_sb;
    struct block_device *bdev = sb ? sb->s_bdev : NULL;
    unsigned int blksize, blksize_bits;
    loff_t end;
    sector_t lfirst, llast, l;
    int captured = 0;

    if (!sb || !bdev || count == 0)
        return 0;

    blksize      = sb->s_blocksize;
    blksize_bits = sb->s_blocksize_bits;

    if (blksize > PAGE_SIZE){
        pr_info("SNAPSHOT: Block size > Page Size. Not implemented");
        return 0;
    }
        

    end    = start + count - 1;
    lfirst = (sector_t)(start >> blksize_bits);
    llast  = (sector_t)(end   >> blksize_bits);

    for (l = lfirst; l <= llast; ++l) {
        sector_t pblock = inode_bmap_block(inode, l);
        sector_t key;
        void *copy;

        if (!pblock)
            continue;

        key = (sector_t)pblock * (blksize >> 9);

        if (xa_load(&ses->saved_blocks, key) ||
            xa_load(&ses->pending_block, key))
            continue;

        if (xa_insert(&ses->pending_block, key, xa_mk_value(1), GFP_ATOMIC))
            continue;

        copy = kmalloc(blksize, GFP_KERNEL);
        if (!copy) {
            xa_erase(&ses->pending_block, key);
            continue;
        }

        if (read_old_block(bdev, key, copy, blksize) == 0) {
            (void)xa_store(&ses->pending_block, key, copy, GFP_KERNEL);
            captured++;
        } else {
            kfree(copy);
            xa_erase(&ses->pending_block, key);
        }
    }
    return captured;
}
/**
 * vfs_write_entry - Pre-handler for vfs_write
 */
static int vfs_write_entry(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *)regs->di;
    size_t count = (size_t)regs->dx;
    loff_t *ppos = (loff_t *)regs->cx;
    loff_t start;
    snapshot_device *sdev;
    snapshot_session *ses;
    unsigned long *kprobe_cpu;
    int ncap = 0, nsched = 0;

    if (!file || !file->f_inode)
        return 0;

    if (!file->f_inode->i_sb || !file->f_inode->i_sb->s_bdev)
        return 0;
    /*Search for device */
    sdev = find_device_for_bdev(file->f_inode->i_sb->s_bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) || READ_ONCE(sdev->bdev) != file->f_inode->i_sb->s_bdev)
        return 0;
    /*Get active session */
    ses = get_active_session_rcu(sdev);
    if (!ses)
        return 0;

    /* We do not check if files are ready here, let our vfs capture the first write*/
    /* Initial offset */
    start = ppos ? READ_ONCE(*ppos) : file->f_pos;

    /* To enable blocking function add the trick*/
    kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
    __this_cpu_write(*kprobe_cpu, 0UL);
    preempt_enable();
    
    ncap = cow_capture(file, start, count, ses);
    /* Restore context*/
    preempt_disable();
    __this_cpu_write(*kprobe_cpu, (unsigned long)&the_probe);

    /* If the files are ready we can schedule the persistence to disk */
    if (atomic_read(&ses->ref_files_ready))
        nsched = cow_schedule(file, start, count, ses);

    if (ncap || nsched) {
        pr_info("SNAPSHOT: vfs_write preimage: captured=%d scheduled=%d inode=%lu pid=%d comm=%s\n",
                ncap, nsched, file->f_inode->i_ino, current->pid, current->comm);
    }

    return 0;
}

static struct kprobe vfs_write_kp = {
    .symbol_name = "vfs_write",
    .pre_handler = vfs_write_entry,
};

/**
 * install_vfs_write_hook - Install the write event hook
 */
int install_vfs_write_hook(void)
{
    int ret = register_kprobe(&vfs_write_kp);
    if (ret < 0) {
        pr_err("SNAPSHOT: Failed to register kprobe on vfs_write: %d\n", ret);
        return ret;
    }
    pr_info("SNAPSHOT: vfs_write hook installed\n");
    return 0;
}
/**
 * remove_vfs_write_hook - Remove the write event hook
 */
void remove_vfs_write_hook(void)
{
    unregister_kprobe(&vfs_write_kp);
    pr_info("SNAPSHOT: vfs_write hook removed\n");
}

/*
*   search pointer for the kprobe context.
*/
static int the_search(struct kprobe *kp, struct pt_regs *regs)
{
    unsigned long *temp = (unsigned long *)&BRUTE_START;

    while (temp > 0) {
        temp -= 1;
        if ((unsigned long)__this_cpu_read(*temp) == (unsigned long)kp) {
            atomic_inc(&successful_search_counter);
            printk(KERN_DEBUG "SNAPSHOT: found kprobe context pointer at %p\n", temp);
            reference_offset = temp;
            break;
        }
        if(temp <= 0)
            return 1;
    }
    __this_cpu_write(kprobe_context_pointer, temp);
    return 0;
}

/*
*   snapshot_kprobe_setup_init
*/
int snapshot_kprobe_setup_init(void)
{
    int ret;

    setup_probe.symbol_name = "run_on_cpu";
    setup_probe.pre_handler  = (kprobe_pre_handler_t)the_search;

    ret = register_kprobe(&setup_probe);
    if (ret < 0) {
        pr_info("SNAPSHOT: hook init failed for the init kprobe setup, returned %d\n", ret);
        return ret;
    }
    get_cpu();
    smp_call_function((smp_call_func_t)run_on_cpu, NULL, 1);

    if (atomic_read(&successful_search_counter) < num_online_cpus() - 1 ) {
        pr_info("SNAPSHOT: read hook load failed - number of setup CPUs is %d - number of remote online CPUs is %d\n", atomic_read(&successful_search_counter), num_online_cpus() - 1);
        put_cpu();
        unregister_kprobe(&setup_probe);
        return -1; 
    }
    if (reference_offset == 0x0){
        pr_info("SNAPSHOT: inconsistent value found for refeence offset\n");
        put_cpu();
        unregister_kprobe(&setup_probe);
        return -1;
    }   
    __this_cpu_write(kprobe_context_pointer, reference_offset);

    put_cpu();

    return 0;
}
/**
 * remove_setup_probe - Remove the probe setup
 */
void remove_setup_probe(void){
    unregister_kprobe(&setup_probe);
    pr_info("SNAPSHOT: Setup probe removed\n");
}

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
    /* Create workqueue for handling mount/unmount events */
    snapshot_wq = alloc_workqueue("snapshot_wq", WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!snapshot_wq) {
        pr_err("SNAPSHOT: Failed to create workqueue\n");
        return -ENOMEM;
    }

    snapshot_bio_wq = alloc_workqueue("snapshot_bio_kp_wq", WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!snapshot_bio_wq){
        pr_err("SNAPSHOT: Failed to create bio workqueue\n");
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

    if (snapshot_bio_wq) {
        flush_workqueue(snapshot_bio_wq);
        destroy_workqueue(snapshot_bio_wq);
        snapshot_bio_wq = NULL;
    }
    
    pr_info("SNAPSHOT: Subsystem cleaned up\n");
}