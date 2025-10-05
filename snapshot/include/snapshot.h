#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
/* Maximum length of a device name */
#define MAX_DEV_LEN 256
#define DEFAULT_BLOCK_SIZE 4096


/** struct block_data - Stored block data 
 * @sector: Sector number 
 * @data: Block content 
 * @size: Size of the block
 */ 
struct block_data { 
    sector_t sector; 
    void *data;
    size_t size;
};

/**
 * struct snapshot_session - Represents a snapshot session
 * @timestamp: Unique identifier for the snapshot session
 * @sdev: Pointer to the associated snapshot_device
 * @snapshot_dir: Directory path for storing snapshots
 * @dir_mtx: Mutex to protect snapshot_dir creation
 * @saved_blocks: XArray of saved blocks (key: sector_t, value: block data)
 * @pending_block: XArray of blocks pending to be copied
 * @list: List head for linking sessions
 * @ref_count: Reference counter for safe cleanup
 */
typedef struct {
    u64 timestamp;              
    struct snapshot_device *sdev;       
    char snapshot_dir[PATH_MAX];
    struct mutex dir_mtx;
    struct xarray saved_blocks;
    struct xarray pending_block; 
    struct list_head list;
    atomic_t ref_count;
    struct file *map_file;        
    struct file *data_file;       
    loff_t map_pos;
    loff_t data_pos;
} snapshot_session;

/**
 * struct snapshot_device - Represents a snapshot device
 * @name: Device name 
 * @bdev: Associated block device (if mounted)
 * @snapshot_active: Flag indicating if snapshot is active
 * @list: List head for linking devices
 * @rcu: RCU head used for lockless readers
 * @lock: Spinlock to protect access to sessions list
 * @sessions: List of active sessions
 */
typedef struct snapshot_device {
    char name[MAX_DEV_LEN];
    struct block_device *bdev;
    bool snapshot_active;
    struct list_head list;
    struct rcu_head rcu;
    spinlock_t lock;          
    struct list_head sessions;
    snapshot_session __rcu *active_session;
} snapshot_device;

struct cow_work {
    struct work_struct work;
    struct block_device *bdev;     /* target to read the ORIGINAL block from */
    snapshot_session *session;     /* holds refcount while work runs */
    sector_t blocknr;              /* FS block number */
    unsigned int size;             /* FS block size (bytes) */
    sector_t sector_key;           /* key used in xarrays: sector units (512B) */
};

/**
 * struct mount_work - Work structure for async mount handling
 * @work: Work queue item
 * @bdev: Block device being mounted
 * @key: Device key 
 */
struct mount_work {
    struct work_struct work;
    struct block_device *bdev;
    snapshot_device *sdev;
};

/* Core snapshot functions */
int start_session_for_bdev(snapshot_device *sdev, struct block_device *bdev, u64 *out_ts);
int stop_sessions_for_bdev(snapshot_device *sdev);


/* Session management */
snapshot_session *create_session(snapshot_device *sdev, u64 timestamp);
void destroy_session(snapshot_session *session);

/* Block tracking */
int save_block_to_session(snapshot_session *session, sector_t sector, 
                          const void *data, size_t size);
bool is_block_saved(snapshot_session *session, sector_t sector);

int queue_cow_for_block(snapshot_session *session,
    struct block_device *bdev,
    sector_t blocknr,
    unsigned int size,
    sector_t sector_key);

/* Run restore (device unmounted): write saved blocks back */
int restore_snapshot_for_devname(const char *devname);

static inline snapshot_session *get_active_session_rcu(snapshot_device *sdev)
{
    snapshot_session *session;
    rcu_read_lock();
    session = rcu_dereference(sdev->active_session);
    if (session)
        atomic_inc(&session->ref_count); 
    rcu_read_unlock();
    return session;
}

static inline void put_session(snapshot_session *ses)
{
    if (!ses) return;
    atomic_dec(&ses->ref_count);
}
/* Workqueue initialization */
int snapshot_init(void);
void snapshot_exit(void);

/**
 * install_write_hook - Install the write event hook
 * Return: 0 on success, error code on failure
 */
int install_write_hook(void);

/**
 * remove_write_hook - Remove the write event hook
 */
void remove_write_hook(void);


#endif
