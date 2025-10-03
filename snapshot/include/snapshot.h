#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/limits.h>
#include <linux/types.h>
/* Maximum length of a device name */
#define MAX_DEV_LEN 256
#define DEFAULT_BLOCK_SIZE 4096

/**
 * struct block_data - Stored block data
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
 * @list: List head for linking sessions
 * @ref_count: Reference counter for safe cleanup
 */
typedef struct {
    u64 timestamp;              
    struct snapshot_device *sdev;       
    char snapshot_dir[PATH_MAX];
    struct mutex dir_mtx;
    struct xarray saved_blocks;   
    struct list_head list;
    atomic_t ref_count;
} snapshot_session;

/**
 * struct snapshot_device - Represents a snapshot device
 * @name: Device name (canonical key)
 * @snapshot_active: Flag indicating if snapshot is active
 * @list: List head for linking devices
 * @rcu: RCU head used for lockless readers
 * @lock: Spinlock to protect access to sessions list
 * @sessions: List of active sessions
 * @bdev: Associated block device (if mounted)
 */
typedef struct snapshot_device {
    char name[MAX_DEV_LEN];
    bool snapshot_active;
    struct list_head list;
    struct rcu_head rcu;
    spinlock_t lock;             
    struct list_head sessions;
    struct block_device *bdev;
} snapshot_device;


/**
 * struct mount_work - Work structure for async mount handling
 * @work: Work queue item
 * @bdev: Block device being mounted
 * @key: Device key (canonical path)
 */
struct mount_work {
    struct work_struct work;
    struct block_device *bdev;
    snapshot_device *sdev;
};

/* Core snapshot functions */
void store_key_from_bdev(struct block_device *bdev, char *out, size_t len);
int start_session_for_bdev(snapshot_device *sdev, struct block_device *bdev, u64 *out_ts);
int stop_sessions_for_bdev(snapshot_device *sdev);

/* Session management */
snapshot_session *create_session(snapshot_device *sdev, u64 timestamp);
void destroy_session(snapshot_session *session);
snapshot_session *find_session_by_timestamp(snapshot_device *sdev, u64 timestamp);

/* Block tracking */
int save_block_to_session(snapshot_session *session, sector_t sector, 
                          const void *data, size_t size);
bool is_block_saved(snapshot_session *session, sector_t sector);

/* Workqueue initialization */
int snapshot_init(void);
void snapshot_exit(void);


#endif
