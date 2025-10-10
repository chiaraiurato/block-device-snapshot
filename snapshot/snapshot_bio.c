#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include "include/snapshot.h"
#include "../register/include/register.h"


#define COW_SECT_PER_BLK    (COW_BLK_SZ / COW_SECT_SZ)
#define ALIGN_DOWN_SECT(s)  ((s) & ~((sector_t)COW_SECT_PER_BLK - 1))
#define ALIGN_UP_SECT(s)    (((s) + COW_SECT_PER_BLK - 1) & ~((sector_t)COW_SECT_PER_BLK - 1))

static struct workqueue_struct *snapshot_bio_wq;

// TODO: Refactor this struct 
struct preimage_work {
    struct work_struct work;
    snapshot_session *ses;
    struct block_device *bdev;
    sector_t key;      
    unsigned int size; 
};



static int submit_bio_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct bio *bio = (struct bio *)regs->di;
    snapshot_device *sdev;
    snapshot_session *ses;

    if (!bio || !bio->bi_bdev) return 0;
    if (!op_is_write(bio_op(bio))) return 0; /* solo WRITE */

    sdev = find_device_for_bdev(bio->bi_bdev);
    if (!sdev || !READ_ONCE(sdev->snapshot_active) ||
        READ_ONCE(sdev->bdev) != bio->bi_bdev)
        return 0;

    ses = get_active_session_rcu(sdev);
    if (!ses) return 0;

    pr_info_ratelimited("SNAPSHOT: submit_bio WRITE dev=%s secs=%llu len=%u\n",
        bio->bi_bdev->bd_disk ? bio->bi_bdev->bd_disk->disk_name : "?",
        (unsigned long long)bio->bi_iter.bi_sector,
        bio->bi_iter.bi_size);

    // /* best-effort: non blocchiamo il write */
    // schedule_preimages_for_bio(ses, bio->bi_bdev, bio);
    // put_session(ses);
    return 0;
}


static struct kprobe kp_submit_bio          = { .symbol_name = "submit_bio",          .pre_handler = submit_bio_pre };

int install_bio_kprobe(void)
{
    int ret;

    snapshot_bio_wq = alloc_workqueue("snapshot_bio_kp_wq",
                                      WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!snapshot_bio_wq) return -ENOMEM;

    ret = register_kprobe(&kp_submit_bio);
    if (!ret) { pr_info("SNAPSHOT: kprobe submit_bio\n"); return 0; }

    destroy_workqueue(snapshot_bio_wq);
    snapshot_bio_wq = NULL;
    pr_err("SNAPSHOT: no submit_bio* symbol hookable (ret=%d)\n", ret);
    return ret;
}

void remove_bio_kprobe(void)
{
    unregister_kprobe(&kp_submit_bio);

    if (snapshot_bio_wq) {
        flush_workqueue(snapshot_bio_wq);
        destroy_workqueue(snapshot_bio_wq);
        snapshot_bio_wq = NULL;
    }
    pr_info("SNAPSHOT: BIO kprobe removed\n");
}
