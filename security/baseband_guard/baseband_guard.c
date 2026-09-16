#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/ratelimit.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"
#include "blkdev_helper.h"

struct device_hash_node {
	dev_t			dev;
	struct hlist_node	h;
};

/*
 * Devices that resolved to an allowlisted partition, cached so the
 * bd_meta_info lookup happens once per device rather than once per write.
 *
 * Readers run from the file_permission hook on every block device write and
 * take nothing but rcu_read_lock(); the spinlock only serialises insertion.
 * Entries are never removed, so no grace period is ever required.  A dev_t
 * reused by a different device would keep the stale verdict, which cannot
 * happen here: only GPT partitions and zram are ever cached and neither is
 * torn down at runtime.
 */
static DEFINE_HASHTABLE(allowed_devs, 7);
static DEFINE_SPINLOCK(allowed_devs_lock);

static bool allow_has(dev_t dev)
{
	struct device_hash_node *p;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(allowed_devs, p, h, (u64)dev) {
		if (p->dev == dev) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

static void allow_add(dev_t dev)
{
	struct device_hash_node *n, *p;

	if (!dev || allow_has(dev))
		return;

	n = kmalloc(sizeof(*n), GFP_ATOMIC | __GFP_NOWARN);
	if (!n)
		return;
	n->dev = dev;

	spin_lock(&allowed_devs_lock);
	hash_for_each_possible(allowed_devs, p, h, (u64)dev) {
		if (p->dev == dev) {
			spin_unlock(&allowed_devs_lock);
			kfree(n);
			return;
		}
	}
	hash_add_rcu(allowed_devs, &n->h, (u64)dev);
	spin_unlock(&allowed_devs_lock);

	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

static bool is_zram_device(dev_t dev)
{
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u identified, whitelisting\n",
				MAJOR(dev), MINOR(dev));
	}
	return is_zram;
}

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_zram_device(cur)) {
		allow_add(cur);
		return true;
	}
	if (is_allowed_partition_dev_resolve(cur)) {
		allow_add(cur);
		return true;
	}
	return false;
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

/*
 * A denied writer usually retries, so the log has to be bounded or a single
 * stuck script scrolls the ring buffer clear of everything that mattered.
 * An explicit ratelimit_state rather than pr_warn_ratelimited() because the
 * path buffer must only be allocated when the message is actually going out.
 */
static DEFINE_RATELIMIT_STATE(bbg_deny_rs, 5 * HZ, 10);

static void bbg_log_deny_detail(const char *why, struct file *file,
				struct inode *inode, unsigned int cmd_opt)
{
	const int PATH_BUFLEN = 256;
	dev_t dev = inode ? inode->i_rdev : 0;
	const char *path = NULL;
	char *pathbuf;

	if (!__ratelimit(&bbg_deny_rs))
		return;

	pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC | __GFP_NOWARN);
	if (pathbuf)
		path = bbg_file_path(file, pathbuf, PATH_BUFLEN);

	if (cmd_opt)
		pr_warn("baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm);
	else
		pr_warn("baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm);

	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	bbg_log_deny_detail(why, file, inode, cmd_opt);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (likely(current_process_trusted()))
		return 0;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, inode, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr)
#endif
{
	struct inode *inode;

	if (current_process_trusted())
		return 0;
	inode = d_inode(dentry);

	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("setattr on protected partition", 0, inode, 0);
}

static inline bool is_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
#ifdef BLKPG
	case BLKPG:
#endif
#ifdef BLKTRIM
	case BLKTRIM:
#endif
#ifdef BLKRRPART
	case BLKRRPART:
#endif
#ifdef BLKSETRO
	case BLKSETRO:
#endif
#ifdef BLKSETBADSECTORS
	case BLKSETBADSECTORS:
#endif
		return true;
	default:
		return false;
	}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	if (likely(current_process_trusted()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("destructive ioctl on protected partition", file, inode, cmd);
}

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
	LSM_HOOK_INIT(inode_setattr, 		bb_inode_setattr),

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
	LSM_HOOK_INIT(bprm_set_creds, 		bb_bprm_set_creds),
#endif
	LSM_HOOK_INIT(cred_transfer, 		bb_cred_transfer),
	LSM_HOOK_INIT(cred_prepare, 	    bb_cred_prepare),

#ifdef BB_HAS_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
	pr_info("baseband_guard: version %s active\n", BBG_VERSION);
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
	.blobs = &bbg_blob_sizes
};

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");
