// SPDX-License-Identifier: GPL-2.0
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/string.h>

#include "tracing.h"

struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct bbg_cred_security_struct),
};

/*
 * SELinux domains a root implementation transitions into on execve.  A
 * process that passes through one of these, and every process it later
 * forks or execs, is treated as untrusted.
 */
static const char * const bbg_root_contexts[] = {
	"u:r:su:s0",		/* KernelSU (legacy), APatch */
	"u:r:ksu:s0",		/* KernelSU (current) */
	"u:r:magisk:s0",	/* Magisk */
};

static u32 bbg_root_sids[ARRAY_SIZE(bbg_root_contexts)];
static bool bbg_root_sids_valid;

/*
 * Resolve the contexts once, the first time a lookup happens after the
 * policy has been loaded.  Racing callers compute identical values, so the
 * array contents never disagree.
 *
 * A policy reload can in principle renumber these SIDs.  Android loads its
 * policy once during early init, so this is not handled.
 */
static bool bbg_is_root_domain(u32 secid)
{
	unsigned int i;

	if (!secid)
		return false;

	/*
	 * Pairs with the smp_store_release() below: a reader that sees the
	 * flag set must also see every bbg_root_sids[] store before it.
	 */
	if (!smp_load_acquire(&bbg_root_sids_valid)) {
		u32 sids[ARRAY_SIZE(bbg_root_contexts)];
		bool resolved_any = false;

		for (i = 0; i < ARRAY_SIZE(bbg_root_contexts); i++) {
			const char *ctx = bbg_root_contexts[i];

			if (security_secctx_to_secid(ctx, strlen(ctx), &sids[i]))
				sids[i] = 0;
			else
				resolved_any = true;
		}

		/* No policy yet: nothing can be in a root domain either. */
		if (!resolved_any)
			return false;

		for (i = 0; i < ARRAY_SIZE(bbg_root_contexts); i++)
			bbg_root_sids[i] = sids[i];

		/* Publish the table before the flag that advertises it. */
		smp_store_release(&bbg_root_sids_valid, true);
	}

	for (i = 0; i < ARRAY_SIZE(bbg_root_contexts); i++)
		if (secid == bbg_root_sids[i])
			return true;

	return false;
}

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	*bbg_cred(new) = *bbg_cred(old);
	return 0;
}

void bb_cred_transfer(struct cred *new, const struct cred *old)
{
	*bbg_cred(new) = *bbg_cred(old);
}

int bb_bprm_set_creds(struct linux_binprm *bprm)
{
	struct bbg_cred_security_struct *new_tsec = bbg_cred(bprm->cred);
	u32 old_sid, new_sid;

	new_tsec->is_untrusted_process =
		bbg_cred(current_cred())->is_untrusted_process;

	/* Already inherited the mark, no need to look at the domain. */
	if (new_tsec->is_untrusted_process)
		return 0;

	/*
	 * baseband_guard is ordered after selinux in CONFIG_LSM, so by the
	 * time this runs selinux has already stamped the post-exec SID onto
	 * bprm->cred.  Checking the old and the new SID therefore covers
	 * both "exec issued from a root domain" and "exec transitions into
	 * one".
	 */
	security_cred_getsecid(current_cred(), &old_sid);
	security_cred_getsecid(bprm->cred, &new_sid);

	if (!bbg_is_root_domain(old_sid) && !bbg_is_root_domain(new_sid))
		return 0;

	new_tsec->is_untrusted_process = 1;
	pr_info("baseband_guard: pid %d marked untrusted by SELinux domain\n",
		current->pid);

	return 0;
}
