/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BBG_TRACING_H_
#define _BBG_TRACING_H_

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/lsm_hooks.h>

struct bbg_cred_security_struct {
	unsigned is_untrusted_process:1;	/* execve from su */
};

extern struct lsm_blob_sizes bbg_blob_sizes;

static inline struct bbg_cred_security_struct *bbg_cred(const struct cred *cred)
{
	return cred->security + bbg_blob_sizes.lbs_cred;
}

static inline int current_process_trusted(void)
{
	return !bbg_cred(current_cred())->is_untrusted_process;
}

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void bb_cred_transfer(struct cred *new, const struct cred *old);
int bb_bprm_set_creds(struct linux_binprm *bprm);

#endif /* _BBG_TRACING_H_ */
