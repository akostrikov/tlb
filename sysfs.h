#pragma once


#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/completion.h>

struct tlb_kobject_holder {
	struct kobject kobj;
	struct completion completion;
	atomic_t deiniting;
};

extern struct kobj_type tlb_ktype;

int tlb_sysfs_init(struct tlb_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...);

void tlb_sysfs_deinit(struct tlb_kobject_holder *holder);
