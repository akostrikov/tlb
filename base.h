#pragma once

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/mutex.h>
#include <linux/bitmap.h>
#include <net/sock.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/kobject.h>
#include <linux/zlib.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/rwsem.h>
#include <linux/cdrom.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/sched/task.h>

#define trace(fmt, ...)    \
                pr_info("tlb: %d: %s(),%d: " fmt, current->pid, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define trace_err(fmt, ...)    \
                pr_err("tlb: %d: %s(),%d: " fmt, current->pid, __FUNCTION__, __LINE__, ##__VA_ARGS__)

