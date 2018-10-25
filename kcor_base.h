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

#define kcor_log_info(fmt, ...)    \
                pr_info("kcor: " fmt, ##__VA_ARGS__)

#define kcor_log_error(fmt, ...)    \
                pr_err("kcor: " fmt, ##__VA_ARGS__)

