#include "sysfs.h"
#include "module.h"

#include <linux/sysfs.h>

#define TLB_ATTR_RO(_name) \
struct tlb_sysfs_attr tlb_attr_##_name = \
	__ATTR(_name, S_IRUGO, tlb_attr_##_name##_show, NULL)

#define TLB_ATTR_RW(_name) \
struct tlb_sysfs_attr tlb_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, tlb_attr_##_name##_show, \
		tlb_attr_##_name##_store)

struct tlb_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct tlb_context *, char *);
	ssize_t (*store)(struct tlb_context *, const char *, size_t count);
};

static struct completion *tlb_get_completion_from_kobject(struct kobject *kobj)
{
	return &container_of(kobj,
		struct tlb_kobject_holder, kobj)->completion;
}

static void tlb_kobject_release(struct kobject *kobj)
{
	complete(tlb_get_completion_from_kobject(kobj));
}

static struct tlb_context *tlb_from_kobject(struct kobject *kobj)
{
	return container_of(kobj, struct tlb_context, kobj_holder.kobj);
}

int tlb_sysfs_init(struct tlb_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...)
{
	char name[256];
	va_list args;

	ktype->release = tlb_kobject_release;

	init_completion(&holder->completion);

	va_start(args, fmt);
	vsnprintf(name, ARRAY_SIZE(name), fmt, args);
	va_end(args);

	return kobject_init_and_add(&holder->kobj, ktype, root, "%s", name);
}

void tlb_sysfs_deinit(struct tlb_kobject_holder *holder)
{
	struct kobject *kobj = &holder->kobj;

	if (atomic_cmpxchg(&holder->deiniting, 0, 1) == 0) {
		kobject_put(kobj);
		wait_for_completion(tlb_get_completion_from_kobject(kobj));
	}
}

static ssize_t tlb_attr_start_server_store(struct tlb_context *tlb,
					const char *buf, size_t count)
{
	char host[64];
	int r, port;

	r = sscanf(buf, "%63s %d", host, &port);
	if (r != 2)
		return -EINVAL;

	r = tlb_server_start(&tlb->srv, host, port);
	if (r)
		return r;

	return count;
}

static ssize_t tlb_attr_start_server_show(struct tlb_context *tlb,
				     char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "\n");
}

static ssize_t tlb_attr_stop_server_store(struct tlb_context *tlb,
					const char *buf, size_t count)
{
	int r;
	
	r = tlb_server_stop(&tlb->srv);
	if (r)
		return r;

	return count;
}

static ssize_t tlb_attr_stop_server_show(struct tlb_context *tlb,
				     char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "\n");
}

static ssize_t tlb_attr_add_target_store(struct tlb_context *tlb,
					  const char *buf, size_t count)
{
	char host[64];
	int r, port;

	r = sscanf(buf, "%63s %d", host, &port);
	if (r != 2)
		return -EINVAL;

	host[63] = '\0';
	r = tlb_server_add_target(&tlb->srv, host, port);
	if (r)
		return r;

	return count;
}

static ssize_t tlb_attr_remove_target_store(struct tlb_context *tlb,
					  const char *buf, size_t count)
{
	char host[64];
	int r, port;

	r = sscanf(buf, "%63s %d", host, &port);
	if (r != 2)
		return -EINVAL;

	host[63] = '\0';
	r = tlb_server_remove_target(&tlb->srv, host, port);
	if (r)
		return r;

	return count;
}

static ssize_t tlb_attr_add_target_show(struct tlb_context *tlb,
					 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "\n");
}


static ssize_t tlb_attr_remove_target_show(struct tlb_context *tlb,
					 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "\n");
}

static ssize_t tlb_attr_targets_show(struct tlb_context *tlb,
					char *buf)
{
	struct tlb_server *srv = &tlb->srv;
	struct tlb_target *target;
	int r, off;
	u64 con_time_p50, con_time_p75, con_time_p90, con_time_p99, con_time_p995;

	read_lock(&srv->target_lock);
	off = 0;
	target = tlb_server_next_target(srv, NULL);
	while (target) {
		if (off >= PAGE_SIZE)
			goto fail_nomem;

		con_time_p995 = con_time_p99 = con_time_p90 = con_time_p75 = con_time_p50 = 0;
		spin_lock(&target->lock);
		if (resample_count(&target->con_time_sample) == 1000) {
			resample_sort(&target->con_time_sample);
			con_time_p50 = resample_get(&target->con_time_sample, 500);
			con_time_p75 = resample_get(&target->con_time_sample, 750);
			con_time_p90 = resample_get(&target->con_time_sample, 900);
			con_time_p99 = resample_get(&target->con_time_sample, 990);
			con_time_p995 = resample_get(&target->con_time_sample, 995);
		}
		spin_unlock(&target->lock);

		r = snprintf(buf + off, PAGE_SIZE - off, "%s %d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
				target->host, target->port, atomic64_read(&target->total_cons), atomic64_read(&target->active_cons),
				target->min_con_time_us, target->max_con_time_us,
				(atomic64_read(&target->total_cons)) ? target->total_con_time_us / atomic64_read(&target->total_cons) : 0,
				con_time_p50, con_time_p75, con_time_p90, con_time_p99, con_time_p995);
		if (r >= (PAGE_SIZE - off))
			goto fail_nomem;

		off += r;
		target = tlb_server_next_target(srv, target);
	}
	read_unlock(&srv->target_lock);
	return off;

fail_nomem:
	tlb_target_put(target);
	read_unlock(&srv->target_lock);
	return -ENOMEM;
}

static ssize_t tlb_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct tlb_sysfs_attr *vattr;
	struct tlb_context *tlb;

	vattr = container_of(attr, struct tlb_sysfs_attr, attr);
	if (!vattr->show)
		return -EIO;

	tlb = tlb_from_kobject(kobj);
	if (!tlb)
		return -EIO;

	return vattr->show(tlb, page);
}

static ssize_t tlb_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct tlb_sysfs_attr *vattr;
	struct tlb_context *tlb;

	vattr = container_of(attr, struct tlb_sysfs_attr, attr);
	if (!vattr->store)
		return -EIO;

	tlb = tlb_from_kobject(kobj);
	if (!tlb)
		return -EIO;

	return vattr->store(tlb, page, count);
}

static TLB_ATTR_RW(start_server);
static TLB_ATTR_RW(stop_server);
static TLB_ATTR_RW(add_target);
static TLB_ATTR_RW(remove_target);
static TLB_ATTR_RO(targets);

static struct attribute *tlb_attrs[] = {
	&tlb_attr_start_server.attr,
	&tlb_attr_stop_server.attr,
	&tlb_attr_add_target.attr,
	&tlb_attr_remove_target.attr,
	&tlb_attr_targets.attr,
	NULL,
};

static const struct sysfs_ops tlb_sysfs_ops = {
	.show	= tlb_attr_show,
	.store	= tlb_attr_store,
};

struct kobj_type tlb_ktype = {
	.sysfs_ops	= &tlb_sysfs_ops,
	.default_attrs	= tlb_attrs,
};
