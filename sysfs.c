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
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
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
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
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
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}


static ssize_t tlb_attr_remove_target_show(struct tlb_context *tlb,
					 char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
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

static struct attribute *tlb_attrs[] = {
	&tlb_attr_start_server.attr,
	&tlb_attr_stop_server.attr,
	&tlb_attr_add_target.attr,
	&tlb_attr_remove_target.attr,
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
