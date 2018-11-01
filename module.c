#include "module.h"
#include "sysfs.h"
#include "server.h"

static struct tlb_context g_context;

static int __init tlb_init(void)
{
	int r;

	trace("initing\n");

	tlb_server_init(&g_context.srv);
	r = tlb_sysfs_init(&g_context.kobj_holder, fs_kobj, &tlb_ktype, "%s", "tlb");

	trace("inited r %d\n", r);
	return r;
}

static void __exit tlb_exit(void)
{
	trace("exiting\n");

	tlb_sysfs_deinit(&g_context.kobj_holder);
	tlb_server_stop(&g_context.srv);

	trace("exited\n");
}

module_init(tlb_init)
module_exit(tlb_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("");
MODULE_LICENSE("GPL");
