#include "module.h"
#include "sysfs.h"
#include "server.h"

static struct tlb_context g_context;

static int __init tlb_init(void)
{
	int r;

	pr_info("tlb: initing\n");

	r = coroutine_init();
	if (r)
		goto fail;

	r = tlb_server_cache_init();
	if (r)
		goto fail_coroutine_deinit;

	r = tlb_server_init(&g_context.srv);
	if (r)
		goto fail_server_cache_deinit;

	r = tlb_sysfs_init(&g_context.kobj_holder, fs_kobj, &tlb_ktype, "%s", "tlb");
	if (r)
		goto fail_server_deinit;

	pr_info("tlb: inited r %d\n", r);
	return r;

fail_server_deinit:
	tlb_server_stop(&g_context.srv);
fail_server_cache_deinit:
	tlb_server_cache_deinit();
fail_coroutine_deinit:
	coroutine_deinit();
fail:
	pr_err("tlb: inited r %d\n", r);
	return r;
}

static void __exit tlb_exit(void)
{
	pr_info("tlb: exiting\n");

	tlb_sysfs_deinit(&g_context.kobj_holder);
	tlb_server_stop(&g_context.srv);
	tlb_server_cache_deinit();
	coroutine_deinit();
	pr_info("tlb: exited\n");
}

module_init(tlb_init)
module_exit(tlb_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Tcp connection based load balancer");
MODULE_LICENSE("GPL");
