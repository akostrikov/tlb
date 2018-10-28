#include "base.h"
#include "tlb_server.h"

struct tlb_context {
	struct tlb_server srv;
};

static struct tlb_context g_context;

static int __init tlb_init(void)
{
	int r;

	trace("initing\n");

	r = tlb_server_start(&g_context.srv, "0.0.0.0", 51111);

	trace("inited r %d\n", r);
	return r;
}

static void __exit tlb_exit(void)
{
	trace("exiting\n");

	tlb_server_stop(&g_context.srv);

	trace("exited\n");
}

module_init(tlb_init)
module_exit(tlb_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("");
MODULE_LICENSE("GPL");
