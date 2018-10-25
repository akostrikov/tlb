#include "kcor_base.h"

struct kcor_thread {
	struct task_struct *task;
};

struct kcor_context {
	struct kcor_thread thread;
};

static struct kcor_context g_kcor_context;

static int kcor_thread_routine(void *data)
{
	struct kcor_thread *thread = (struct kcor_thread *)data;

	kcor_log_info("running thread 0x%px\n", thread);

	while (!kthread_should_stop()) {
		msleep(100);
	}
	kcor_log_info("stopping thread 0x%px\n", thread);

	return 0;
}

static int kcor_thread_start(struct kcor_thread *thread)
{
	struct task_struct *task;

	task = kthread_create(kcor_thread_routine, thread, "kcor_thread");
	if (IS_ERR(task))
		return PTR_ERR(task);

	get_task_struct(task);
	thread->task = task;
	wake_up_process(task);

	return 0;
}

static void kcor_thread_stop(struct kcor_thread *thread)
{
	kthread_stop(thread->task);
	put_task_struct(thread->task);
}

static int kcor_context_start(struct kcor_context *ctx)
{
	return kcor_thread_start(&ctx->thread);
}

static void kcor_context_stop(struct kcor_context *ctx)
{
	kcor_thread_stop(&ctx->thread);	
}

static int __init kcor_module_init(void)
{
	int r;

	kcor_log_info("initing\n");

	r = kcor_context_start(&g_kcor_context);

	kcor_log_info("inited r %d\n", r);
	return r;
}

static void __exit kcor_module_exit(void)
{
	kcor_log_info("exiting\n");

	kcor_context_stop(&g_kcor_context);

	kcor_log_info("exited\n");
}

module_init(kcor_module_init)
module_exit(kcor_module_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Kernel coroutines");
MODULE_LICENSE("GPL");
