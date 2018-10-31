#include "coroutine.h"

#define COROUTINE_MAGIC			0xCBDACBDA
#define COROUTINE_STACK_BOTTOM_MAGIC	0x0BEDABEDAUL
#define COROUTINE_STACK_TOP_MAGIC		0x0CCCCCCCCUL

#define COROUTINE_PAGE_SIZE 4096UL
#define COROUTINE_PAGE_SHIFT 12UL

#define COROUTINE_STACK_SHIFT ((ulong)(COROUTINE_PAGE_SHIFT + 2))
#define COROUTINE_STACK_SIZE (1UL << COROUTINE_STACK_SHIFT)

struct coroutine *coroutine_create(struct coroutine_thread *thread)
{
	struct coroutine *co;

	co = kmalloc(sizeof(*co), GFP_KERNEL);
	if (!co)
		return NULL;
	memset(co, 0, sizeof(*co));
	co->magic = COROUTINE_MAGIC;
	co->thread = thread;
	co->stack = kmalloc(COROUTINE_STACK_SIZE, GFP_KERNEL);
	atomic_set(&co->ref_count, 1);
	atomic_set(&co->signaled, 0);
	INIT_LIST_HEAD(&co->co_list_entry);
	if (!co->stack) {
		kfree(co);
		return NULL;
	}
	BUG_ON((ulong)co->stack & (COROUTINE_PAGE_SIZE - 1));

	*(ulong *)((ulong)co->stack) = COROUTINE_STACK_BOTTOM_MAGIC;
	*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) = COROUTINE_STACK_TOP_MAGIC;
	*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong)) = (ulong)co;


	trace("co create 0x%px stack 0x%px\n", co, co->stack);

	return co;
}

void coroutine_ref(struct coroutine *co)
{
	atomic_inc(&co->ref_count);
}

static void coroutine_delete(struct coroutine *co)
{
	struct coroutine_thread *thread = co->thread;

	BUG_ON(co->magic != COROUTINE_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack) != COROUTINE_STACK_BOTTOM_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) != COROUTINE_STACK_TOP_MAGIC);
	BUG_ON(atomic_read(&co->ref_count) != 0);

	trace("co delete 0x%px stack 0x%px\n", co, co->stack);

	spin_lock(&thread->co_list_lock);
	list_del_init(&co->co_list_entry);
	spin_unlock(&thread->co_list_lock);

	kfree(co->stack);
	kfree(co);
}

void coroutine_deref(struct coroutine *co)
{
	if (atomic_dec_and_test(&co->ref_count))
			coroutine_delete(co);
}


void coroutine_yield(struct coroutine *co)
{
	BUG_ON(co->magic != COROUTINE_MAGIC);
	
	if (kernel_setjmp(&co->ctx) == 0)
		kernel_longjmp(&co->thread->ctx, 0x1);
}

static void coroutine_trampoline(void)
{
	ulong rsp = kernel_get_rsp();
	ulong stack = (rsp >>  COROUTINE_STACK_SHIFT) << COROUTINE_STACK_SHIFT;
	struct coroutine *co;

	co = (struct coroutine *)(*(ulong *)(stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong)));

	trace("co 0x%px rsp 0x%lx stack 0x%lx\n", co, rsp, stack);

	BUG_ON(co->magic != COROUTINE_MAGIC);	
	BUG_ON(*(ulong *)((ulong)co->stack) != COROUTINE_STACK_BOTTOM_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) != COROUTINE_STACK_TOP_MAGIC);

	co->ret = co->fun(co, co->arg);

	BUG_ON(co->magic != COROUTINE_MAGIC);	
	BUG_ON(*(ulong *)((ulong)co->stack) != COROUTINE_STACK_BOTTOM_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) != COROUTINE_STACK_TOP_MAGIC);

	co->running = false;
	coroutine_yield(co);
}

void coroutine_start(struct coroutine *co, void* (*fun)(struct coroutine *co, void* arg), void *arg)
{
	struct coroutine_thread *thread = co->thread;

	BUG_ON(co->magic != COROUTINE_MAGIC);
	
	co->fun = fun;
	co->arg = arg;
	co->ctx.rip = (ulong)coroutine_trampoline;	
	co->ctx.rsp = (ulong)co->stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong);
	co->running = true;

	trace("co 0x%px start\n", co);

	coroutine_ref(co);
	spin_lock(&thread->co_list_lock);
	list_add_tail(&co->co_list_entry, &thread->co_list);
	spin_unlock(&thread->co_list_lock);

	coroutine_signal(co);
}

static void coroutine_enter(struct coroutine *co)
{
	BUG_ON(co->magic != COROUTINE_MAGIC);
	BUG_ON(!co->running);

	if (kernel_setjmp(&co->thread->ctx) == 0)
		kernel_longjmp(&co->ctx, 0x1);
}

void coroutine_signal(struct coroutine *co)
{
	atomic_cmpxchg(&co->signaled, 0, 1);
	atomic_inc(&co->thread->signaled);
	wake_up_interruptible(&co->thread->waitq);
}

static struct coroutine *coroutine_thread_next_coroutine(struct coroutine_thread *thread, struct coroutine *prev_co)
{
	struct list_head *list_entry;
	struct coroutine *co;

	spin_lock(&thread->co_list_lock);
	list_entry = (prev_co) ? prev_co->co_list_entry.next : thread->co_list.next;
	while (list_entry != &thread->co_list) {
		co = container_of(list_entry, struct coroutine, co_list_entry);
		if (atomic_cmpxchg(&co->signaled, 1, 0) == 1 && atomic_inc_not_zero(&co->ref_count)) {
			spin_unlock(&thread->co_list_lock);
			if (prev_co)
				coroutine_deref(prev_co);
			return co;
		}
		list_entry = list_entry->next;
	}
	spin_unlock(&thread->co_list_lock);
	if (prev_co)
		coroutine_deref(prev_co);
	return NULL;
}

static int coroutine_thread_routine(void *data)
{
	struct coroutine_thread *thread = (struct coroutine_thread *)data;
	struct coroutine *co, *next_co;

	trace("co thread 0x%px enter\n", thread);

	for (;;) {
		wait_event_interruptible(thread->waitq, (thread->stopping || atomic_read(&thread->signaled)));
		if (thread->stopping)
			break;

		atomic_set(&thread->signaled, 0);
		co = coroutine_thread_next_coroutine(thread, NULL);
		while (co != NULL) {
			coroutine_enter(co);
			next_co = coroutine_thread_next_coroutine(thread, co);
			if (!co->running) {
				spin_lock(&thread->co_list_lock);
				BUG_ON(list_empty(&co->co_list_entry));
				list_del_init(&co->co_list_entry);
				spin_unlock(&thread->co_list_lock);
				coroutine_deref(co);
			}
			co = next_co;
		}
	}
	trace("co thread 0x%px leave\n", thread);

	return 0;
}

int coroutine_thread_start(struct coroutine_thread *thread)
{
	struct task_struct *task;

	memset(thread, 0, sizeof(*thread));
	spin_lock_init(&thread->co_list_lock);
	INIT_LIST_HEAD(&thread->co_list);
	init_waitqueue_head(&thread->waitq);
	thread->stopping = false;
	atomic_set(&thread->signaled, 0);

	task = kthread_create(coroutine_thread_routine, thread, "coroutine");
	if (IS_ERR(task))
		return PTR_ERR(task);

	get_task_struct(task);
	thread->task = task;
	wake_up_process(task);

	return 0;
}

void coroutine_thread_stop(struct coroutine_thread *thread)
{
	struct coroutine *co, *co_tmp;
	struct list_head co_list;

	thread->stopping = true;
	wake_up_interruptible(&thread->waitq);
	kthread_stop(thread->task);

	INIT_LIST_HEAD(&co_list);
	spin_lock(&thread->co_list_lock);
	list_splice_init(&thread->co_list, &co_list);
	spin_unlock(&thread->co_list_lock);

	list_for_each_entry_safe(co, co_tmp, &co_list, co_list_entry) {
		list_del_init(&co->co_list_entry);
		coroutine_deref(co);	
	}
	put_task_struct(thread->task);
}
