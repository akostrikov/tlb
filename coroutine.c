#include "coroutine.h"
#include "trace.h"

struct coroutine_thread_work {
	struct coroutine *co;
	struct list_head list_entry;
};

struct coroutine *coroutine_create(struct coroutine_thread *thread)
{
	struct coroutine *co;

	co = kmalloc(sizeof(*co), GFP_KERNEL);
	if (!co)
		return NULL;
	memset(co, 0, sizeof(*co));
	mutex_init(&co->lock);
	co->magic = COROUTINE_MAGIC;
	co->thread = thread;
	co->stack = kmalloc(COROUTINE_STACK_SIZE, GFP_KERNEL);
	co->state = COROUTINE_INITED;
	atomic_set(&co->ref_count, 1);
	if (!co->stack) {
		kfree(co);
		return NULL;
	}
	BUG_ON((ulong)co->stack & (COROUTINE_PAGE_SIZE - 1));

	*(ulong *)((ulong)co->stack) = COROUTINE_STACK_BOTTOM_MAGIC;
	*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) = COROUTINE_STACK_TOP_MAGIC;
	*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong)) = (ulong)co;

	trace_coroutine_create(co, co->stack, thread);
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

	trace_coroutine_delete(co, co->stack, thread);

	kfree(co->stack);
	kfree(co);
}

void coroutine_deref(struct coroutine *co)
{
	if (atomic_dec_and_test(&co->ref_count))
			coroutine_delete(co);
}

static void coroutine_trampoline(void)
{
	ulong rsp = kernel_get_rsp();
	ulong stack = (rsp >>  COROUTINE_STACK_SHIFT) << COROUTINE_STACK_SHIFT;
	struct coroutine *co;

	co = (struct coroutine *)(*(ulong *)(stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong)));

	BUG_ON(co->magic != COROUTINE_MAGIC);	
	BUG_ON(co->state != COROUTINE_RUNNING);
	BUG_ON(*(ulong *)((ulong)co->stack) != COROUTINE_STACK_BOTTOM_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) != COROUTINE_STACK_TOP_MAGIC);

	co->ret = co->fun(co, co->arg);

	BUG_ON(co->magic != COROUTINE_MAGIC);	
	BUG_ON(co->state != COROUTINE_RUNNING);
	BUG_ON(*(ulong *)((ulong)co->stack) != COROUTINE_STACK_BOTTOM_MAGIC);
	BUG_ON(*(ulong *)((ulong)co->stack + COROUTINE_STACK_SIZE - sizeof(ulong)) != COROUTINE_STACK_TOP_MAGIC);

	mb();
	co->state = COROUTINE_EXITED;
	coroutine_yield(co);
}

void coroutine_start(struct coroutine *co, void* (*fun)(struct coroutine *co, void* arg), void *arg)
{
	BUG_ON(co->magic != COROUTINE_MAGIC);

	mutex_lock(&co->lock);
	BUG_ON(co->state != COROUTINE_INITED);
	co->fun = fun;
	co->arg = arg;
	co->ctx.rip = (ulong)coroutine_trampoline;	
	co->ctx.rsp = (ulong)co->stack + COROUTINE_STACK_SIZE - 2 * sizeof(ulong);
	co->state = COROUTINE_READY;
	mutex_unlock(&co->lock);

	coroutine_signal(co);
}

static __always_inline void coroutine_enter(struct coroutine *co)
{
	BUG_ON(co->magic != COROUTINE_MAGIC);
	BUG_ON(co->state != COROUTINE_RUNNING);

	trace_coroutine_enter(co);
	if (kernel_setjmp(&co->thread->ctx) == 0)
		kernel_longjmp(&co->ctx, 0x1);
	trace_coroutine_enter_return(co);
}

void coroutine_signal(struct coroutine *co)
{
	struct coroutine_thread *thread = co->thread;
	struct coroutine_thread_work *work;
	unsigned long flags;


	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;

	coroutine_ref(co);
	work->co = co;

	spin_lock_irqsave(&thread->work_list_lock, flags);
	list_add_tail(&work->list_entry, &thread->work_list);
	spin_unlock_irqrestore(&thread->work_list_lock, flags);

	wake_up_interruptible(&thread->waitq);
}

void coroutine_cancel(struct coroutine *co)
{
	mutex_lock(&co->lock);
	if (co->state == COROUTINE_READY)
		co->state = COROUTINE_CANCELED;
	else
		BUG_ON(co->state != COROUTINE_RUNNING && co->state != COROUTINE_EXITED);
	mutex_unlock(&co->lock);
}

static int coroutine_thread_routine(void *data)
{
	struct coroutine_thread *thread = (struct coroutine_thread *)data;
	struct coroutine *co;
	struct coroutine_thread_work *work, *work_tmp;
	struct list_head work_list;
	unsigned long flags;

	for (;;) {
		trace_coroutine_thread_wait(thread);
		wait_event_interruptible(thread->waitq, (thread->stopping || !list_empty(&thread->work_list)));
		trace_coroutine_thread_wait_return(thread);
		if (thread->stopping)
			break;

		if (list_empty(&thread->work_list))
			continue;

		INIT_LIST_HEAD(&work_list);
		spin_lock_irqsave(&thread->work_list_lock, flags);
		list_splice_init(&thread->work_list, &work_list);
		spin_unlock_irqrestore(&thread->work_list_lock, flags);

		list_for_each_entry_safe(work, work_tmp, &work_list, list_entry) {
			list_del_init(&work->list_entry);
			co = work->co;
			mutex_lock(&co->lock);
			if (co->state == COROUTINE_READY) {
				co->state = COROUTINE_RUNNING;
				coroutine_enter(co);
				if (co->state == COROUTINE_RUNNING)
					co->state = COROUTINE_READY;
				else
					BUG_ON(co->state != COROUTINE_EXITED);
			}
			mutex_unlock(&co->lock);
			coroutine_deref(co);
			kfree(work);
		}
	}

	return 0;
}

int coroutine_thread_start(struct coroutine_thread *thread, const char *name, unsigned int cpu)
{
	struct task_struct *task;

	memset(thread, 0, sizeof(*thread));
	spin_lock_init(&thread->work_list_lock);
	INIT_LIST_HEAD(&thread->work_list);
	init_waitqueue_head(&thread->waitq);
	thread->stopping = false;

	task = kthread_create(coroutine_thread_routine, thread, "%s-%u", name, cpu);
	if (IS_ERR(task))
		return PTR_ERR(task);

	kthread_bind(task, cpu);
	get_task_struct(task);
	thread->task = task;
	thread->cpu = cpu;
	wake_up_process(task);

	return 0;
}

void coroutine_thread_stop(struct coroutine_thread *thread)
{
	struct coroutine_thread_work *work, *work_tmp;
	struct list_head work_list;
	unsigned long flags;

	thread->stopping = true;
	wake_up_interruptible(&thread->waitq);
	kthread_stop(thread->task);

	INIT_LIST_HEAD(&work_list);
	spin_lock_irqsave(&thread->work_list_lock, flags);
	list_splice_init(&thread->work_list, &work_list);
	spin_unlock_irqrestore(&thread->work_list_lock, flags);

	list_for_each_entry_safe(work, work_tmp, &work_list, list_entry) {
		list_del_init(&work->list_entry);
		coroutine_deref(work->co);
		kfree(work);
	}

	put_task_struct(thread->task);
}
