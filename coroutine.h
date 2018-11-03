#pragma once

#include "base.h"
#include "setjmp_64.h"

#define COROUTINE_MAGIC			0xCBDACBDA
#define COROUTINE_STACK_BOTTOM_MAGIC	0x0BEDABEDAUL
#define COROUTINE_STACK_TOP_MAGIC		0x0CCCCCCCCUL

#define COROUTINE_PAGE_SIZE 4096UL
#define COROUTINE_PAGE_SHIFT 12UL

#define COROUTINE_STACK_SHIFT ((ulong)(COROUTINE_PAGE_SHIFT + 2))
#define COROUTINE_STACK_SIZE (1UL << COROUTINE_STACK_SHIFT)

struct coroutine_thread {
	struct task_struct *task;
	struct kernel_jmp_buf ctx;
	struct list_head co_list;
	spinlock_t co_list_lock;
	struct wait_queue_head waitq;
	bool stopping;
	atomic_t signaled;
};

struct coroutine {
	struct kernel_jmp_buf ctx;
	struct coroutine_thread *thread;
	struct list_head co_list_entry;
	void *stack;
	void *arg;
	void *ret;
	void* (*fun)(struct coroutine *co, void *arg);
	bool running;
	int magic;
	atomic_t ref_count;
};

struct coroutine *coroutine_create(struct coroutine_thread *thread);

void coroutine_ref(struct coroutine *co);

void coroutine_deref(struct coroutine *co);

void coroutine_start(struct coroutine *co, void* (*fun)(struct coroutine *co, void* arg), void *arg);

static void __always_inline coroutine_yield(struct coroutine *co)
{
	BUG_ON(co->magic != COROUTINE_MAGIC);
	
	if (kernel_setjmp(&co->ctx) == 0)
		kernel_longjmp(&co->thread->ctx, 0x1);
}


void coroutine_signal(struct coroutine *co);

void coroutine_cancel(struct coroutine *co);

void* coroutine_wait(struct coroutine *self, struct coroutine *co);

int coroutine_thread_start(struct coroutine_thread *thread);

void coroutine_thread_stop(struct coroutine_thread *thread);
