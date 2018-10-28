#pragma once

#include "base.h"
#include "setjmp_64.h"

struct coroutine_thread {
	struct task_struct *task;
	struct kernel_jmp_buf ctx;
	struct list_head co_list;
	struct rw_semaphore co_list_lock;
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

void coroutine_yield(struct coroutine *co);

int coroutine_thread_start(struct coroutine_thread *thread);

void coroutine_thread_stop(struct coroutine_thread *thread);
