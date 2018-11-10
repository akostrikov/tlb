#if !defined(_TRACE_TLB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TLB_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM tlbtrace

TRACE_EVENT(coroutine_create,
	TP_PROTO(void* co, void* stack, void* thread),
	TP_ARGS(co, stack, thread),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(void*, stack)
		__field(void*, thread)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->stack = stack;
		__entry->thread = thread;
	),

	TP_printk("co 0x%px stack 0x%px thread 0x%px", __entry->co, __entry->stack, __entry->thread)
);

TRACE_EVENT(coroutine_delete,
	TP_PROTO(void* co, void* stack, void* thread),
	TP_ARGS(co, stack, thread),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(void*, stack)
		__field(void*, thread)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->stack = stack;
		__entry->thread = thread;
	),

	TP_printk("co 0x%px stack 0x%px thread 0x%px", __entry->co, __entry->stack, __entry->thread)
);

TRACE_EVENT(con_create,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(con_delete,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(con_co_enter,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(con_co_leave,
	TP_PROTO(void* con, void *co, int r),
	TP_ARGS(con, co, r),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
		__field(int, r)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
		__entry->r = r;
	),

	TP_printk("con 0x%px co 0x%px r %d", __entry->con, __entry->co, __entry->r)
);

TRACE_EVENT(con_state_change,
	TP_PROTO(void* con, int state),
	TP_ARGS(con, state),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(int, state)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->state = state;
	),

	TP_printk("con 0x%px state %d", __entry->con, __entry->state)
);


TRACE_EVENT(target_con_create,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(target_con_delete,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(target_con_co_enter,
	TP_PROTO(void* con, void *co),
	TP_ARGS(con, co),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
	),

	TP_printk("con 0x%px co 0x%px", __entry->con, __entry->co)
);

TRACE_EVENT(target_con_co_leave,
	TP_PROTO(void* con, void *co, int r),
	TP_ARGS(con, co, r),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(void*, co)
		__field(int, r)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->co = co;
		__entry->r = r;
	),

	TP_printk("con 0x%px co 0x%px r %d", __entry->con, __entry->co, __entry->r)
);

TRACE_EVENT(target_con_state_change,
	TP_PROTO(void* con, int state),
	TP_ARGS(con, state),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(int, state)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->state = state;
	),

	TP_printk("con 0x%px state %d", __entry->con, __entry->state)
);

TRACE_EVENT(coroutine_yield,
	TP_PROTO(void* co),
	TP_ARGS(co),

	TP_STRUCT__entry(
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->co = co;
	),

	TP_printk("co 0x%px", __entry->co)
);

TRACE_EVENT(coroutine_yield_return,
	TP_PROTO(void* co),
	TP_ARGS(co),

	TP_STRUCT__entry(
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->co = co;
	),

	TP_printk("co 0x%px", __entry->co)
);

TRACE_EVENT(coroutine_enter,
	TP_PROTO(void* co),
	TP_ARGS(co),

	TP_STRUCT__entry(
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->co = co;
	),

	TP_printk("co 0x%px", __entry->co)
);

TRACE_EVENT(coroutine_enter_return,
	TP_PROTO(void* co),
	TP_ARGS(co),

	TP_STRUCT__entry(
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->co = co;
	),

	TP_printk("co 0x%px", __entry->co)
);

TRACE_EVENT(coroutine_signal,
	TP_PROTO(void* co),
	TP_ARGS(co),

	TP_STRUCT__entry(
		__field(void*, co)
	),

	TP_fast_assign(
		__entry->co = co;
	),

	TP_printk("co 0x%px", __entry->co)
);

TRACE_EVENT(coroutine_send,
	TP_PROTO(void* co, int bytes),
	TP_ARGS(co, bytes),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(int, bytes)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->bytes = bytes;
	),

	TP_printk("co 0x%px bytes %d", __entry->co, __entry->bytes)
);

TRACE_EVENT(coroutine_send_return,
	TP_PROTO(void* co, int bytes),
	TP_ARGS(co, bytes),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(int, bytes)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->bytes = bytes;
	),

	TP_printk("co 0x%px bytes %d", __entry->co, __entry->bytes)
);

TRACE_EVENT(coroutine_recv,
	TP_PROTO(void* co, int bytes),
	TP_ARGS(co, bytes),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(int, bytes)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->bytes = bytes;
	),

	TP_printk("co 0x%px bytes %d", __entry->co, __entry->bytes)
);

TRACE_EVENT(coroutine_recv_return,
	TP_PROTO(void* co, int bytes),
	TP_ARGS(co, bytes),

	TP_STRUCT__entry(
		__field(void*, co)
		__field(int, bytes)
	),

	TP_fast_assign(
		__entry->co = co;
		__entry->bytes = bytes;
	),

	TP_printk("co 0x%px bytes %d", __entry->co, __entry->bytes)
);

TRACE_EVENT(coroutine_thread_wait,
	TP_PROTO(void* thread),
	TP_ARGS(thread),

	TP_STRUCT__entry(
		__field(void*, thread)
	),

	TP_fast_assign(
		__entry->thread = thread;
	),

	TP_printk("thread 0x%px", __entry->thread)
);

TRACE_EVENT(coroutine_thread_wait_return,
	TP_PROTO(void* thread),
	TP_ARGS(thread),

	TP_STRUCT__entry(
		__field(void*, thread)
	),

	TP_fast_assign(
		__entry->thread = thread;
	),

	TP_printk("thread 0x%px", __entry->thread)
);

TRACE_EVENT(con_too_long,
	TP_PROTO(void* con, s64 age),
	TP_ARGS(con, age),

	TP_STRUCT__entry(
		__field(void*, con)
		__field(s64, age)
	),

	TP_fast_assign(
		__entry->con = con;
		__entry->age = age;
	),

	TP_printk("con 0x%px %lld", __entry->con, __entry->age)
);

TRACE_EVENT(con_sock_release,
	TP_PROTO(void* con),
	TP_ARGS(con),

	TP_STRUCT__entry(
		__field(void*, con)
	),

	TP_fast_assign(
		__entry->con = con;
	),

	TP_printk("con 0x%px", __entry->con)
);

TRACE_EVENT(con_sock_release_return,
	TP_PROTO(void* con),
	TP_ARGS(con),

	TP_STRUCT__entry(
		__field(void*, con)
	),

	TP_fast_assign(
		__entry->con = con;
	),

	TP_printk("con 0x%px", __entry->con)
);

#endif /* _TRACE_TLB_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
