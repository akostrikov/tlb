#include "base.h"
#include "server.h"
#include "coroutine.h"
#include "trace.h"

void tlb_con_delete(struct tlb_con *con)
{
	s64 age;

	BUG_ON(!list_empty(&con->list_entry));

	if (con->start_time) {
		age = ktime_ms_delta(ktime_get(), con->start_time);
		if (age > 5)
			trace_con_too_long(con, age);
	}

	if (con->target_con)
		tlb_target_con_close(con->target_con);
	if (con->target)
		tlb_target_put(con->target);
	if (con->buf)
		kmem_cache_free(g_con_buf_cache, con->buf);

	if (con->sock) {
		trace_con_sock_release(con);
		ksock_release(con->sock);
		trace_con_sock_release_return(con);
	}

	trace_con_delete(con, con->co);

	coroutine_deref(con->co);
	kmem_cache_free(g_con_cache, con);
}

struct tlb_con *tlb_con_create(struct tlb_server *srv)
{
	struct tlb_con *con;

	con = kmem_cache_alloc(g_con_cache, GFP_KERNEL);
	if (!con)
		return NULL;
	memset(con, 0, sizeof(*con));
	atomic_inc(&srv->next_con_thread);
	con->co = coroutine_create(&srv->con_thread[atomic_read(&srv->next_con_thread) % srv->nr_con_thread]);
	if (!con->co) {
		kmem_cache_free(g_con_cache, con);
		return NULL;
	}
	con->srv = srv;
	INIT_LIST_HEAD(&con->list_entry);
	trace_con_create(con, con->co);
	return con;
}

void tlb_con_data_ready(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

void tlb_con_write_space(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

void tlb_con_state_change(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	trace_con_state_change(con, sk->sk_state);
	coroutine_signal(con->co);
}

static int copy_socket_coroutine(struct coroutine *co, struct socket *from, struct socket *to, char *buf, int buf_len, bool *closed)
{
	int r, received, sent;

	*closed = false;
	for (;;) {
		trace_coroutine_recv(co, buf_len);
		r = ksock_recv(from, buf, buf_len);
		trace_coroutine_recv_return(co, r);
		if (r < 0) {
			if (r == -EAGAIN) {
				coroutine_yield(co);
				continue;
			} else
				break;
		} else if (r == 0) {
			*closed = true;
			break;
		}

		received = r;
		sent = 0;
		while (sent < received) {
			trace_coroutine_send(co, received - sent);
			r = ksock_send(to, buf + sent, received - sent);
			trace_coroutine_send_return(co, r);
			if (r < 0) {
				if (r == -EAGAIN) {
					coroutine_yield(co);
					continue;
				} else
					break;
			}
			sent += r;
		}
		if (r < 0)
			break;
	}

	return r;
}

static void *tlb_target_con_coroutine(struct coroutine *co, void *arg)
{
	struct tlb_target_con *con = arg;
	int r;
	bool closed;

	trace_target_con_co_enter(con, co);

	con->buf_len = TLB_CON_BUF_SIZE;
	con->buf = kmem_cache_alloc(g_con_buf_cache, GFP_KERNEL);
	if (!con->buf) {
		r = -ENOMEM;
		goto out;
	}

	for (;;) {
		r = copy_socket_coroutine(co, con->sock, con->src_sock, con->buf, con->buf_len, &closed);
		if (r)
			break;
		if (closed)
			break;
	}

	trace_con_sock_release(con);
	ksock_release(con->sock);
	trace_con_sock_release_return(con);

	con->sock = NULL;
	kmem_cache_free(g_con_buf_cache, con->buf);
	con->buf = NULL;
out:
	trace_target_con_co_leave(con, co, r);
	return ERR_PTR(r);
}

static void *tlb_con_coroutine(struct coroutine *co, void *arg)
{
	struct tlb_con *con = (struct tlb_con *)arg;
	struct tlb_server *srv = con->srv;
	struct coroutine *target_con_co;
	struct tlb_target *target;
	u64 con_time_us;
	int r;
	bool closed;

	BUG_ON(con->co != co);

	trace_con_co_enter(con, co);

	con->buf_len = TLB_CON_BUF_SIZE;
	con->buf = kmem_cache_alloc(g_con_buf_cache, GFP_KERNEL);
	if (!con->buf) {
		r = -ENOMEM;
		goto out;
	}

	con->target = tlb_server_select_target(srv);
	if (!con->target) {
		r = -ENOENT;
		goto free_buf;
	}
	atomic64_inc(&con->target->total_cons);
	atomic64_inc(&con->target->active_cons);

	target_con_co = coroutine_create(co->thread);
	if (!target_con_co) {
		r = -ENOMEM;
		goto put_target;
	}

	r = tlb_target_connect(con->target, target_con_co, &con->target_con);
	coroutine_deref(target_con_co);
	if (r)
		goto put_target;

	con->target_con->src_sock = con->sock;
	coroutine_start(target_con_co, tlb_target_con_coroutine, con->target_con);
	for (;;) {
		r = copy_socket_coroutine(co, con->sock, con->target_con->sock, con->buf, con->buf_len, &closed);
		if (r)
			break;
		if (closed)
			break;	
	}
	trace_con_sock_release(con);
	ksock_release(con->sock);
	trace_con_sock_release_return(con);
	con->sock = NULL;
	if (r)
		coroutine_cancel(con->target_con->co);
	else {
		void *ret;
		
		coroutine_cancel(con->target_con->co);
		ret = con->target_con->co->ret;
		if (IS_ERR(ret))
				r = PTR_ERR(ret);
	}

	tlb_target_con_close(con->target_con);
	con->target_con = NULL;
put_target:
	target = con->target;
	atomic64_dec(&target->active_cons);

	spin_lock(&target->lock);
	con_time_us = ktime_us_delta(ktime_get(), con->start_time);
	if (con_time_us > target->max_con_time_us)
		target->max_con_time_us = con_time_us;
	if (con_time_us < target->min_con_time_us)
		target->min_con_time_us = con_time_us;
	target->total_con_time_us += con_time_us;
	spin_unlock(&target->lock);

	tlb_target_put(target);
	con->target = NULL;
free_buf:
	kmem_cache_free(g_con_buf_cache, con->buf);
	con->buf = NULL;
out:
	trace_con_co_leave(con, co, r);
	tlb_server_unlink_con(srv, con);
	tlb_con_delete(con);
	return NULL;
}

void tlb_con_start(struct tlb_con *con, struct socket *sock)
{
	con->sock = sock;
	coroutine_start(con->co, tlb_con_coroutine, con);
}
