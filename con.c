#include "base.h"
#include "server.h"
#include "coroutine.h"

void tlb_con_delete(struct tlb_con *con)
{
	BUG_ON(!list_empty(&con->list_entry));

	//trace("con 0x%px delete\n", con);
	
	if (con->target_con)
		tlb_target_con_close(con->target_con);
	if (con->target)
		tlb_target_put(con->target);
	if (con->buf)
		kfree(con->buf);

	coroutine_deref(con->co);

	if (con->sock)
		ksock_release(con->sock);
}

struct tlb_con *tlb_con_create(struct tlb_server *srv)
{
	struct tlb_con *con;

	con = kmalloc(sizeof(*con), GFP_KERNEL);
	if (!con)
		return NULL;
	memset(con, 0, sizeof(*con));
	con->co = coroutine_create(&srv->con_thread);
	if (!con->co) {
		kfree(con);
		return NULL;
	}
	con->srv = srv;
	INIT_LIST_HEAD(&con->list_entry);
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

	//trace("con 0x%px state %d\n", con, sk->sk_state);
	coroutine_signal(con->co);
}

static int copy_socket_coroutine(struct coroutine *co, struct socket *from, struct socket *to, char *buf, int buf_len, bool *closed)
{
	int r, received, sent;

	*closed = false;
	for (;;) {
		//trace("co 0x%px ksock_recv buf 0x%px \n", co, buf);
		r = ksock_recv(from, buf, buf_len);
		//trace("co 0x%px ksock_recv r %d\n", co, r);
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
			//trace("co 0x%px ksock_send\n", co);
			r = ksock_send(to, buf + sent, received - sent);
			//trace("co 0x%px ksock_send r %d\n", co, r);
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

	//trace("con 0x%px co 0x%px", con, co);

	con->buf_len = 16 * 1024;
	con->buf = kmalloc(con->buf_len, GFP_KERNEL);
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

	kfree(con->buf);
	con->buf = NULL;
out:
	//trace("con 0x%px co 0x%px r %d", con, co, r);
	return ERR_PTR(r);
}

static void *tlb_con_coroutine(struct coroutine *co, void *arg)
{
	struct tlb_con *con = (struct tlb_con *)arg;
	struct tlb_server *srv = con->srv;
	struct coroutine *target_con_co;
	int r;
	bool closed;

	BUG_ON(con->co != co);

	//trace("con 0x%px co 0x%px\n", con, co);

	con->buf_len = 16 * 1024;
	con->buf = kmalloc(con->buf_len, GFP_KERNEL);
	if (!con->buf) {
		r = -ENOMEM;
		goto out;
	}

	con->target = tlb_server_select_target(srv);
	if (!con->target) {
		r = -ENOENT;
		goto free_buf;
	}

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

	if (r)
		coroutine_cancel(target_con_co);
	else {
		void *ret;
		
		coroutine_cancel(target_con_co);
		ret = target_con_co->ret;
		if (IS_ERR(ret))
				r = PTR_ERR(ret);
	}

	tlb_target_con_close(con->target_con);
	con->target_con = NULL;
put_target:
	tlb_target_put(con->target);
	con->target = NULL;
free_buf:
	kfree(con->buf);
	con->buf = NULL;
out:
	//trace("con 0x%px co 0x%px r %d", con, co, r);

	tlb_server_unlink_con(srv, con);
	tlb_con_delete(con);
	return NULL;
}

void tlb_con_start(struct tlb_con *con, struct socket *sock)
{
	con->sock = sock;
	coroutine_start(con->co, tlb_con_coroutine, con);
}
