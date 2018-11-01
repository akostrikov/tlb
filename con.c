#include "base.h"
#include "server.h"
#include "coroutine.h"

void tlb_con_delete(struct tlb_con *con)
{
	BUG_ON(!list_empty(&con->list_entry));

	trace("con 0x%px delete\n", con);
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

	coroutine_signal(con->co);
}

static int copy_socket_coroutine(struct coroutine *co, struct socket *from, struct socket *to, char *buf, int buf_len, bool *closed)
{
	int r, received, sent;

	*closed = false;
	for (;;) {
		r = ksock_recv(from, buf, buf_len);
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
			r = ksock_send(to, (char *)buf + sent, received - sent);
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

static void *tlb_con_coroutine(struct coroutine *co, void *arg)
{
	struct tlb_con *con = (struct tlb_con *)arg;
	struct tlb_server *srv = con->srv;
	struct tlb_target *target;
	struct tlb_target_con *target_con;
	int r;
	char *buf;
	int buf_len;
	bool closed;

	BUG_ON(con->co != co);

	trace("con 0x%px co 0x%px\n", con, co);

	buf_len = 16 * 1024;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		r = -ENOMEM;
		goto out;
	}

	target = tlb_server_select_target(srv);
	if (!target) {
		r = -ENOENT;
		goto out;
	}

	r = tlb_target_connect(target, co, &target_con);
	if (r)
		goto put_target;

	for (;;) {
		r = copy_socket_coroutine(co, con->sock, target_con->sock, buf, buf_len, &closed);
		if (r)
			break;
		if (closed)
			break;
		r = copy_socket_coroutine(co, target_con->sock, con->sock, buf, buf_len, &closed);
		if (r)
			break;
		if (closed)
			break;
	}

	tlb_target_con_close(target_con);
put_target:
	tlb_target_put(target);
out:
	trace("con 0x%px co 0x%px r %d", con, co, r);

	tlb_server_unlink_con(srv, con);
	tlb_con_delete(con);
	kfree(buf);
	return NULL;
}

void tlb_con_start(struct tlb_con *con, struct socket *sock)
{
	con->sock = sock;
	coroutine_start(con->co, tlb_con_coroutine, con);
}
