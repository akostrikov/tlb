#include "server.h"

struct tlb_con {
	struct socket *sock;
	struct coroutine *co;
	struct tlb_server *srv;
	struct list_head list_entry;
};

static void tlb_con_delete(struct tlb_con *con)
{
	BUG_ON(!list_empty(&con->list_entry));

	trace("con 0x%px delete\n", con);
	coroutine_deref(con->co);
	if (con->sock)
		ksock_release(con->sock);
}

static void tlb_con_data_ready(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

static void tlb_con_write_space(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

static void tlb_con_state_change(struct sock *sk)
{
	struct tlb_con *con = sk->sk_user_data;

	trace("con 0x%px state change %u\n", con, sk->sk_state);

	coroutine_signal(con->co);
}

static void *tlb_con_coroutine(struct coroutine *co, void *arg)
{
	struct tlb_con *con = (struct tlb_con *)arg;
	struct tlb_server *srv = con->srv;
	int r, received, sent;
	char *buf;
	int buf_len;

	BUG_ON(con->co != co);

	trace("con 0x%px co 0x%px\n", con, co);

	buf_len = 16 * 1024;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		r = -ENOMEM;
		goto out;
	}

	for (;;) {
		r = ksock_recv(con->sock, buf, buf_len);
		if (r < 0) {
			if (r == -EAGAIN) {
				coroutine_yield(co);
				continue;
			} else
				break;
		} else if (r == 0)
			break;

		received = r;
		sent = 0;
		while (sent < received) {
			r = ksock_send(con->sock, (char *)buf + sent, received - sent);
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

out:
	trace("con 0x%px co 0x%px r %d", con, co, r);

	spin_lock(&srv->con_list_lock);
	list_del_init(&con->list_entry);
	spin_unlock(&srv->con_list_lock);

	tlb_con_delete(con);
	kfree(buf);
	return NULL;
}

static struct tlb_con *tlb_con_create(struct tlb_server *srv)
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

static void tlb_con_start(struct tlb_con *con, struct socket *sock)
{
	con->sock = sock;
	coroutine_start(con->co, tlb_con_coroutine, con);
}

static int tlb_server_listen_thread_routine(void *arg)
{
	struct tlb_server *srv = (struct tlb_server *)arg;
	struct socket *sock;
	struct ksock_callbacks callbacks;
	struct tlb_con *con;
	int r;
	
	while (!kthread_should_stop() && !srv->stopping) {
		con = tlb_con_create(srv);
		if (!con)
			break;

		callbacks.user_data = con;
		callbacks.state_change = tlb_con_state_change;
		callbacks.data_ready = tlb_con_data_ready;
		callbacks.write_space = tlb_con_write_space;

		r = ksock_accept(&sock, srv->listen_sock, &callbacks);
		if (r) {
			trace_err("accept r %d\n", r);
			tlb_con_delete(con);
			continue;
		}
		spin_lock(&srv->con_list_lock);
		list_add_tail(&con->list_entry, &srv->con_list);
		spin_unlock(&srv->con_list_lock);
		tlb_con_start(con, sock);
	}

	srv->listen_thread_stopping = true;
	return 0;
}

int tlb_server_start(struct tlb_server *srv, const char *host, int port)
{
	int r, i;

	memset(srv, 0, sizeof(*srv));
	if (snprintf(srv->host, ARRAY_SIZE(srv->host), "%s", host) != strlen(host))
		return EINVAL;
	srv->port = port;
	INIT_LIST_HEAD(&srv->con_list);
	spin_lock_init(&srv->con_list_lock);
	for (i = 0; i < 5; i++) {
		r = ksock_listen_host(&srv->listen_sock, srv->host, srv->port, 5);
		if (r) {
			trace_err("ksock_listen r %d\n", r);
			if (r == -EADDRINUSE) {
				msleep_interruptible(100);
				continue;
			}
		} else
			break;
	}
	if (r)
		return r;

	r = coroutine_thread_start(&srv->con_thread);
	if (r) {
		ksock_release(srv->listen_sock);
		return r;
	}

	srv->listen_thread = kthread_create(tlb_server_listen_thread_routine, srv, "tlb_listen");
	if (IS_ERR(srv->listen_thread)) {
		r = PTR_ERR(srv->listen_thread);
		coroutine_thread_stop(&srv->con_thread);
		ksock_release(srv->listen_sock);
		return r;
	}

	get_task_struct(srv->listen_thread);
	wake_up_process(srv->listen_thread);
	return 0;
}

void tlb_server_stop(struct tlb_server *srv)
{
	struct tlb_con *con, *tmp;

	srv->stopping = true;
	while (!srv->listen_thread_stopping) {
		ksock_abort_accept(srv->listen_sock);
		msleep_interruptible(100);
	}

	kthread_stop(srv->listen_thread);
	put_task_struct(srv->listen_thread);
	coroutine_thread_stop(&srv->con_thread);
	ksock_release(srv->listen_sock);

	list_for_each_entry_safe(con, tmp, &srv->con_list, list_entry) {
		list_del_init(&con->list_entry);
		tlb_con_delete(con);
	}
}
