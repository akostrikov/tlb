#include "target.h"
#include "base.h"
#include "server.h"
#include "trace.h"

static int tlb_target_init(struct tlb_target *target, const char *host, int port)
{
	int r;

	if (strlen(host) >= ARRAY_SIZE(target->host))
		return -EINVAL;

	if (port <= 0 || port > 65535)
		return -EINVAL;

	r = ksock_resolve_addr(host, port, &target->addr);
	if (r)
		return r;

	snprintf(target->host, ARRAY_SIZE(target->host), "%s", host);
	target->port = port;

	atomic_set(&target->ref_count, 1);
	return 0;
}

static void tlb_target_get(struct tlb_target *target)
{
	atomic_inc(&target->ref_count);
}

void tlb_target_put(struct tlb_target *target)
{
	if (atomic_dec_and_test(&target->ref_count))
		kfree(target);
}

static void tlb_target_con_data_ready(struct sock *sk)
{
	struct tlb_target_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

static void tlb_target_con_write_space(struct sock *sk)
{
	struct tlb_target_con *con = sk->sk_user_data;

	coroutine_signal(con->co);
}

static void tlb_target_con_state_change(struct sock *sk)
{
	struct tlb_target_con *con = sk->sk_user_data;

	trace_target_con_state_change(con, sk->sk_state);

	coroutine_signal(con->co);
}

int tlb_target_connect(struct tlb_target *target, struct coroutine *co, struct tlb_target_con **pcon)
{
	struct tlb_target_con *con;
	struct ksock_callbacks callbacks;
	int r;

	con = kmalloc(sizeof(*con), GFP_KERNEL);
	if (!con)
		return -ENOMEM;
	memset(con, 0, sizeof(*con));
	coroutine_ref(co);
	con->co = co;
	callbacks.user_data = con;
	callbacks.data_ready = tlb_target_con_data_ready;
	callbacks.write_space = tlb_target_con_write_space;
	callbacks.state_change = tlb_target_con_state_change;

	r = ksock_connect_addr(&con->sock, &target->addr, &callbacks);
	if (r) {
		kfree(con);
		return r;
	}

	trace_target_con_create(con, co);

	*pcon = con;
	return r;
}

void tlb_target_con_close(struct tlb_target_con *con)
{
	if (con->sock) {
		trace_con_sock_release(con);
		ksock_release(con->sock);
		trace_con_sock_release_return(con);
	}
	if (con->buf)
		kfree(con->buf);

	trace_target_con_delete(con, con->co);

	coroutine_deref(con->co);
	kfree(con);
}

void tlb_server_init_targets(struct tlb_server *srv)
{
	rwlock_init(&srv->target_lock);
	srv->nr_targets = 0;
	atomic_set(&srv->next_target, 0);
}

void tlb_server_deinit_targets(struct tlb_server *srv)
{
	int i;

	for (i = 0; i < srv->nr_targets; i++)
		tlb_target_put(srv->target[i]);
}

static struct tlb_target *tlb_server_lookup_target(struct tlb_server *srv, const char *host, int port, bool remove)
{
	int i;
	struct tlb_target *target;

	for (i = 0; i < srv->nr_targets; i++) {
		target = srv->target[i];
		if (strncmp(target->host, host, strlen(target->host) + 1) == 0 &&
		    target->port == port) {
			tlb_target_get(target);
			if (remove) {
				memmove(&srv->target[i], &srv->target[i+1],
					(srv->nr_targets - (i + 1))*sizeof(struct tlb_target *));
				srv->nr_targets--;
				tlb_target_put(target);
			}
			return target;
		}
	}
	return NULL;
}

static int tlb_server_insert_target(struct tlb_server *srv, struct tlb_target *new_target)
{
	struct tlb_target *target;

	mutex_lock(&srv->lock);
	if (srv->state != TLB_SRV_RUNNING) {
		mutex_unlock(&srv->lock);
		return -EPERM;
	}

	write_lock(&srv->target_lock);
	if (srv->nr_targets >= ARRAY_SIZE(srv->target)) {
		write_unlock(&srv->target_lock);	
		mutex_unlock(&srv->lock);
		return -ENOMEM;
	}

	target = tlb_server_lookup_target(srv, new_target->host, new_target->port, false);
	if (target) {
		tlb_target_put(target);
		write_unlock(&srv->target_lock);
		mutex_unlock(&srv->lock);
		return -EEXIST;
	}

	tlb_target_get(new_target);
	srv->target[srv->nr_targets++] = new_target;
	write_unlock(&srv->target_lock);
	mutex_unlock(&srv->lock);
	return 0;
}

int tlb_server_add_target(struct tlb_server *srv, const char *host, int port)
{
	struct tlb_target *target;
	int r;

	target = kmalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return -ENOMEM;

	r = tlb_target_init(target, host, port);
	if (r) {
		kfree(target);
		return r;
	}

	r = tlb_server_insert_target(srv, target);
	if (r) {
		tlb_target_put(target);
		return r;
	}
	return 0;
}

int tlb_server_remove_target(struct tlb_server *srv, const char *host, int port)
{
	struct tlb_target *target;

	mutex_lock(&srv->lock);
	if (srv->state != TLB_SRV_RUNNING) {
		mutex_unlock(&srv->lock);
		return -EPERM;
	}

	write_lock(&srv->target_lock);
	target = tlb_server_lookup_target(srv, host, port, true);
	if (!target) {
		write_unlock(&srv->target_lock);
		mutex_unlock(&srv->lock);
		return -ENOENT;
	}
	tlb_target_put(target);
	write_unlock(&srv->target_lock);
	mutex_unlock(&srv->lock);
	return 0;
}

struct tlb_target* tlb_server_select_target(struct tlb_server *srv)
{
	struct tlb_target *target;

	read_lock(&srv->target_lock);
	if (!srv->nr_targets) {
		read_unlock(&srv->target_lock);
		return NULL;
	}

	atomic_inc(&srv->next_target);
	target = srv->target[atomic_read(&srv->next_target) % srv->nr_targets];
	tlb_target_get(target);
	read_unlock(&srv->target_lock);
	return target;
}
