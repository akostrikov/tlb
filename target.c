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

	memset(target, 0, sizeof(*target));
	r = ksock_resolve_addr(host, port, &target->addr);
	if (r)
		return r;

	snprintf(target->host, ARRAY_SIZE(target->host), "%s", host);
	target->port = port;
	atomic_set(&target->ref_count, 1);
	atomic64_set(&target->active_cons, 0);
	atomic64_set(&target->total_cons, 0);
	target->min_con_time_us = U64_MAX;

	resample_init(&target->con_time_sample, target->con_time_sample_value, ARRAY_SIZE(target->con_time_sample_value));
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

	con = kmem_cache_alloc(g_target_con_cache, GFP_KERNEL);
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
		coroutine_deref(con->co);
		kmem_cache_free(g_target_con_cache, con);
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
		kmem_cache_free(g_con_buf_cache, con->buf);

	trace_target_con_delete(con, con->co);

	coroutine_deref(con->co);
	kmem_cache_free(g_target_con_cache, con);
}

void tlb_server_init_targets(struct tlb_server *srv)
{
	rwlock_init(&srv->target_lock);
	srv->target_tree = RB_ROOT;
}

void tlb_server_deinit_targets(struct tlb_server *srv)
{
	struct rb_node *node;
	struct tlb_target *target;

	for (;;) {
		node = rb_first(&srv->target_tree);
		if (!node)
			break;

		target = rb_entry(node, struct tlb_target, target_tree_entry);
		rb_erase(&target->target_tree_entry, &srv->target_tree);
		tlb_target_put(target);
	}
}

static int cmp_host_port(const char *host1, int port1, const char *host2, int port2)
{
	int cmp;

	cmp = strncmp(host1, host2, strlen(host1) + 1);
	if (cmp == 0) {
		if (port1 < port2)
			return -1;
		else if (port1 > port2)
			return 1;
		return 0;
	}

	return cmp;
}

static int cmp_target(struct tlb_target *t1, struct tlb_target *t2)
{
	return cmp_host_port(t1->host, t1->port, t2->host, t2->port);
}

static struct tlb_target *tlb_server_lookup_target(struct tlb_server *srv, const char *host, int port, bool remove)
{
	struct rb_node *node = srv->target_tree.rb_node;
	struct tlb_target *target;
	int cmp;

	while (node) {
		target = rb_entry(node, struct tlb_target, target_tree_entry);
		cmp = cmp_host_port(host, port, target->host, target->port);
		if (cmp == 0) {
			if (remove)
				rb_erase(&target->target_tree_entry, &srv->target_tree);
			else
				tlb_target_get(target);
			return target;
		} else if (cmp < 0)
			node = node->rb_left;
		else
			node = node->rb_right;
	}

	return NULL;
}

static int tlb_server_insert_target(struct tlb_server *srv, struct tlb_target *new_target)
{
	struct tlb_target *target;
	struct rb_node **node;
	struct rb_node *parent = NULL;
	int cmp;

	write_lock(&srv->target_lock);
	node = &srv->target_tree.rb_node;
	while (*node) {
		target = rb_entry(*node, struct tlb_target, target_tree_entry);
		parent = *node;
		cmp = cmp_target(new_target, target);
		if (cmp == 0) {
			write_unlock(&srv->target_lock);
			return -EEXIST;
		} else if (cmp < 0)
			node = &parent->rb_left;
		else
			node = &parent->rb_right;
	}

	rb_link_node(&new_target->target_tree_entry, parent, node);
	rb_insert_color(&new_target->target_tree_entry, &srv->target_tree);
	tlb_target_get(new_target);

	write_unlock(&srv->target_lock);
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
	tlb_target_put(target);
	return r;
}

int tlb_server_remove_target(struct tlb_server *srv, const char *host, int port)
{
	struct tlb_target *target;

	write_lock(&srv->target_lock);
	target = tlb_server_lookup_target(srv, host, port, true);
	if (!target) {
		write_unlock(&srv->target_lock);
		return -ENOENT;
	}
	tlb_target_put(target);
	write_unlock(&srv->target_lock);
	return 0;
}

struct tlb_target* tlb_server_select_target(struct tlb_server *srv)
{
	struct rb_node *node;
	struct tlb_target *target;
	struct tlb_target *least_con_target = NULL;

	read_lock(&srv->target_lock);
	for (node = rb_first(&srv->target_tree); node != NULL; node = rb_next(node)) {
		target = rb_entry(node, struct tlb_target, target_tree_entry);
		if (!least_con_target)
			least_con_target = target;
		else
			if (atomic64_read(&target->active_cons) < atomic64_read(&least_con_target->active_cons))
				least_con_target = target;
	}

	if (least_con_target)
		tlb_target_get(least_con_target);
	read_unlock(&srv->target_lock);

	return least_con_target;
}

struct tlb_target* tlb_server_next_target(struct tlb_server *srv, struct tlb_target* prev)
{
	struct rb_node *node;
	struct tlb_target *next;

	if (prev == NULL)
		node = rb_first(&srv->target_tree);
	else
		node = rb_next(&prev->target_tree_entry);

	if (node)
		next = rb_entry(node, struct tlb_target, target_tree_entry);
	else
		next = NULL;

	return next;
}
