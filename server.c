#include "server.h"
#include "con.h"

struct kmem_cache *g_con_cache;
struct kmem_cache *g_target_con_cache;
struct kmem_cache *g_con_buf_cache;

void tlb_server_unlink_con(struct tlb_server *srv, struct tlb_con *con)
{
	spin_lock(&srv->con_list_lock);
	list_del_init(&con->list_entry);
	spin_unlock(&srv->con_list_lock);
}

static int tlb_server_listen_thread_routine(void *arg)
{
	struct tlb_server *srv = (struct tlb_server *)arg;
	struct socket *sock;
	struct ksock_callbacks callbacks;
	struct tlb_con *con;
	int r;

	while (!kthread_should_stop() && srv->state != TLB_SRV_STOPPING) {
		con = tlb_con_create(srv);
		if (!con)
			break;

		callbacks.user_data = con;
		callbacks.state_change = tlb_con_state_change;
		callbacks.data_ready = tlb_con_data_ready;
		callbacks.write_space = tlb_con_write_space;

		r = ksock_accept(&sock, srv->listen_sock, &callbacks);
		if (r) {
			pr_err("tlb: accept r %d\n", r);
			tlb_con_delete(con);
			continue;
		}

		con->start_time = ktime_get();
		spin_lock(&srv->con_list_lock);
		list_add_tail(&con->list_entry, &srv->con_list);
		spin_unlock(&srv->con_list_lock);
		tlb_con_start(con, sock);
	}

	srv->listen_thread_stopping = true;
	return 0;
}

int tlb_server_init(struct tlb_server *srv)
{
	mutex_init(&srv->lock);
	srv->state = TLB_SRV_INITED;
	return 0;
}

int tlb_server_start(struct tlb_server *srv, const char *host, int port)
{
	int r, i;
	unsigned int cpu;
	struct sockaddr_storage addr;

	if (strlen(host) >= ARRAY_SIZE(srv->host) || port <= 0 || port > 65535)
		return -EINVAL;

	r = ksock_resolve_addr(host, port, &addr);
	if (r)
		return r;

	mutex_lock(&srv->lock);
	if (srv->state != TLB_SRV_INITED) {
		r = -EEXIST;
		goto unlock;
	}
	srv->state = TLB_SRV_STARTING;

	srv->nr_con_thread = 0;
	atomic_set(&srv->next_con_thread, 0);
	tlb_server_init_targets(srv);
	snprintf(srv->host, ARRAY_SIZE(srv->host), "%s", host);
	srv->port = port;
	INIT_LIST_HEAD(&srv->con_list);
	spin_lock_init(&srv->con_list_lock);
	for (i = 0; i < 5; i++) {
		r = ksock_listen_addr(&srv->listen_sock, &addr, SOMAXCONN);
		if (r) {
			pr_err("tlb: ksock_listen r %d\n", r);
			if (r == -EADDRINUSE) {
				msleep_interruptible(100);
				continue;
			}
		} else
			break;
	}
	if (r)
		goto deinit_targets;

	for_each_cpu(cpu, cpu_online_mask) {
		r = coroutine_thread_start(&srv->con_thread[srv->nr_con_thread], "tlb_coroutine", cpu);
		if (r)
			goto stop_con_coroutine;

		srv->nr_con_thread++;
	}

	srv->listen_thread = kthread_create(tlb_server_listen_thread_routine, srv, "tlb_listen");
	if (IS_ERR(srv->listen_thread)) {
		r = PTR_ERR(srv->listen_thread);
		goto stop_con_coroutine;
	}

	get_task_struct(srv->listen_thread);
	wake_up_process(srv->listen_thread);
	srv->state = TLB_SRV_RUNNING;
	mutex_unlock(&srv->lock);
	return 0;

stop_con_coroutine:
	for (i = 0; i < srv->nr_con_thread; i++)
		coroutine_thread_stop(&srv->con_thread[i]);

	ksock_release(srv->listen_sock);
deinit_targets:
	tlb_server_deinit_targets(srv);
	srv->state = TLB_SRV_INITED;
unlock:
	mutex_unlock(&srv->lock);
	return r;
}

int tlb_server_stop(struct tlb_server *srv)
{
	struct tlb_con *con, *tmp;
	int i;

	mutex_lock(&srv->lock);
	if (srv->state != TLB_SRV_RUNNING) {
		mutex_unlock(&srv->lock);
		return -ENOENT;
	}
	srv->state = TLB_SRV_STOPPING;

	while (!srv->listen_thread_stopping) {
		ksock_abort_accept(srv->listen_sock);
		msleep_interruptible(100);
	}
	kthread_stop(srv->listen_thread);
	put_task_struct(srv->listen_thread);
	srv->listen_thread_stopping = false;

	for (i = 0; i < srv->nr_con_thread; i++)
		coroutine_thread_stop(&srv->con_thread[i]);

	ksock_release(srv->listen_sock);

	list_for_each_entry_safe(con, tmp, &srv->con_list, list_entry) {
		list_del_init(&con->list_entry);
		tlb_con_delete(con);
	}

	tlb_server_deinit_targets(srv);

	srv->state = TLB_SRV_INITED;
	mutex_unlock(&srv->lock);
	return 0;
}

int tlb_server_cache_init(void)
{
	g_con_cache = kmem_cache_create("tlb_con_cache", sizeof(struct tlb_con), 0, 0, NULL);
	if (!g_con_cache)
		return -ENOMEM;

	g_target_con_cache = kmem_cache_create("tlb_target_con_cache", sizeof(struct tlb_target_con), 0, 0, NULL);
	if (!g_target_con_cache) {
		kmem_cache_destroy(g_con_cache);
		return -ENOMEM;
	}

	g_con_buf_cache = kmem_cache_create("tlb_con_buf_cache", TLB_CON_BUF_SIZE, 0, 0, NULL);
	if (!g_con_buf_cache) {
		kmem_cache_destroy(g_target_con_cache);
		kmem_cache_destroy(g_con_cache);
		return -ENOMEM;
	}
	return 0;
}

void tlb_server_cache_deinit(void)
{
	kmem_cache_destroy(g_con_buf_cache);
	kmem_cache_destroy(g_target_con_cache);
	kmem_cache_destroy(g_con_cache);
}
