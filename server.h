#pragma once

#include "base.h"
#include "ksock.h"
#include "coroutine.h"
#include "target.h"
#include "con.h"

enum {
	TLB_SRV_INITED = 1,
	TLB_SRV_STARTING,
	TLB_SRV_RUNNING,
	TLB_SRV_STOPPING
};

struct tlb_server {
	char host[64];
	int port;

	struct task_struct *listen_thread;
	struct socket *listen_sock;
	struct coroutine_thread con_thread[NR_CPUS];
	int nr_con_thread;
	atomic_t next_con_thread;
	int state;
	struct mutex lock;
	bool listen_thread_stopping;
	struct list_head con_list;
	spinlock_t con_list_lock;

	rwlock_t target_lock;
	struct tlb_target *target[16];
	int nr_targets;
	atomic_t next_target;
};

void tlb_server_init(struct tlb_server *srv);

int tlb_server_start(struct tlb_server *srv, const char *host, int port);

int tlb_server_stop(struct tlb_server *srv);

void tlb_server_unlink_con(struct tlb_server *srv, struct tlb_con *con);
