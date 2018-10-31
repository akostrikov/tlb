#pragma once

#include "base.h"
#include "ksock.h"
#include "coroutine.h"

struct tlb_server {
	char host[64];
	int port;

	struct task_struct *listen_thread;
	struct socket *listen_sock;
	struct coroutine_thread con_thread;
	bool stopping;
	bool listen_thread_stopping;
	struct list_head con_list;
	spinlock_t con_list_lock;
};

int tlb_server_start(struct tlb_server *srv, const char *host, int port);

void tlb_server_stop(struct tlb_server *srv);
