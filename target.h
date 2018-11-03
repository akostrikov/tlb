#pragma once

#include "ksock.h"
#include "coroutine.h"

struct tlb_server;

struct tlb_target {
	char host[64];
	int port;
	atomic_t ref_count;
};

struct tlb_target_con {
	struct socket *sock;
	struct coroutine *co;
	struct socket *src_sock;
	char *buf;
	int buf_len;
};

void tlb_target_put(struct tlb_target *target);

int tlb_target_connect(struct tlb_target *target, struct coroutine *co, struct tlb_target_con **pcon);

void tlb_target_con_close(struct tlb_target_con *con);

void tlb_server_init_targets(struct tlb_server *srv);

void tlb_server_deinit_targets(struct tlb_server *srv);

int tlb_server_add_target(struct tlb_server *srv, const char *host, int port);

int tlb_server_remove_target(struct tlb_server *srv, const char *host, int port);

struct tlb_target* tlb_server_select_target(struct tlb_server *srv);
