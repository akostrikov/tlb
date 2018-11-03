#pragma once

#include "coroutine.h"

struct tlb_server;
struct tlb_target;
struct tlb_target_con;

struct tlb_con {
	struct socket *sock;
	struct coroutine *co;
	struct tlb_server *srv;
	struct list_head list_entry;
	char *buf;
	int buf_len;
	struct tlb_target *target;
	struct tlb_target_con *target_con;
};

struct tlb_con *tlb_con_create(struct tlb_server *srv);

void tlb_con_start(struct tlb_con *con, struct socket *sock);

void tlb_con_data_ready(struct sock *sk);

void tlb_con_write_space(struct sock *sk);

void tlb_con_state_change(struct sock *sk);

void tlb_con_delete(struct tlb_con *con);
