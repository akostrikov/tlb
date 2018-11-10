#pragma once

#include <linux/net.h>

u16 ksock_self_port(struct socket *sock);
u16 ksock_peer_port(struct socket *sock);
u32 ksock_peer_addr(struct socket *sock);
u32 ksock_self_addr(struct socket *sock);

int ksock_create(struct socket **sockp,
	__u32 local_ip, int local_port);

int ksock_set_sendbufsize(struct socket *sock, int size);

int ksock_set_rcvbufsize(struct socket *sock, int size);

int ksock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port);

void ksock_release(struct socket *sock);

int ksock_send(struct socket *sock, void *buf, int len);

int ksock_recv(struct socket *sock, void *buf, int len);

int ksock_listen(struct socket **sockp, __u32 local_ip, int local_port,
	int backlog);

struct ksock_callbacks {
	void *user_data;
	void (*data_ready)(struct sock *sk);
	void (*write_space)(struct sock *sk);
	void (*state_change)(struct sock *sk);
};

int ksock_accept(struct socket **newsockp, struct socket *sock, struct ksock_callbacks *callbacks);

void ksock_abort_accept(struct socket *sock);

int ksock_ioctl(struct socket *sock, int cmd, unsigned long arg);

int ksock_set_nodelay(struct socket *sock, bool no_delay);

int ksock_resolve_addr(const char *host, u16 port, struct sockaddr_storage *addr);

int ksock_connect_host(struct socket **sockp, const char *host, u16 port, struct ksock_callbacks *callbacks);

int ksock_connect_addr(struct socket **sockp, struct sockaddr_storage *addr, struct ksock_callbacks *callbacks);

int ksock_listen_host(struct socket **sockp, char *host, int port, int backlog);
