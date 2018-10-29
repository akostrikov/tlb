#include "ksock.h"
#include "base.h"

#include <linux/version.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <linux/tcp.h>
#include <linux/dns_resolver.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>

u16 ksock_peer_port(struct socket *sock)
{
	return be16_to_cpu(sock->sk->sk_dport);
}

u16 ksock_self_port(struct socket *sock)
{
	return sock->sk->sk_num;
}

u32 ksock_peer_addr(struct socket *sock)
{
	return be32_to_cpu(sock->sk->sk_daddr);
}

u32 ksock_self_addr(struct socket *sock)
{
	return be32_to_cpu(sock->sk->sk_rcv_saddr);
}

int ksock_create(struct socket **sockp,
	__u32 local_ip, int local_port)
{
	struct sockaddr_in	localaddr;
	struct socket		*sock = NULL;
	int			error;
	int			option;
	mm_segment_t		oldmm = get_fs();

	error = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
	if (error)
		goto out;


	set_fs(KERNEL_DS);
	option = 1;
	error = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	if (error)
		goto out_sock_release;

	if (local_ip != 0 || local_port != 0) {
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(local_port);
		localaddr.sin_addr.s_addr = (local_ip == 0) ?
			INADDR_ANY : htonl(local_ip);
		error = sock->ops->bind(sock, (struct sockaddr *)&localaddr,
				sizeof(localaddr));
		if (error == -EADDRINUSE)
			goto out_sock_release;

		if (error)
			goto out_sock_release;

	}
	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

int ksock_set_nodelay(struct socket *sock, bool no_delay)
{
	int option;
	int error;
	mm_segment_t oldmm = get_fs();

	option = (no_delay) ? 1 : 0;

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_TCP, TCP_NODELAY,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_set_sendbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;
	mm_segment_t oldmm = get_fs();

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_set_rcvbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;
	mm_segment_t oldmm = get_fs();

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port)
{
	struct sockaddr_in srvaddr;
	int error;
	struct socket *sock = NULL;

	error = ksock_create(&sock, local_ip, local_port);
	if (error)
		goto out;

	error = ksock_set_nodelay(sock, true);
	if (error)
		goto out_sock_release;

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(peer_port);
	srvaddr.sin_addr.s_addr = htonl(peer_ip);

	error = sock->ops->connect(sock, (struct sockaddr *)&srvaddr,
			sizeof(srvaddr), 0);
	if (error)
		goto out_sock_release;

	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

void ksock_release(struct socket *sock)
{

	synchronize_rcu();
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}

int ksock_send(struct socket *sock, void *buf, int len)
{
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);

	return sock_sendmsg(sock, &msg);
}

int ksock_recv(struct socket *sock, void *buf, int len)
{
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	iov_iter_init(&msg.msg_iter, READ, &iov, 1, len);

	return sock_recvmsg(sock, &msg, 0);
}

int ksock_listen(struct socket **sockp, __u32 local_ip, int local_port,
	int backlog)
{
	int error;
	struct socket *sock = NULL;

	error = ksock_create(&sock, local_ip, local_port);
	if (error)
		return error;

	error = sock->ops->listen(sock, backlog);
	if (error)
		goto out;

	*sockp = sock;
	return 0;
out:
	sock_release(sock);
	return error;
}

int ksock_accept(struct socket **newsockp, struct socket *sock, struct ksock_callbacks *callbacks)
{
	struct wait_queue_entry wait;
	struct socket *newsock;
	int error;

	init_waitqueue_entry(&wait, current);
	error = sock_create_lite(sock->ops->family, sock->type, IPPROTO_TCP, &newsock);
	if (error)
		return error;

	newsock->ops = sock->ops;
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(sk_sleep(sock->sk), &wait);
	error = sock->ops->accept(sock, newsock, O_NONBLOCK, true);
	if (error == -EAGAIN) {
		schedule();
		error = sock->ops->accept(sock, newsock, O_NONBLOCK, true);
	}
	remove_wait_queue(sk_sleep(sock->sk), &wait);
	set_current_state(TASK_RUNNING);
	if (error)
		goto out;

	if (callbacks) {
		struct sock *sk = newsock->sk;
		
		sk->sk_user_data = callbacks->user_data;
		sk->sk_data_ready = callbacks->data_ready;
		sk->sk_write_space = callbacks->write_space;
		sk->sk_state_change = callbacks->state_change;
	}

	*newsockp = newsock;
	return 0;
out:
	sock_release(newsock);
	return error;
}

void ksock_abort_accept(struct socket *sock)
{
	wake_up_all(sk_sleep(sock->sk));
}

int ksock_ioctl(struct socket *sock, int cmd, unsigned long arg)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	err = sock->ops->ioctl(sock, cmd, arg);
	set_fs(oldfs);
	return err;
}

static void ksock_addr_set_port(struct sockaddr_storage *ss, int p)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)ss)->sin_port = htons(p);
			break;
	case AF_INET6:
		((struct sockaddr_in6 *)ss)->sin6_port = htons(p);
			break;
	}
}

static int ksock_pton(char *ip, int ip_len, struct sockaddr_storage *ss)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *) ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

	memset(ss, 0, sizeof(*ss));

	if (in4_pton(ip, ip_len, (u8 *)&in4->sin_addr.s_addr, -1, NULL)) {
		ss->ss_family = AF_INET;
		return 0;
	}

	if (in6_pton(ip, ip_len, (u8 *)&in6->sin6_addr.s6_addr, -1, NULL)) {
		ss->ss_family = AF_INET6;
		return 0;
	}

	return -EINVAL;
}

static int ksock_dns_resolve(char *name, struct sockaddr_storage *ss)
{
	int ip_len, r;
	char *ip_addr = NULL;

	ip_len = dns_query(NULL, name, strlen(name), NULL, &ip_addr, NULL);
	if (ip_len > 0)
		r = ksock_pton(ip_addr, ip_len, ss);
	else {
		trace_err("dns_query %s failed error %d\n", name, ip_len);
		r = -ESRCH;
	}
	kfree(ip_addr);
	return r;
}

int ksock_connect_host(struct socket **sockp, char *host, u16 port)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	int r;
	struct socket *sock;
	int option;
	mm_segment_t oldmm;

	r = ksock_pton(host, strlen(host), &addr);
	if (r) {
		r = ksock_dns_resolve(host, &addr);
		if (r)
			return r;
	}

	r = sock_create(addr.ss_family, SOCK_STREAM, 0, &sock);
	if (r)
		return r;

	oldmm = get_fs();
	set_fs(KERNEL_DS);
	option = 1;
	r = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	set_fs(oldmm);
	if (r)
		goto release_sock;

	r = ksock_set_nodelay(sock, true);
	if (r)
		goto release_sock;

	ksock_addr_set_port(&addr, port);

	r = sock->ops->connect(sock, (struct sockaddr *)&addr,
		(addr.ss_family == AF_INET) ? sizeof(*in4) : sizeof(*in6), 0);
	if (r)
		goto release_sock;

	*sockp = sock;
	return 0;

release_sock:
	sock_release(sock);
	return r;
}

int ksock_create_host(struct socket **sockp, char *host, int port)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	struct socket		*sock = NULL;
	int			error;
	int			option;
	mm_segment_t		oldmm = get_fs();

	error = ksock_pton(host, strlen(host), &addr);
	if (error) {
		error = ksock_dns_resolve(host, &addr);
		if (error)
			return error;
	}

	error = sock_create(addr.ss_family, SOCK_STREAM, 0, &sock);
	if (error)
		return error;

	set_fs(KERNEL_DS);
	option = 1;
	error = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	if (error)
		goto out_sock_release;

	ksock_addr_set_port(&addr, port);

	error = sock->ops->bind(sock, (struct sockaddr *)&addr,
		(addr.ss_family == AF_INET) ? sizeof(*in4) : sizeof(*in6));

	if (error == -EADDRINUSE)
		goto out_sock_release;

	if (error)
		goto out_sock_release;

	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
	return error;
}

int ksock_listen_host(struct socket **sockp, char *host, int port, int backlog)
{
	int error;
	struct socket *sock = NULL;

	error = ksock_create_host(&sock, host, port);
	if (error)
		return error;

	error = sock->ops->listen(sock, backlog);
	if (error)
		goto out;

	*sockp = sock;
	return 0;
out:
	sock_release(sock);
	return error;
}
