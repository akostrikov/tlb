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

int ksock_set_reuse_addr(struct socket *sock, bool reuse)
{
	int r;
	int option;
	mm_segment_t oldmm;

	option = (reuse) ? 1 : 0;

	oldmm = get_fs();
	set_fs(KERNEL_DS);
	option = 1;
	r = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	set_fs(oldmm);
	return r;
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

void ksock_release(struct socket *sock)
{
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}

int ksock_send(struct socket *sock, void *buf, int len)
{
	struct kvec iov = {buf, len};
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL | MSG_EOR;
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &iov, 1, len);

	return sock_sendmsg(sock, &msg);
}

int ksock_recv(struct socket *sock, void *buf, int len)
{
	struct kvec iov = {buf, len};
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, len);

	return sock_recvmsg(sock, &msg, msg.msg_flags);
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

static int ksock_pton(const char *ip, int ip_len, struct sockaddr_storage *ss)
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

static int ksock_dns_resolve(const char *name, struct sockaddr_storage *ss)
{
	int ip_len, r;
	char *ip_addr = NULL;

	ip_len = dns_query(NULL, name, strlen(name), NULL, &ip_addr, NULL);
	if (ip_len > 0)
		r = ksock_pton(ip_addr, ip_len, ss);
	else
		r = -ESRCH;
	kfree(ip_addr);
	return r;
}

int ksock_resolve_addr(const char *host, u16 port, struct sockaddr_storage *addr)
{
	int r;

	r = ksock_pton(host, strlen(host), addr);
	if (r) {
		r = ksock_dns_resolve(host, addr);
		if (r)
			return r;
	}
	ksock_addr_set_port(addr, port);
	return r;
}

int ksock_connect_host(struct socket **sockp, const char *host, u16 port, struct ksock_callbacks *callbacks)
{
	struct sockaddr_storage addr;
	int r;

	r = ksock_resolve_addr(host, port, &addr);
	if (r)
		return r;

	return ksock_connect_addr(sockp, &addr, callbacks);
}

int ksock_connect_addr(struct socket **sockp, struct sockaddr_storage *addr, struct ksock_callbacks *callbacks)
{
	int r;
	struct socket *sock;

	r = sock_create(addr->ss_family, SOCK_STREAM, 0, &sock);
	if (r)
		return r;

	r = sock->ops->connect(sock, (struct sockaddr *)addr,
		(addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), O_NONBLOCK);
	if (r) {
		if (r != -EINPROGRESS)
			goto release_sock;
	}

	if (callbacks) {
		struct sock *sk = sock->sk;
		
		sk->sk_user_data = callbacks->user_data;
		sk->sk_data_ready = callbacks->data_ready;
		sk->sk_write_space = callbacks->write_space;
		sk->sk_state_change = callbacks->state_change;
	}

	*sockp = sock;
	return 0;

release_sock:
	sock_release(sock);
	return r;
}

int ksock_listen_addr(struct socket **sockp, struct sockaddr_storage *addr, int backlog)
{
	int r;
	struct socket *sock = NULL;

	r = sock_create(addr->ss_family, SOCK_STREAM, 0, &sock);
	if (r)
		return r;

	r = ksock_set_reuse_addr(sock, true);
	if (r)
		goto out_sock_release;

	r = sock->ops->bind(sock, (struct sockaddr *)addr,
		(addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

	r = sock->ops->listen(sock, backlog);
	if (r)
		goto out_sock_release;

	*sockp = sock;
	return 0;
out_sock_release:
	sock_release(sock);
	return r;
}
