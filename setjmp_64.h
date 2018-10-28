#pragma once

struct kernel_jmp_buf {
	unsigned long rbx;
	unsigned long rsp;
	unsigned long rbp;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long rip;
};

extern int kernel_setjmp(struct kernel_jmp_buf *ctx);
extern void kernel_longjmp(struct kernel_jmp_buf *ctx, int value);
extern unsigned long kernel_get_rsp(void);
