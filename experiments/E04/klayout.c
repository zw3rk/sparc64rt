/* E04 kernel-ABI layout check (sparc64): the types the rt_sigaction syscall
 * and rt_signal_frame64 actually use (uapi headers, NOT libc types).
 * Curated C11, no VLAs.
 */
#include <stddef.h>
#include <stdio.h>
#include <asm/signal.h>
#include <asm/ptrace.h>

int main(void)
{
	printf("k_sigset=%zu\n", sizeof(__new_sigset_t));
	printf("k_sigaction=%zu\n", sizeof(struct __new_sigaction));
	printf("k_sa_handler=%zu\n",
	    offsetof(struct __new_sigaction, sa_handler));
	printf("k_sa_flags=%zu\n",
	    offsetof(struct __new_sigaction, sa_flags));
	printf("k_sa_restorer=%zu\n",
	    offsetof(struct __new_sigaction, sa_restorer));
	printf("k_sa_mask=%zu\n",
	    offsetof(struct __new_sigaction, sa_mask));
	printf("k_stackf=%zu fp=%zu cpc=%zu\n",
	    sizeof(struct sparc_stackf),
	    offsetof(struct sparc_stackf, fp),
	    offsetof(struct sparc_stackf, callers_pc));
	printf("k_ptregs=%zu tstate=%zu tpc=%zu tnpc=%zu\n",
	    sizeof(struct pt_regs),
	    offsetof(struct pt_regs, tstate),
	    offsetof(struct pt_regs, tpc),
	    offsetof(struct pt_regs, tnpc));
	printf("k_stackt=%zu sp=%zu flags=%zu size=%zu\n",
	    sizeof(stack_t),
	    offsetof(stack_t, ss_sp),
	    offsetof(stack_t, ss_flags),
	    offsetof(stack_t, ss_size));
	printf("k_frame_total=%zu\n",
	    sizeof(struct sparc_stackf) + 128u + sizeof(struct pt_regs) +
	    8u + sizeof(stack_t) + sizeof(__new_sigset_t) + 8u);
	return 0;
}
