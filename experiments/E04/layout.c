/* E04 layout check (sparc64): sizeof/offsetof for rt_signal_frame64 members.
 * Curated C11, no VLAs. Built against the cross glibc headers and run under
 * qemu-sparc64; output is pasted into FINDINGS.md.
 */
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <ucontext.h>
#include <asm/ptrace.h>

#define SZ(t) printf("sizeof(" #t ")=%zu\n", sizeof(t))

int main(void)
{
	SZ(sigset_t);
	SZ(struct sigaction);
	printf("off(sa_handler)=%zu\n", offsetof(struct sigaction, sa_handler));
	printf("off(sa_flags)=%zu\n", offsetof(struct sigaction, sa_flags));
	printf("off(sa_restorer)=%zu\n",
	    offsetof(struct sigaction, sa_restorer));
	printf("off(sa_mask)=%zu\n", offsetof(struct sigaction, sa_mask));
	SZ(struct sparc_stackf);
	printf("off(locals)=%zu\n", offsetof(struct sparc_stackf, locals));
	printf("off(ins)=%zu\n", offsetof(struct sparc_stackf, ins));
	printf("off(fp)=%zu\n", offsetof(struct sparc_stackf, fp));
	printf("off(callers_pc)=%zu\n",
	    offsetof(struct sparc_stackf, callers_pc));
	printf("off(structptr)=%zu\n",
	    offsetof(struct sparc_stackf, structptr));
	printf("off(xargs)=%zu\n", offsetof(struct sparc_stackf, xargs));
	printf("off(xxargs)=%zu\n", offsetof(struct sparc_stackf, xxargs));
	SZ(struct pt_regs);
	printf("off(u_regs)=%zu\n", offsetof(struct pt_regs, u_regs));
	printf("off(tstate)=%zu\n", offsetof(struct pt_regs, tstate));
	printf("off(tpc)=%zu\n", offsetof(struct pt_regs, tpc));
	printf("off(tnpc)=%zu\n", offsetof(struct pt_regs, tnpc));
	printf("off(y)=%zu\n", offsetof(struct pt_regs, y));
	printf("off(magic)=%zu\n", offsetof(struct pt_regs, magic));
	SZ(siginfo_t);
	printf("off(si_signo)=%zu\n", offsetof(siginfo_t, si_signo));
	printf("off(si_errno)=%zu\n", offsetof(siginfo_t, si_errno));
	printf("off(si_code)=%zu\n", offsetof(siginfo_t, si_code));
	SZ(stack_t);
	printf("off(ss_sp)=%zu\n", offsetof(stack_t, ss_sp));
	printf("off(ss_flags)=%zu\n", offsetof(stack_t, ss_flags));
	printf("off(ss_size)=%zu\n", offsetof(stack_t, ss_size));
	printf("frame_total=%zu\n",
	    sizeof(struct sparc_stackf) + sizeof(siginfo_t) +
	    sizeof(struct pt_regs) + 8u + sizeof(stack_t) + 8u + 8u);
	printf("SIGUSR1=%d SA_SIGINFO=0x%x\n", SIGUSR1, SA_SIGINFO);
	printf("ucontext=%zu\n", sizeof(ucontext_t));
	return 0;
}
