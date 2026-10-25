! E06 probe: SPARC V9 (sparc64) thread pointer %g7, fork child semantics,
! clone(2) with CLONE_SETTLS.
!
! Freestanding V9: sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static.
! Syscalls: ta 0x6d (encodes as 0x91d0206d), number in %g1, args in
! %o0..%o5, return in %o0.
! Numbers verified against /usr/sparc64-linux-gnu/include/asm/unistd_64.h
! in the oracle image: exit=1 fork=2 write=4 wait4=7 getpid=20 clone=217.
! SIGCHLD=20 verified against asm/signal.h.
! CLONE_SETTLS=0x00080000 verified against linux/sched.h.
! Register discipline: gas only allows .register for %g2,%g3,%g6,%g7
! (%g1 is scratch, %g4/%g5 are reserved), so all hand-managed state uses
! %g2/%g3 as temps and %g6 as the single value saved across calls.
! Helpers (puts/puthex64/putc/putnl) clobber %g1-%g3 and %o0-%o2 only;
! they never touch %g6 or %g7.
! Exit code 0 = probe completed (all lines printed); 1 = self-check FAIL.
	.register %g2, #scratch
	.register %g3, #scratch
	.register %g6, #scratch
	.register %g7, #scratch
	.text
	.balign 16
	.global _start
_start:
	! --- 1. initial %g7 at process entry ---
	sethi %hi(msg_g7init), %g2
	or %g2, %lo(msg_g7init), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- 2. getpid sanity (validates the ta 0x6d trap path) ---
	sethi %hi(msg_pid), %g2
	or %g2, %lo(msg_pid), %g2
	call puts
	nop
	mov 20, %g1
	ta 0x6d
	mov %o0, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- 3. write %g7 = TP_MARK, read back ---
	sethi %hi(tpmark), %g2
	or %g2, %lo(tpmark), %g2
	ldx [%g2], %g2
	mov %g2, %g7
	sethi %hi(msg_g7set), %g2
	or %g2, %lo(msg_g7set), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- 4. TP-relative access: %g7 -> tpscratch, stx/ldx [%g7+16] ---
	sethi %hi(tpscratch), %g2
	or %g2, %lo(tpscratch), %g2
	mov %g2, %g7
	sethi %hi(tpval), %g2
	or %g2, %lo(tpval), %g2
	ldx [%g2], %g2
	stx %g2, [%g7 + 16]
	ldx [%g7 + 16], %g6
	sethi %hi(msg_tprel), %g2
	or %g2, %lo(msg_tprel), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	! restore %g7 = TP_MARK
	sethi %hi(tpmark), %g2
	or %g2, %lo(tpmark), %g2
	ldx [%g2], %g2
	mov %g2, %g7
	sethi %hi(msg_g7rest), %g2
	or %g2, %lo(msg_g7rest), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- 5. fork: child sees ret 0, parent sees child pid; %g7 equal? ---
	mov 2, %g1
	ta 0x6d
	mov %o0, %g6
	tst %g6
	be child_fork
	nop
parent_fork:
	! serialize: reap the child first, print afterwards
	mov -1, %o0
	sethi %hi(wstat), %o1
	or %o1, %lo(wstat), %o1
	mov 0, %o2
	mov 0, %o3
	mov 7, %g1
	ta 0x6d
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	stx %o0, [%g2]
	sethi %hi(msg_forkp_ret), %g2
	or %g2, %lo(msg_forkp_ret), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_forkp_g7), %g2
	or %g2, %lo(msg_forkp_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_wait), %g2
	or %g2, %lo(msg_wait), %g2
	call puts
	nop
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	ldx [%g2], %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_wstat), %g2
	or %g2, %lo(msg_wstat), %g2
	call puts
	nop
	sethi %hi(wstat), %g2
	or %g2, %lo(wstat), %g2
	ldx [%g2], %g2
	call puthex64
	nop
	call putnl
	nop
	ba after_fork
	nop
child_fork:
	sethi %hi(msg_forkc_ret), %g2
	or %g2, %lo(msg_forkc_ret), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_forkc_g7), %g2
	or %g2, %lo(msg_forkc_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d
after_fork:

	! --- 6. clone A: SIGCHLD|CLONE_SETTLS, tls value in %o4 ---
	sethi %hi(clstack_top), %g2
	or %g2, %lo(clstack_top), %g2
	mov %g2, %o1
	sethi %hi(0x80014), %o0
	or %o0, %lo(0x80014), %o0
	mov 0, %o2
	mov 0, %o3
	sethi %hi(tlsa), %g2
	or %g2, %lo(tlsa), %g2
	ldx [%g2], %o4
	mov 217, %g1
	ta 0x6d
	mov %o0, %g6
	tst %g6
	be child_cla
	nop
parent_cla:
	! serialize: reap the child first, print afterwards
	mov -1, %o0
	sethi %hi(wstat), %o1
	or %o1, %lo(wstat), %o1
	mov 0, %o2
	mov 0, %o3
	mov 7, %g1
	ta 0x6d
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	stx %o0, [%g2]
	sethi %hi(msg_clap_ret), %g2
	or %g2, %lo(msg_clap_ret), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_clap_g7), %g2
	or %g2, %lo(msg_clap_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_waita), %g2
	or %g2, %lo(msg_waita), %g2
	call puts
	nop
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	ldx [%g2], %g2
	call puthex64
	nop
	call putnl
	nop
	ba after_cla
	nop
child_cla:
	sethi %hi(msg_clac_g7), %g2
	or %g2, %lo(msg_clac_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d
after_cla:

	! --- 7. clone B: SIGCHLD|CLONE_SETTLS, tls value in %o3, %o4 = 0 ---
	sethi %hi(clstack_top), %g2
	or %g2, %lo(clstack_top), %g2
	mov %g2, %o1
	sethi %hi(0x80014), %o0
	or %o0, %lo(0x80014), %o0
	mov 0, %o2
	sethi %hi(tlsb), %g2
	or %g2, %lo(tlsb), %g2
	ldx [%g2], %o3
	mov 0, %o4
	mov 217, %g1
	ta 0x6d
	mov %o0, %g6
	tst %g6
	be child_clb
	nop
parent_clb:
	! serialize: reap the child first, print afterwards
	mov -1, %o0
	sethi %hi(wstat), %o1
	or %o1, %lo(wstat), %o1
	mov 0, %o2
	mov 0, %o3
	mov 7, %g1
	ta 0x6d
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	stx %o0, [%g2]
	sethi %hi(msg_clbp_ret), %g2
	or %g2, %lo(msg_clbp_ret), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_clbp_g7), %g2
	or %g2, %lo(msg_clbp_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_waitb), %g2
	or %g2, %lo(msg_waitb), %g2
	call puts
	nop
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	ldx [%g2], %g2
	call puthex64
	nop
	call putnl
	nop
	ba after_clb
	nop
child_clb:
	sethi %hi(msg_clbc_g7), %g2
	or %g2, %lo(msg_clbc_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d
after_clb:

	! --- 8. clone C: SIGCHLD|CLONE_SETTLS, DISTINCT tls in %o3 AND %o4 ---
	sethi %hi(clstack_top), %g2
	or %g2, %lo(clstack_top), %g2
	mov %g2, %o1
	sethi %hi(0x80014), %o0
	or %o0, %lo(0x80014), %o0
	mov 0, %o2
	sethi %hi(tlsc3), %g2
	or %g2, %lo(tlsc3), %g2
	ldx [%g2], %o3
	sethi %hi(tlsc4), %g2
	or %g2, %lo(tlsc4), %g2
	ldx [%g2], %o4
	mov 217, %g1
	ta 0x6d
	mov %o0, %g6
	tst %g6
	be child_clc
	nop
parent_clc:
	! serialize: reap the child first, print afterwards
	mov -1, %o0
	sethi %hi(wstat), %o1
	or %o1, %lo(wstat), %o1
	mov 0, %o2
	mov 0, %o3
	mov 7, %g1
	ta 0x6d
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	stx %o0, [%g2]
	sethi %hi(msg_clcp_ret), %g2
	or %g2, %lo(msg_clcp_ret), %g2
	call puts
	nop
	mov %g6, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_clcp_g7), %g2
	or %g2, %lo(msg_clcp_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	sethi %hi(msg_waitc), %g2
	or %g2, %lo(msg_waitc), %g2
	call puts
	nop
	sethi %hi(wret), %g2
	or %g2, %lo(wret), %g2
	ldx [%g2], %g2
	call puthex64
	nop
	call putnl
	nop
	ba after_clc
	nop
child_clc:
	sethi %hi(msg_clcc_g7), %g2
	or %g2, %lo(msg_clcc_g7), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex64
	nop
	call putnl
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d
after_clc:

	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x6d

! ---------- helpers (leaf: no SAVE, touch no stack) ----------
puts:
	mov %g2, %o4
1:	ldub [%o4], %g3
	tst %g3
	be 2f
	nop
	add %o4, 1, %o4
	ba 1b
	nop
2:	sub %o4, %g2, %o2
	mov %g2, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x6d
	retl
	nop
puthex64:
	sethi %hi(hexbuf), %g3
	or %g3, %lo(hexbuf), %g3
	mov 60, %o2
1:	srlx %g2, %o2, %o4
	and %o4, 0xf, %o4
	cmp %o4, 10
	bl 2f
	nop
	add %o4, 'a' - 10, %o4
	ba 3f
	nop
2:	add %o4, '0', %o4
3:	stb %o4, [%g3]
	add %g3, 1, %g3
	subcc %o2, 4, %o2
	bge 1b
	nop
	sethi %hi(hexbuf), %o1
	or %o1, %lo(hexbuf), %o1
	mov 1, %o0
	mov 16, %o2
	mov 4, %g1
	ta 0x6d
	retl
	nop
putnl:
	mov 10, %g2
	ba putc
	nop
putc:
	sethi %hi(charbuf), %g3
	or %g3, %lo(charbuf), %g3
	stb %g2, [%g3]
	mov 1, %o0
	mov %g3, %o1
	mov 1, %o2
	mov 4, %g1
	ta 0x6d
	retl
	nop

	.data
	.balign 8
tpmark:	.xword 0x123456789abcdef0
tpval:	.xword 0x0badc0de0badc0de
tlsa:	.xword 0x5e7715a55e7715a5
tlsb:	.xword 0x5e7715b55e7715b5
tlsc3:	.xword 0x5e771c355e771c35
tlsc4:	.xword 0x5e771c455e771c45
msg_g7init:	.asciz "g7init="
msg_pid:	.asciz "pid="
msg_g7set:	.asciz "g7set="
msg_tprel:	.asciz "tprel="
msg_g7rest:	.asciz "g7rest="
msg_forkc_ret:	.asciz "fork-c ret="
msg_forkc_g7:	.asciz "fork-c g7="
msg_forkp_ret:	.asciz "fork-p ret="
msg_forkp_g7:	.asciz "fork-p g7="
msg_wait:	.asciz "wait="
msg_wstat:	.asciz "wstat="
msg_clac_g7:	.asciz "cloneA-c g7="
msg_clap_ret:	.asciz "cloneA-p ret="
msg_clap_g7:	.asciz "cloneA-p g7="
msg_waita:	.asciz "waitA="
msg_clbc_g7:	.asciz "cloneB-c g7="
msg_clbp_ret:	.asciz "cloneB-p ret="
msg_clbp_g7:	.asciz "cloneB-p g7="
msg_waitb:	.asciz "waitB="
msg_clcc_g7:	.asciz "cloneC-c g7="
msg_clcp_ret:	.asciz "cloneC-p ret="
msg_clcp_g7:	.asciz "cloneC-p g7="
msg_waitc:	.asciz "waitC="
msg_pass:	.asciz "E06-PASS\n"
msg_fail:	.asciz "E06-FAIL\n"
	.section .bss
	.balign 16
tpscratch:	.skip 64
	.balign 16
clstack:	.skip 8192
clstack_top:
	.balign 8
wstat:	.skip 8
wret:	.skip 8
hexbuf:	.skip 16
charbuf:	.skip 8
