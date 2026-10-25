! E04 probe (sparc64): `ta 0x6d` dual-carry convention + `rt_signal_frame64`
! (528 B) layout. Freestanding SPARC V9 (-m64 -nostdlib -static).
! Exit code 0 = all critical checks pass; 1 = self-check FAIL.
!
! SPARC64 Linux numbers (asm/unistd_64.h): exit=1 read=3 write=4 close=6
! getpid=20 kill=37 rt_sigreturn=101 rt_sigaction=102 exit_group=188.
! SPARC signals (asm/signal.h): SIGUSR1=30, SA_SIGINFO=0x200.
!
! Helper discipline: puts/puthex16/putc take input in %g2 and clobber only
! %g1,%g2,%g3,%o0-%o4. All cross-call state lives in BSS (handler keeps its
! base in %l1, which helpers never touch); snapshot every value to BSS
! value to BSS before printing (traps preserve %g2-%g7, helpers do not).
	.text
	.align 4
	.register %g2, #scratch
	.register %g3, #scratch
			.global _start
_start:
	! --- initial %sp: unbiased (%sp+2047) must be 16-byte aligned ---
	mov %sp, %l1
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	stx %l1, [%g2]
	sethi %hi(msg_sp0), %g2
	or %g2, %lo(msg_sp0), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2], %g2
	add %g2, 2047, %g2
	andcc %g2, 15, %g0
	bnz fail
	nop

	! --- dump our own `ta` encoding: expect 0x91d0206d ---
	sethi %hi(msg_ta), %g2
	or %g2, %lo(msg_ta), %g2
	call puts
	nop
	sethi %hi(ta1), %g2
	or %g2, %lo(ta1), %g2
	ld [%g2], %g2
	srl %g2, 0, %g2			! zero-extend the 32-bit word
	sethi %hi(snap), %g3
	or %g3, %lo(snap), %g3
	stx %g2, [%g3 + 8]
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 8], %g2
	sethi %hi(0x91d02000), %g3
	or %g3, %lo(0x91d02000), %g3
	add %g3, 0x6d, %g3
	cmp %g2, %g3
	bne fail
	nop

	! --- getpid(20): success clears BOTH icc.C and xcc.C ---
	mov 20, %g1
ta1:	ta 0x6d
	bcs fail
	nop
	bcs %xcc, fail
	nop
	tst %o0
	ble fail
	nop
	mov %o0, %l1
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	stx %l1, [%g2 + 16]		! snap pid
	sethi %hi(msg_pid), %g2
	or %g2, %lo(msg_pid), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 16], %g2
	call puthex16
	nop
	call putnl
	nop

	! --- error case: close(-1) -> BOTH carries set, %o0 = EBADF(9) ---
	mov 6, %g1
	mov -1, %o0
	ta 0x6d
	bcc fail
	nop
	bcc %xcc, fail
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	stx %o0, [%g2 + 24]		! snap errno BEFORE any call
	sethi %hi(msg_errno), %g2
	or %g2, %lo(msg_errno), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 24], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 24], %g2
	cmp %g2, 9
	bne fail
	nop

	! --- build struct sigaction {handler, SA_SIGINFO, 0, mask=0} ---
	sethi %hi(handler), %g3
	or %g3, %lo(handler), %g3
	sethi %hi(act), %g2
	or %g2, %lo(act), %g2
	stx %g3, [%g2]
	mov 0x200, %g3
	stx %g3, [%g2 + 8]
	stx %g0, [%g2 + 16]
	stx %g0, [%g2 + 24]
	! rt_sigaction(30, &act, NULL, restorer, 8): SPARC 5-arg convention,
	! restorer in %o3, sigsetsize in %o4 (qemu mirrors arch/sparc).
	mov 30, %o0
	sethi %hi(act), %g3
	or %g3, %lo(act), %g3
	mov %g3, %o1
	mov 0, %o2
	sethi %hi(rest), %g3
	or %g3, %lo(rest), %g3
	mov %g3, %o3
	mov 8, %o4
	mov 102, %g1
	ta 0x6d
	bcs fail
	nop
	bcs %xcc, fail
	nop
	sethi %hi(msg_saok), %g2
	or %g2, %lo(msg_saok), %g2
	call puts
	nop

	! --- canary + kill(self, SIGUSR1=30) ---
	set 0xe04ca4e, %g3
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	stx %g3, [%g2 + 32]
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 16], %o0		! pid
	mov 30, %o1
	mov 37, %g1
	ta 0x6d				! kill: handler runs before return
	bcs fail
	nop
	bcs %xcc, fail
	nop
	! bounded spin for h_flag (self-signal is synchronous; insurance)
	set 2000000, %o4
	sethi %hi(h_flag), %g3
	or %g3, %lo(h_flag), %g3
spin:	lduw [%g3], %g2
	tst %g2
	bnz resumed
	nop
	subcc %o4, 1, %o4
	bne spin
	nop
	sethi %hi(msg_nohdl), %g2
	or %g2, %lo(msg_nohdl), %g2
	call puts
	nop
	ba fail
	nop
resumed:
	sethi %hi(msg_resumed), %g2
	or %g2, %lo(msg_resumed), %g2
	call puts
	nop
	! canary intact?
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 32], %g2
	set 0xe04ca4e, %g3
	cmp %g2, %g3
	bne fail
	nop
	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 188, %g1
	ta 0x6d				! exit_group(0)

! ---------- SA_SIGINFO handler ----------
! Entry (leaf, no save yet): %o0=signo %o1=&info %o2=&sigcontext
! %o6=%sp (biased) %o7=restorer. Preserve %o6; end with rt_sigreturn.
	.align 4
handler:
	! snapshot entry state first (helpers clobber %g1-%g3,%o0-%o2)
	sethi %hi(hsnap), %l1
	or %l1, %lo(hsnap), %l1
	stx %o0, [%l1]
	stx %o1, [%l1 + 8]
	stx %o2, [%l1 + 16]
	stx %o6, [%l1 + 24]
	stx %o7, [%l1 + 32]
	! unbiased = sp + 2047
	add %o6, 2047, %g2
	stx %g2, [%l1 + 40]
	sethi %hi(msg_sig), %g2
	or %g2, %lo(msg_sig), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2], %g2
	call puthex16
	nop
	call putnl
	nop
	! print info/uctx/sp/unbiased/ret
	sethi %hi(msg_info), %g2
	or %g2, %lo(msg_info), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_uctx), %g2
	or %g2, %lo(msg_uctx), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 16], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_hsp), %g2
	or %g2, %lo(msg_hsp), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 24], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_un), %g2
	or %g2, %lo(msg_un), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 40], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_ret), %g2
	or %g2, %lo(msg_ret), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 32], %g2
	call puthex16
	nop
	call putnl
	nop
	! --- critical: entry %o7 == restorer address (I7 = ka_restorer) ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 32], %g3
	sethi %hi(rest), %g2
	or %g2, %lo(rest), %g2
	cmp %g3, %g2
	bne fail
	nop
	! --- critical: signo == 30 ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2], %g2
	cmp %g2, 30
	bne fail
	nop
	! --- critical: unbiased 16-byte aligned ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 40], %g2
	andcc %g2, 15, %g0
	bnz fail
	nop
	! --- siginfo words via %o1 ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g3		! info ptr
	lduw [%g3], %g2			! si_signo
	stx %g2, [%l1 + 48]
	sethi %hi(msg_sisigno), %g2
	or %g2, %lo(msg_sisigno), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 48], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_sierrno), %g2
	or %g2, %lo(msg_sierrno), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g3
	lduw [%g3 + 4], %g2		! si_errno
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g3
	lduw [%g3 + 8], %g2		! si_code
	stx %g2, [%l1 + 56]
	sethi %hi(msg_sicode), %g2
	or %g2, %lo(msg_sicode), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 56], %g2
	call puthex16
	nop
	call putnl
	nop
	! --- critical: si_signo == 30, si_code == SI_USER(0) ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 48], %g2
	cmp %g2, 30
	bne fail
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 56], %g2
	tst %g2
	bnz fail
	nop
	! --- frame fields at SPEC offsets off unbiased ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 40], %g3		! un
	ldx [%g3 + 0x70], %g2		! ss.fp
	stx %g2, [%l1 + 64]
	ldx [%g3 + 0x78], %g2		! ss.callers_pc
	stx %g2, [%l1 + 72]
	ldx [%g3 + 0x1c0], %g2		! regs.tstate
	stx %g2, [%l1 + 80]
	ldx [%g3 + 0x1c8], %g2		! regs.tpc
	stx %g2, [%l1 + 88]
	ldx [%g3 + 0x1d0], %g2		! regs.tnpc
	stx %g2, [%l1 + 96]
	lduw [%g3 + 0x1dc], %g2		! regs.magic
	stx %g2, [%l1 + 104]
	ldx [%g3 + 0x1e0], %g2		! fpu_save
	stx %g2, [%l1 + 112]
	ldx [%g3 + 0x1e8], %g2		! stack.ss_sp
	stx %g2, [%l1 + 120]
	ldx [%g3 + 0x1f8], %g2		! stack.ss_size
	stx %g2, [%l1 + 128]
	ldx [%g3 + 0x200], %g2		! mask
	stx %g2, [%l1 + 136]
	ldx [%g3 + 0x208], %g2		! rwin_save
	stx %g2, [%l1 + 144]
	! print ss_fp, tpc, tnpc, tstate
	sethi %hi(msg_ssfp), %g2
	or %g2, %lo(msg_ssfp), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 64], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_tpc), %g2
	or %g2, %lo(msg_tpc), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 88], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_tnpc), %g2
	or %g2, %lo(msg_tnpc), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 96], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_tstate), %g2
	or %g2, %lo(msg_tstate), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 80], %g2
	call puthex16
	nop
	call putnl
	nop
	! print fpu, mask, rwin
	sethi %hi(msg_fpu), %g2
	or %g2, %lo(msg_fpu), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 112], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_mask), %g2
	or %g2, %lo(msg_mask), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 136], %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_rwin), %g2
	or %g2, %lo(msg_rwin), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 144], %g2
	call puthex16
	nop
	call putnl
	nop
	! --- critical: tpc inside probe text [_start, text_end) ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 88], %g3		! tpc
	sethi %hi(_start), %g2
	or %g2, %lo(_start), %g2
	cmp %g3, %g2
	bcs fail
	nop
	sethi %hi(text_end), %g2
	or %g2, %lo(text_end), %g2
	cmp %g2, %g3
	bcs fail
	nop
	! --- record i1-un and i2-un diffs (expect 0xC0 per kernel) ---
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g3		! i1
	ldx [%g2 + 40], %o4		! un
	sub %g3, %o4, %g2
	sethi %hi(msg_di1), %g2
	or %g2, %lo(msg_di1), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 8], %g3
	ldx [%g2 + 40], %o4
	sub %g3, %o4, %g2
	call puthex16
	nop
	call putnl
	nop
	sethi %hi(msg_di2), %g2
	or %g2, %lo(msg_di2), %g2
	call puts
	nop
	sethi %hi(hsnap), %g2
	or %g2, %lo(hsnap), %g2
	ldx [%g2 + 16], %g3		! i2
	ldx [%g2 + 40], %o4
	sub %g3, %o4, %g2
	call puthex16
	nop
	call putnl
	nop
	! flag = 1, then rt_sigreturn (never returns)
	sethi %hi(h_flag), %g2
	or %g2, %lo(h_flag), %g2
	mov 1, %g3
	st %g3, [%g2]
	mov 101, %g1
	ta 0x6d				! rt_sigreturn
	ba fail				! must not return
	nop

! restorer trampoline: handler return address (%o7) lands here.
	.align 4
rest:
	mov 101, %g1
	ta 0x6d				! rt_sigreturn

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 188, %g1
	ta 0x6d
text_end:

! ---------- helpers ----------
! puts: %g2 = NUL-terminated string. Clobbers %g1,%g2,%g3,%o0-%o4.
puts:
	mov %g2, %o4
1:	ldub [%o4], %g3
	tst %g3
	bz 2f
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
! puthex16: %g2 = u64 value, prints 16 lowercase hex digits.
puthex16:
	sethi %hi(hexbuf), %g3
	or %g3, %lo(hexbuf), %g3
	mov 60, %o2
1:	srlx %g2, %o2, %g1
	and %g1, 0xf, %g1
	cmp %g1, 10
	bl 2f
	nop
	add %g1, 'a' - 10, %g1
	ba 3f
	nop
2:	add %g1, '0', %g1
3:	stb %g1, [%g3]
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
! putc: %g2 = char (low 8 bits).
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
msg_sp0:	.asciz "sp0="
msg_ta:		.asciz "ta6d="
msg_pid:	.asciz "pid="
msg_errno:	.asciz "close(-1) errno="
msg_saok:	.asciz "sigaction ok\n"
msg_nohdl:	.asciz "no handler\n"
msg_resumed:	.asciz "resumed\n"
msg_sig:	.asciz "sig="
msg_info:	.asciz "info="
msg_uctx:	.asciz "uctx="
msg_hsp:	.asciz "hsp="
msg_un:		.asciz "un="
msg_ret:	.asciz "ret="
msg_sisigno:	.asciz "si_signo="
msg_sierrno:	.asciz "si_errno="
msg_sicode:	.asciz "si_code="
msg_ssfp:	.asciz "ss_fp="
msg_tpc:	.asciz "tpc="
msg_tnpc:	.asciz "tnpc="
msg_tstate:	.asciz "tstate="
msg_fpu:	.asciz "fpu="
msg_mask:	.asciz "mask="
msg_rwin:	.asciz "rwin="
msg_di1:	.asciz "i1-un="
msg_di2:	.asciz "i2-un="
msg_pass:	.asciz "E04-PASS\n"
msg_fail:	.asciz "E04-FAIL\n"
	.section .bss
	.align 8
hexbuf:	.skip 16
charbuf:	.skip 8
snap:	.skip 40
act:	.skip 32
hsnap:	.skip 152
h_flag:	.skip 8
