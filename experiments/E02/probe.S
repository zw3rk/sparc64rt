! E02 probe: dual carry-flag update — CCR.icc.C (bit 0) & CCR.xcc.C (bit 4).
! Freestanding SPARC V9 (-m64 default, -nostdlib -static).
! Syscalls via ta 0x6d (= 0x91d0206d): write=4, exit=1, getpid=20.
! *cc ALU checks use %l0 (observed CCR) / %l1 (observed result) so helper
! calls cannot clobber the evidence; no SAVE/RESTORE is used.
! exit code 0 = all verified; 1 = FAIL (message printed first).
! %g2-%g4 are ours (not toolchain-reserved): declare them scratch so
! sparc64 GAS accepts them without .register warnings-as-errors.
	.register %g2, #scratch
	.register %g3, #scratch
	.text
	.align 4
	.global _start
_start:
	sethi %hi(msg_banner), %g2
	or %g2, %lo(msg_banner), %g2
	call puts
	nop

	! --- T1: 32-bit carry only: 0x00000000ffffffff + 1 = 0x100000000 ---
	! Expect CCR=0x05 (icc: N=0,Z=1,V=0,C=1 ; xcc: N=0,Z=0,V=0,C=0).
	mov -1, %g1
	srl %g1, 0, %g1			! zero-extend -> 0x00000000ffffffff
	addcc %g1, 1, %g5
	rd %ccr, %l0
	mov %g5, %l1
	and %l0, 0xff, %g4
	cmp %g4, 0x05
	bne fail
	nop
	srlx %l1, 32, %g4		! high32 == 1 ?
	cmp %g4, 1
	bne fail
	nop
	srl %l1, 0, %g4			! low32 == 0 ?
	cmp %g4, 0
	bne fail
	nop
	sethi %hi(msg_t1), %g2
	or %g2, %lo(msg_t1), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- T2: 64-bit carry: 0xffffffffffffffff + 1 = 0 ---
	! Expect CCR=0x55 (both N=0,Z=1,V=0,C=1).
	mov -1, %g1
	addcc %g1, 1, %g5
	rd %ccr, %l0
	mov %g5, %l1
	cmp %l1, 0
	bne fail
	nop
	and %l0, 0xff, %g4
	cmp %g4, 0x55
	bne fail
	nop
	sethi %hi(msg_t2), %g2
	or %g2, %lo(msg_t2), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- T3: no carry: 2 + 3 = 5 --- Expect CCR=0x00.
	mov 2, %g1
	addcc %g1, 3, %g5
	rd %ccr, %l0
	mov %g5, %l1
	cmp %l1, 5
	bne fail
	nop
	and %l0, 0xff, %g4
	cmp %g4, 0
	bne fail
	nop
	sethi %hi(msg_t3), %g2
	or %g2, %lo(msg_t3), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- T4: sub borrow: 0 - 1 = -1, borrow SETS both C ---
	! Expect CCR=0x99 (both N=1,Z=0,V=0,C=1): SUBcc C = borrow, i.e.
	! C=1 iff src1 < src2 unsigned (cross-checked: blu, a synonym of
	! bcs, IS taken for 0-1, and bleu/bgu behave accordingly).
	subcc %g0, 1, %g5
	rd %ccr, %l0
	mov %g5, %l1
	cmp %l1, -1
	bne fail
	nop
	and %l0, 0xff, %g4
	cmp %g4, 0x99
	bne fail
	nop
	sethi %hi(msg_t4), %g2
	or %g2, %lo(msg_t4), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- T5: ta 0x6d success (getpid): xcc.C cleared, rest preserved ---
	! Oracle rule (see FINDINGS): success clears xcc.C only; icc.C and
	! N/Z/V are preserved. Helpers clobber CCR, so the pre-state is
	! re-established immediately before the trap (no *cc in between).
	subcc %g0, 1, %g0		! ccr=0x99: both C set
	rd %ccr, %l0
	and %l0, 0xff, %g4		! precondition: full byte 0x99
	cmp %g4, 0x99
	bne fail
	nop
	sethi %hi(msg_t5pre), %g2
	or %g2, %lo(msg_t5pre), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop
	subcc %g0, 1, %g0		! re-establish 0x99 right before trap
	mov 20, %g1			! SYS_getpid
	ta 0x6d
	mov %o0, %l1			! pid (next insn runs: pc=npc npc+=4)
	rd %ccr, %l0
	and %l0, 0x10, %g4		! xcc.C == 0 (success signal)
	cmp %g4, 0
	bne fail
	nop
	cmp %l1, 0			! pid > 0 ?
	ble fail
	nop
	and %l0, 0xff, %g4		! full byte 0x89: NZV+icc.C preserved
	cmp %g4, 0x89
	bne fail
	nop
	sethi %hi(msg_t5), %g2
	or %g2, %lo(msg_t5), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	mov ' ', %g2
	call putc
	nop
	mov %l1, %g2
	call puthex64
	nop
	call putnl
	nop

	! --- T6: ta 0x6d error (bad syscall 9999): xcc.C set, rest kept ---
	! Oracle rule (see FINDINGS): error sets xcc.C only; icc.C and N/Z/V
	! are preserved; %o0 = SPARC errno (90/ENOSYS for 9999 here).
	addcc %g0, %g0, %g0		! ccr=0x44: all C clear
	rd %ccr, %l0
	and %l0, 0xff, %g4		! precondition: full byte 0x44
	cmp %g4, 0x44
	bne fail
	nop
	sethi %hi(msg_t6pre), %g2
	or %g2, %lo(msg_t6pre), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	call putnl
	nop
	addcc %g0, %g0, %g0		! re-establish 0x44 right before trap
	! NOTE: GAS sparc64 rejects `mov 9999, %g1` (relocation overflow), so
	! materialize out-of-simm13-range constants with sethi/or.
	sethi %hi(9999), %g1
	or %g1, %lo(9999), %g1		! invalid syscall -> ENOSYS
	ta 0x6d
	mov %o0, %l1			! errno (positive)
	rd %ccr, %l0
	and %l0, 0x10, %g4		! xcc.C == 1 (error signal)
	cmp %g4, 0x10
	bne fail
	nop
	cmp %l1, 0			! errno > 0 ?
	ble fail
	nop
	sethi %hi(4096), %g4
	or %g4, %lo(4096), %g4
	cmp %l1, %g4			! errno < 4096 (unsigned) ?
	bcc fail			! SUB C=borrow: C=0 means o0 >= 4096
	nop
	and %l0, 0xff, %g4		! full byte 0x54: NZV+icc.C preserved
	cmp %g4, 0x54
	bne fail
	nop
	sethi %hi(msg_t6), %g2
	or %g2, %lo(msg_t6), %g2
	call puts
	nop
	mov %l0, %g2
	call puthex64
	nop
	mov ' ', %g2
	call putc
	nop
	mov %l1, %g2
	call puthex64
	nop
	call putnl
	nop

	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d				! exit(0)

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x6d				! exit(1)

! ---------- helpers (clobber %g1,%g3,%g4,%o0-%o2; preserve %g2,%l0,%l1) ----------
puts:					! %g2 = NUL-terminated string
	mov %g2, %g4		! NOTE: the bz delay slot must NOT advance %g4,
1:	ldub [%g4], %g3		! or the write would include the NUL (len+1).
	tst %g3
	bz 2f
	nop
	add %g4, 1, %g4
	ba 1b
	nop
2:	sub %g4, %g2, %o2
	mov %g2, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x6d				! write(1, str, len)
	retl
	nop
puthex64:				! %g2 = 64-bit value, prints 16 hex digits
	sethi %hi(hexbuf), %g3
	or %g3, %lo(hexbuf), %g3
	mov 60, %o2
1:	srlx %g2, %o2, %g4
	and %g4, 0xf, %g4
	cmp %g4, 10
	bl 2f
	nop
	add %g4, 'a' - 10, %g4
	ba 3f
	nop
2:	add %g4, '0', %g4
3:	stb %g4, [%g3]
	add %g3, 1, %g3
	subcc %o2, 4, %o2
	bge 1b
	nop
	sethi %hi(hexbuf), %o1
	or %o1, %lo(hexbuf), %o1
	mov 1, %o0
	mov 16, %o2
	mov 4, %g1
	ta 0x6d				! write(1, hexbuf, 16)
	retl
	nop
putnl:
	mov '\n', %g2
	ba putc
	nop
putc:					! %g2 = char
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
	.align 4
msg_banner:	.asciz "E02 dual-carry probe (V9, ta 0x6d)\n"
msg_t1:	.asciz "t1 32b-carry  ccr="
msg_t2:	.asciz "t2 64b-carry  ccr="
msg_t3:	.asciz "t3 no-carry   ccr="
msg_t4:	.asciz "t4 sub-borrow ccr="
msg_t5pre:	.asciz "t5 pre-syscall ccr="
msg_t6pre:	.asciz "t6 pre-syscall ccr="
msg_t5:	.asciz "t5 getpid-ok  ccr= pid="
msg_t6:	.asciz "t6 bad-syscall ccr= errno="
msg_pass:	.asciz "E02-PASS: icc.C + xcc.C dual update verified\n"
msg_fail:	.asciz "E02-FAIL\n"
	.section .bss
	.align 8
hexbuf:	.skip 16
charbuf:	.skip 8
