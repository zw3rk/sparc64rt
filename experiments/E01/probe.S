! E01 probe (SPARC V9, 64-bit): 2047 stack bias + SAVE/RESTORE + _start layout.
! Freestanding SPARC V9 (-fno-pie -no-pie -nostdlib -static).
! Syscalls via ta 0x6d: write=4, exit=1. Args %o0..%o5, number %g1.
! Prints register/memory facts; exit code 0 = self-check PASS, 1 = FAIL.
	.text
	.align 4
	! V9 ABI: %g2-%g7 need explicit .register declarations in 64-bit mode
	.register %g2, #scratch
	.register %g3, #scratch
	.register %g6, #scratch
	.register %g7, #scratch
	.global _start
_start:
	! --- print biased %sp, then unbiased (%sp + 2047) ---
	sethi %hi(msg_sp), %g2
	or %g2, %lo(msg_sp), %g2
	call puts
	nop
	mov %sp, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	add %sp, 2047, %g2
	call puthex
	nop
	call putnl
	nop

	add %sp, 2047, %g6		! %g6 = unbiased base (survives calls)

	! --- argc: full 8-byte slot at [unbiased + 128] ---
	sethi %hi(msg_argc), %g2
	or %g2, %lo(msg_argc), %g2
	call puts
	nop
	ldx [%g6 + 128], %g2
	call puthex
	nop
	call putnl
	nop

	! --- argv[0] pointer at [unbiased + 136]; then argv[0] string ---
	sethi %hi(msg_argv0), %g2
	or %g2, %lo(msg_argv0), %g2
	call puts
	nop
	ldx [%g6 + 136], %g2
	call puthex
	nop
	call putnl
	nop
	ldx [%g6 + 136], %g2
	call puts
	nop
	call putnl
	nop

	! --- envp[0]: scan past argv NULL ---
	ldx [%g6 + 128], %g5		! argc
	add %g6, 136, %g4		! &argv[0]
	sllx %g5, 3, %g3		! argc * 8
	add %g4, %g3, %g4		! &argv[argc] (NULL slot)
	ldx [%g4 + 8], %g7		! envp[0] -> %g7 (puts clobbers %g4)
	sethi %hi(msg_envp0), %g2
	or %g2, %lo(msg_envp0), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex
	nop
	call putnl
	nop

	! --- dump 32 doublewords at [unbiased .. unbiased+256) ---
	! (window save area [0..128) then argc/argv/envp/auxv [128..256))
	sethi %hi(msg_stack), %g2
	or %g2, %lo(msg_stack), %g2
	call puts
	nop
	mov 0, %g5			! index
1:	sllx %g5, 3, %g4
	add %g6, %g4, %g4
	ldx [%g4], %g2
	call puthex
	nop
	add %g5, 1, %g5
	and %g5, 3, %g4
	cmp %g4, 0
	bne 2f
	nop
	call putnl
	nop
	ba 3f
	nop
2:	mov ' ', %g2
	call putc
	nop
3:	cmp %g5, 32
	bl 1b
	nop
	call putnl
	nop

	! --- window rotation + underfill semantics ---
	mov 1, %o0
	mov 2, %o1
	mov 3, %l0
	mov 4, %l1
	! snapshot entry sp (calls use no stack, so plain stx is exact).
	sethi %hi(entrysp), %g4
	or %g4, %lo(entrysp), %g4
	stx %sp, [%g4]
	! fill the new window's future spill area [unbiased-192 .. unbiased-64)
	! with sentinel 0x5A5A5A5A5A5A5A5A (16 doublewords)
	sub %g6, 192, %g4
	sethi %hi(sentinel), %g2
	or %g2, %lo(sentinel), %g2
	ldx [%g2], %g5			! sentinel 0x5A*16 (gas set is 32-bit only)
	mov 16, %g3
1:	stx %g5, [%g4]
	add %g4, 8, %g4
	subcc %g3, 1, %g3
	bnz 1b
	nop
	save %sp, -192, %sp
	! after save: old %o0/%o1 must be visible as %i0/%i1
	sethi %hi(msg_after_save), %g2
	or %g2, %lo(msg_after_save), %g2
	call puts
	nop
	mov %i0, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	mov %i1, %g2
	call puthex
	nop
	call putnl
	nop
	cmp %i0, 1
	bne fail
	nop
	cmp %i1, 2
	bne fail
	nop
	! new window %l/%o are private to it; %i aliases the old %o,
	! so only touch %l/%o here to avoid destroying saved state.
	mov 5, %l0
	mov 6, %o0
	restore
	! Snapshot restored regs to memory BEFORE any call: puts/puthex
	! overwrite %o0-%o2 (fd/len/return), which would fake the readings.
	! snap layout (doublewords): o0 o1 l0..l7 i0..i7 sp  (19 words).
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	stx %o0, [%g2]
	stx %o1, [%g2 + 8]
	stx %l0, [%g2 + 16]
	stx %l1, [%g2 + 24]
	stx %l2, [%g2 + 32]
	stx %l3, [%g2 + 40]
	stx %l4, [%g2 + 48]
	stx %l5, [%g2 + 56]
	stx %l6, [%g2 + 64]
	stx %l7, [%g2 + 72]
	stx %i0, [%g2 + 80]
	stx %i1, [%g2 + 88]
	stx %i2, [%g2 + 96]
	stx %i3, [%g2 + 104]
	stx %i4, [%g2 + 112]
	stx %i5, [%g2 + 120]
	stx %i6, [%g2 + 128]
	stx %i7, [%g2 + 136]
	mov %sp, %g3
	stx %g3, [%g2 + 144]
	! print the 19 snapshot words (loads from memory only)
	sethi %hi(msg_after_restore), %g2
	or %g2, %lo(msg_after_restore), %g2
	call puts
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	mov 0, %g5			! word index
1:	sllx %g5, 3, %g4
	add %g2, %g4, %g4
	ldx [%g4], %g7		! value -> %g7 (call-preserved)
	mov %g7, %g2
	call puthex
	nop
	add %g5, 1, %g5
	cmp %g5, 19
	bne 2f
	nop
	call putnl
	nop
	sethi %hi(snap), %g2		! reload: putnl clobbers %g2
	or %g2, %lo(snap), %g2
	ba 3f
	nop
2:	and %g5, 3, %g4
	cmp %g4, 0
	bne 4f
	nop
	call putnl
	nop
	sethi %hi(snap), %g2		! reload: putnl clobbers %g2
	or %g2, %lo(snap), %g2
	ba 3f
	nop
4:	mov ' ', %g2
	call putc
	nop
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
3:	cmp %g5, 19
	bl 1b
	nop
	! verify rotation survivors from the memory snapshot
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2], %g3
	cmp %g3, 1			! o0: old outs survive (fill skips outs)
	bne fail
	nop
	ldx [%g2 + 8], %g3
	cmp %g3, 2			! o1: same
	bne fail
	nop
	ldx [%g2 + 144], %g3
	sethi %hi(entrysp), %g4
	or %g4, %lo(entrysp), %g4
	ldx [%g4], %g4
	cmp %g3, %g4			! sp restored to entry value
	bne fail
	nop
	! verify no-trap model: at _start all windows are resident, so save at
	! depth 1 spills nothing and restore fills nothing — %l0/%l1 keep the
	! pre-save markers in-register (contrast: 32-bit _start restored with
	! window 0 invalid and refilled l/i from the stack).
	sethi %hi(snap), %g2
	or %g2, %lo(snap), %g2
	ldx [%g2 + 16], %g3
	cmp %g3, 3			! l0: marker preserved, no fill trap
	bne fail
	nop
	ldx [%g2 + 24], %g3
	cmp %g3, 4			! l1: same
	bne fail
	nop
12:
	! sentinel area [unbiased-192 .. unbiased-64) must be intact (no spill)
	add %sp, 2047, %g4
	sub %g4, 192, %g4
	mov 16, %g3
	sethi %hi(sentinel), %g2
	or %g2, %lo(sentinel), %g2
	ldx [%g2], %g5			! sentinel 0x5A*16 (gas set is 32-bit only)
	mov 0, %g7			! mismatch index (%g7 survives calls)
1:	ldx [%g4], %g2
	cmp %g2, %g5
	bne 4f
	nop
	add %g4, 8, %g4
	add %g7, 1, %g7
	subcc %g3, 1, %g3
	bnz 1b
	nop
	ba 5f
	nop
4:	! %g2 still holds the mismatch value, %g7 the idx; stash value first
	! (puts/puthex clobber %g4, so [%g4] is unreadable after any call)
	sethi %hi(filldiag), %g4
	or %g4, %lo(filldiag), %g4
	stx %g2, [%g4]
	sethi %hi(msg_sentinel), %g2
	or %g2, %lo(msg_sentinel), %g2
	call puts
	nop
	mov %g7, %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	sethi %hi(filldiag), %g2
	or %g2, %lo(filldiag), %g2
	ldx [%g2], %g2
	call puthex
	nop
	call putnl
	nop
	ba fail
	nop
5:

	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d			! exit(0)

fail:
	sethi %hi(msg_fail), %g2
	or %g2, %lo(msg_fail), %g2
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x6d			! exit(1)

! ---------- helpers (leaf: no save, return via retl; preserve %g5-%g7) ----------
! puts: %g2 = NUL-terminated string. Clobbers %o0-%o2,%g1,%g3,%g4.
puts:
	mov %g2, %g4
1:	ldub [%g4], %g3
	tst %g3
	bz 2f
	add %g4, 1, %g4
	ba 1b
	nop
2:	sub %g4, %g2, %o2		! %g4 advanced past NUL (delay slot): exact len
	sub %o2, 1, %o2
	mov %g2, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x6d
	retl
	nop
! puthex: %g2 = u64, prints 16 hex digits. Clobbers %o0-%o2,%g1,%g3,%g4.
puthex:
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
	ta 0x6d
	retl
	nop
! putnl: prints '\n'. Clobbers like write.
putnl:
	mov '\n', %g2
	ba putc
	nop
! putc: %g2 = char. Clobbers %o0-%o2,%g1,%g3.
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
msg_sp:	.asciz "sp(biased,unbiased)="
msg_argc:	.asciz "argc@+2175="
msg_argv0:	.asciz "argv0ptr="
msg_envp0:	.asciz "envp0ptr="
msg_stack:	.asciz "win+stack[unbiased..unbiased+256):\n"
msg_after_save:	.asciz "after-save i0 i1="
msg_after_restore:	.asciz "after-restore o0 o1 l0..l7 i0..i7 sp=\n"
msg_sentinel:	.asciz "sentinel mismatch idx val="
msg_pass:	.asciz "E01-PASS: bias ok, rotation ok, no spill/fill traps\n"
msg_fail:	.asciz "E01-FAIL\n"
	.align 8				! ldx needs 8-byte alignment
sentinel:	.xword 0x5A5A5A5A5A5A5A5A
	.section .bss
	.align 8
hexbuf:	.skip 16
charbuf:	.skip 8
snap:	.skip 152
entrysp:	.skip 8
filldiag:	.skip 8			! scratch word for the sentinel-mismatch path
