! E03 probe (SPARC V9, 64-bit): BPcc (icc/xcc + predict + annul),
! BPr (brz/brnz/brlz/brlez/brgz/brgez, 64-bit semantics),
! MOVcc (icc/xcc), MOVr, CASA/CASXA (ASI 0x80), LE ASI (0x88).
! Freestanding V9 (-m64 -fno-pie -no-pie -nostdlib -static).
! Syscalls: write=4, exit=1 via ta 0x6d.
! KEY DISCIPLINE (from 32-bit E03): snapshot every result to memory
! BEFORE any call — helpers clobber %o0-%o2 and %g1-%g3.
! Risky ops (CASA/CASXA/LE-ASI) run AFTER the phase-A print, each with
! its own snapshot+print, so a guest-killing trap still leaves exact
! attribution in the output already flushed via write syscalls.
	.text
	.align 4
	.global _start
	.register %g2, #scratch
	.register %g3, #scratch
	.register %g6, #scratch
_start:
	sethi %hi(snap), %g6
	or %g6, %lo(snap), %g6

	! ============ BPcc ============
	! T0: be %icc taken (Z=1), annulled-taken executes delay slot
	subcc %g0, 0, %g0
	be,a,pt %icc, 1f
	mov 1, %g1			! executes: branch taken
	mov 0, %g1			! reached only if NOT taken (bad)
1:	stx %g1, [%g6 + 0]		! snap[0] expect 1

	! T1: be %icc not-taken (Z=0), annulled -> delay slot skipped
	subcc %g0, 1, %g0		! 0-1: N=1, Z=0
	mov 2, %g1
	be,a,pt %icc, 1f
	mov 0xbad, %g1			! must NOT execute (annulled)
1:	stx %g1, [%g6 + 8]		! snap[1] expect 2

	! T2/T3/T4: icc vs xcc split on %g1 = 0x100000000
	! (low32 == 0 -> icc Z=1; full64 != 0 -> xcc Z=0)
	sethi %hi(0x10000000), %g1
	sllx %g1, 4, %g1		! %g1 = 0x100000000
	cmp %g1, 0
	be,pt %icc, 1f			! icc Z=1 -> taken
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 4, %g2
2:	stx %g2, [%g6 + 16]		! snap[2] expect 4
	cmp %g1, 0			! refresh flags
	mov 3, %g2
	be,a,pt %xcc, 1f		! xcc Z=0 -> not taken, annulled
	mov 0xbad, %g2			! must NOT execute
1:	stx %g2, [%g6 + 24]		! snap[3] expect 3
	cmp %g1, 0			! refresh flags
	bne,pn %xcc, 1f			! xcc NZ=1 -> taken, predict-nt
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 5, %g2
2:	stx %g2, [%g6 + 32]		! snap[4] expect 5

	! ============ BPr: %g1 = 0x80000000 (lo32 negative, 64b positive) ====
	sethi %hi(0x80000000), %g1	! %g1 = 0x0000000080000000
	mov 6, %g2
	brlz,a,pt %g1, 1f		! 64-bit positive -> NOT taken
	mov 0xbad, %g2			! must NOT execute
1:	stx %g2, [%g6 + 40]		! snap[5] expect 6
	mov 0, %g2
	brlez,pn %g1, 1f		! NOT taken
	nop
	mov 7, %g2			! fallthrough marker
	ba 2f
	nop
1:	mov 0, %g2			! taken path (bad)
2:	stx %g2, [%g6 + 48]		! snap[6] expect 7
	brgz,pt %g1, 1f			! taken
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 8, %g2
2:	stx %g2, [%g6 + 56]		! snap[7] expect 8
	brgez,pn %g1, 1f		! taken (predict-nt, still taken)
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 9, %g2
2:	stx %g2, [%g6 + 64]		! snap[8] expect 9

	! ============ BPr: %g1 = -1 ============
	mov -1, %g1
	brlz,pt %g1, 1f			! taken
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 10, %g2
2:	stx %g2, [%g6 + 72]		! snap[9] expect 10
	brnz,pn %g1, 1f			! taken
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 11, %g2
2:	stx %g2, [%g6 + 80]		! snap[10] expect 11

	! ============ BPr: %g1 = 0 ============
	mov 0, %g1
	brz,pt %g1, 1f			! taken
	nop
	mov 0, %g2
	ba 2f
	nop
1:	mov 12, %g2
2:	stx %g2, [%g6 + 88]		! snap[11] expect 12
	mov 13, %g2
	brnz,a,pn %g1, 1f		! NOT taken, annulled
	mov 0xbad, %g2			! must NOT execute
1:	stx %g2, [%g6 + 96]		! snap[12] expect 13

	! ============ MOVcc ============
	! T13/T14: Z=1 -> move takes, movne does not
	subcc %g0, 0, %g0
	mov -1, %g3
	move %icc, 0x111, %g3
	stx %g3, [%g6 + 104]		! snap[13] expect 0x111
	mov -1, %g3
	movne %icc, 0x222, %g3
	stx %g3, [%g6 + 112]		! snap[14] expect -1 (unchanged)

	! T15/T16/T17: icc vs xcc split, %g1 = 0x100000000, cmp 0
	! (icc Z=1, xcc Z=0)
	sethi %hi(0x10000000), %g1
	sllx %g1, 4, %g1
	cmp %g1, 0
	mov -1, %g3
	move %icc, 1, %g3
	stx %g3, [%g6 + 120]		! snap[15] expect 1
	cmp %g1, 0
	mov -1, %g3
	move %xcc, 1, %g3
	stx %g3, [%g6 + 128]		! snap[16] expect -1 (unchanged)
	cmp %g1, 0
	mov -1, %g3
	movne %xcc, 1, %g3
	stx %g3, [%g6 + 136]		! snap[17] expect 1

	! T18/T19: N split, %o4 = 0x80000000, cmp 0
	! (icc N=1 since lo32 < 0; xcc N=0 since full64 > 0)
	sethi %hi(0x80000000), %o4
	cmp %o4, 0
	mov -1, %g3
	movl %icc, 1, %g3
	stx %g3, [%g6 + 144]		! snap[18] expect 1
	cmp %o4, 0
	mov -1, %g3
	movl %xcc, 1, %g3
	stx %g3, [%g6 + 152]		! snap[19] expect -1 (unchanged)

	! ============ MOVr ============
	! T20/T21: %g1 = 0
	mov 0, %g1
	mov -1, %g3
	movrz %g1, 0x333, %g3
	stx %g3, [%g6 + 160]		! snap[20] expect 0x333 sign-extended
	mov -1, %g3
	movrnz %g1, 0x222, %g3
	stx %g3, [%g6 + 168]		! snap[21] expect -1 (unchanged)

	! T22/T23: %g1 = 0x80000000 (64-bit positive)
	sethi %hi(0x80000000), %g1
	mov -1, %g3
	movrlz %g1, 0x111, %g3
	stx %g3, [%g6 + 176]		! snap[22] expect -1 (64-bit proof)
	mov -1, %g3
	movrgz %g1, 0x123, %g3
	stx %g3, [%g6 + 184]		! snap[23] expect 0x666

	! T24/T25: %g1 = -1
	mov -1, %g1
	mov -1, %g3
	movrlez %g1, 0x321, %g3
	stx %g3, [%g6 + 192]		! snap[24] expect 0x321 sign-extended
	mov -1, %g3
	movrgez %g1, 0x213, %g3
	stx %g3, [%g6 + 200]		! snap[25] expect -1 (unchanged)

	! ============ phase-A print: snap[0..25] ============
	sethi %hi(msg_head), %g2
	or %g2, %lo(msg_head), %g2
	call puts
	nop
	sethi %hi(snap), %g6
	or %g6, %lo(snap), %g6
	mov 0, %o3
1:	sllx %o3, 3, %o4
	add %g6, %o4, %o4
	ldx [%o4], %g2
	call puthex
	nop
	add %o3, 1, %o3
	and %o3, 1, %o4
	cmp %o4, 0
	bne 2f
	nop
	call putnl
	nop
	ba 3f
	nop
2:	mov ' ', %g2
	call putc
	nop
	sethi %hi(snap), %g6
	or %g6, %lo(snap), %g6
3:	cmp %o3, 26
	bl 1b
	nop
	call putnl
	nop
	sethi %hi(msg_apass), %g2
	or %g2, %lo(msg_apass), %g2
	call puts
	nop

	! ============ phase B: CASA (32-bit, ASI 0x80 PRIMARY, match) ====
	! mem=0x11111111, cmp=0x11111111 -> expect rd=0x11111111,
	! mem=0x22222222. Traps (guest death) here = oracle gap finding.
	sethi %hi(casamem), %o0
	or %o0, %lo(casamem), %o0
	sethi %hi(0x11111111), %o1
	or %o1, %lo(0x11111111), %o1
	sethi %hi(0x22222222), %o2
	or %o2, %lo(0x22222222), %o2
	casa [%o0] 0x80, %o1, %o2
	sethi %hi(snapB), %g6
	or %g6, %lo(snapB), %g6
	st %o2, [%g6 + 0]		! snapB[0] casa rd
	ld [%o0], %g2
	st %g2, [%g6 + 4]		! snapB[1] casa mem
	sethi %hi(msg_casa), %g2
	or %g2, %lo(msg_casa), %g2
	call puts
	nop
	ld [%g6 + 0], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	ld [%g6 + 4], %g2
	call puthex
	nop
	call putnl
	nop

	! ============ phase C: CASXA (64-bit, ASI 0x80, match) ============
	sethi %hi(casxamem), %o0
	or %o0, %lo(casxamem), %o0
	sethi %hi(0x11111111), %o1
	or %o1, %lo(0x11111111), %o1
	sllx %o1, 32, %o1
	sethi %hi(0x22222222), %o4
	or %o4, %lo(0x22222222), %o4
	or %o1, %o4, %o1		! %o1 = 0x1111111122222222
	sethi %hi(0x33333333), %o2
	or %o2, %lo(0x33333333), %o2
	sllx %o2, 32, %o2
	sethi %hi(0x44444444), %o4
	or %o4, %lo(0x44444444), %o4
	or %o2, %o4, %o2		! %o2 = 0x3333333344444444
	casxa [%o0] 0x80, %o1, %o2
	sethi %hi(snapB), %g6
	or %g6, %lo(snapB), %g6
	stx %o2, [%g6 + 8]		! snapB[2] casxa rd
	ldx [%o0], %g2
	stx %g2, [%g6 + 16]		! snapB[3] casxa mem
	sethi %hi(msg_casxa), %g2
	or %g2, %lo(msg_casxa), %g2
	call puts
	nop
	ldx [%g6 + 8], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	ldx [%g6 + 16], %g2
	call puthex
	nop
	call putnl
	nop

	! ============ phase D: little-endian ASI 0x88 ============
	sethi %hi(lemem), %o0
	or %o0, %lo(lemem), %o0
	lda [%o0] 0x88, %g2		! LE load of 0x01020304
	sethi %hi(snapB), %g6
	or %g6, %lo(snapB), %g6
	stx %g2, [%g6 + 24]		! snapB[4] le load (expect 0x04030201)
	sethi %hi(lemem2), %o0
	or %o0, %lo(lemem2), %o0
	sethi %hi(0x0a0b0c0d), %g2
	or %g2, %lo(0x0a0b0c0d), %g2
	sta %g2, [%o0] 0x88		! LE store
	ld [%o0], %g2			! BE reload: expect 0x0d0c0b0a
	stx %g2, [%g6 + 32]		! snapB[5]
	sethi %hi(msg_le), %g2
	or %g2, %lo(msg_le), %g2
	call puts
	nop
	ldx [%g6 + 24], %g2
	call puthex
	nop
	mov ' ', %g2
	call putc
	nop
	ldx [%g6 + 32], %g2
	call puthex
	nop
	call putnl
	nop

	sethi %hi(msg_pass), %g2
	or %g2, %lo(msg_pass), %g2
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d

! ---------- helpers (clobber %o0-%o2, %g1-%g3; preserve %g6, %o3-%o5) ----------
puts:
	mov %g2, %g3
1:	ldub [%g3], %g1
	cmp %g1, 0
	be 2f
	nop
	add %g3, 1, %g3
	ba 1b
	nop
2:	sub %g3, %g2, %o2
	mov %g2, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x6d
	retl
	nop
puthex:					! %g2 -> 16 hex digits
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
	mov '\n', %g2
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
	.align 8
msg_head:	.asciz "snap[bp0..bp12 movcc13..19 movr20..25]:\n"
msg_apass:	.asciz "E03A-PASS\n"
msg_casa:	.asciz "casa rd mem: "
msg_casxa:	.asciz "casxa rd mem: "
msg_le:		.asciz "leASI ld st: "
msg_pass:	.asciz "E03-PASS\n"
	.align 4
casamem:	.word 0x11111111
	.align 8
casxamem:	.xword 0x1111111122222222
	.align 4
lemem:		.word 0x01020304
lemem2:		.word 0
	.section .bss
	.align 8
hexbuf:		.skip 16
charbuf:	.skip 8
snap:		.skip 208
snapB:		.skip 48
