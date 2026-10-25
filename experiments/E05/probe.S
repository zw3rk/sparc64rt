! E05 probe: SPARC V9 FPU (%f0..%f31 aliased %d0..%d62 / %q0..%q60),
! fcc0..fcc3, FMOVcc/FMOVr, and VIS faligndata + GSR.alignaddr.
! Freestanding V9 (-mcpu=ultrasparc -fno-pie -no-pie -nostdlib -static).
! Syscalls via ta 0x6d: write=4, exit=1.
! Prints labeled hex words, self-checks expectations, prints E05-PASS
! (exit 0) or E05-FAIL (exit 1).
! NOTE: %g2/%g3 are OS-reserved on sparc64 Linux (GAS rejects them w/o
! .register); only %g0/%g1/%g4/%g5 + %o0..%o5 are used below.
	.text
	.align 4
	.global _start

! ---------- print macros (clobber %g1/%g4/%o0-%o2; preserve %g5) ----------
.macro PRINT32 label, waddr
	sethi %hi(\label), %g4
	or %g4, %lo(\label), %g4
	call puts
	nop
	sethi %hi(\waddr), %g1
	or %g1, %lo(\waddr), %g1
	ld [%g1], %g4
	call puthex32
	nop
	call putnl
	nop
.endm
.macro PRINT64 label, waddr
	sethi %hi(\label), %g4
	or %g4, %lo(\label), %g4
	call puts
	nop
	sethi %hi(\waddr), %g1
	or %g1, %lo(\waddr), %g1
	ldx [%g1], %g4
	call puthex64
	nop
	call putnl
	nop
.endm

_start:
	mov 0, %g5			! fail counter (preserved by helpers)

	sethi %hi(msg_head), %g4
	or %g4, %lo(msg_head), %g4
	call puts
	nop

! ---------- T0: initial FSR ----------
	sethi %hi(w_fsr0), %g1
	or %g1, %lo(w_fsr0), %g1
	stx %fsr, [%g1]
	PRINT64 msg_fsr0, w_fsr0

! ---------- T1: single-precision ----------
	sethi %hi(c1f), %g1
	or %g1, %lo(c1f), %g1
	ld [%g1], %f0			! f0 = 1.0f
	sethi %hi(c2f), %g1
	or %g1, %lo(c2f), %g1
	ld [%g1], %f1			! f1 = 2.0f
	sethi %hi(c8f), %g1
	or %g1, %lo(c8f), %g1
	ld [%g1], %f5			! f5 = 8.0f
	fadds %f0, %f1, %f2		! 3.0f = 0x40400000
	fsubs %f1, %f0, %f3		! 1.0f = 0x3f800000
	fmuls %f0, %f1, %f4		! 2.0f = 0x40000000
	fdivs %f5, %f1, %f6		! 4.0f = 0x40800000
	fsmuld %f0, %f1, %d10		! 2.0  = 0x4000000000000000
	sethi %hi(w_fadds), %g1
	or %g1, %lo(w_fadds), %g1
	st %f2, [%g1]
	sethi %hi(w_fsubs), %g1
	or %g1, %lo(w_fsubs), %g1
	st %f3, [%g1]
	sethi %hi(w_fmuls), %g1
	or %g1, %lo(w_fmuls), %g1
	st %f4, [%g1]
	sethi %hi(w_fdivs), %g1
	or %g1, %lo(w_fdivs), %g1
	st %f6, [%g1]
	sethi %hi(w_fsmuld), %g1
	or %g1, %lo(w_fsmuld), %g1
	std %d10, [%g1]
! check f2 == 0x40400000
	sethi %hi(w_fadds), %g1
	or %g1, %lo(w_fadds), %g1
	ld [%g1], %g4
	sethi %hi(0x40400000), %o3
	cmp %g4, %o3
	be C1ok
	nop
	add %g5, 1, %g5
C1ok:
! check f3 == 0x3f800000
	sethi %hi(w_fsubs), %g1
	or %g1, %lo(w_fsubs), %g1
	ld [%g1], %g4
	sethi %hi(0x3f800000), %o3
	cmp %g4, %o3
	be C2ok
	nop
	add %g5, 1, %g5
C2ok:
! check f4 == 0x40000000
	sethi %hi(w_fmuls), %g1
	or %g1, %lo(w_fmuls), %g1
	ld [%g1], %g4
	sethi %hi(0x40000000), %o3
	cmp %g4, %o3
	be C3ok
	nop
	add %g5, 1, %g5
C3ok:
! check f6 == 0x40800000
	sethi %hi(w_fdivs), %g1
	or %g1, %lo(w_fdivs), %g1
	ld [%g1], %g4
	sethi %hi(0x40800000), %o3
	cmp %g4, %o3
	be C4ok
	nop
	add %g5, 1, %g5
C4ok:
! check d10 == 0x4000000000000000
	sethi %hi(w_fsmuld), %g1
	or %g1, %lo(w_fsmuld), %g1
	ldx [%g1], %g4
	sethi %hi(0x40000000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C5ok
	nop
	add %g5, 1, %g5
C5ok:
	PRINT32 msg_fadds, w_fadds
	PRINT32 msg_fsubs, w_fsubs
	PRINT32 msg_fmuls, w_fmuls
	PRINT32 msg_fdivs, w_fdivs
	PRINT64 msg_fsmuld, w_fsmuld

! ---------- T3a: single view of d2 (before T2 overwrites f2/f3) ----------
! d2 = f2:f3 = 0x40400000:0x3f800000 (T1 fadds/fsubs results)
	sethi %hi(w_aliasd), %g1
	or %g1, %lo(w_aliasd), %g1
	std %f2, [%g1]
! check d2 == 0x404000003f800000
	sethi %hi(w_aliasd), %g1
	or %g1, %lo(w_aliasd), %g1
	ldx [%g1], %g4
	sethi %hi(0x40400000), %o3
	sllx %o3, 32, %o3
	sethi %hi(0x3f800000), %o4
	or %o3, %o4, %o3
	cmp %g4, %o3
	be C10ok
	nop
	add %g5, 1, %g5
C10ok:
	PRINT64 msg_aliasd, w_aliasd

! ---------- T2: double-precision ----------
	sethi %hi(c1d), %g1
	or %g1, %lo(c1d), %g1
	ldd [%g1], %d0			! d0 = 1.0
	sethi %hi(c2d), %g1
	or %g1, %lo(c2d), %g1
	ldd [%g1], %d2			! d2 = 2.0
	sethi %hi(c8d), %g1
	or %g1, %lo(c8d), %g1
	ldd [%g1], %d12			! d12 = 8.0
	faddd %d0, %d2, %d4		! 3.0 = 0x4008000000000000
	fsubd %d2, %d0, %d6		! 1.0 = 0x3ff0000000000000
	fmuld %d0, %d2, %d8		! 2.0 = 0x4000000000000000
	fdivd %d12, %d2, %d14		! 4.0 = 0x4010000000000000
	sethi %hi(w_faddd), %g1
	or %g1, %lo(w_faddd), %g1
	std %d4, [%g1]
	sethi %hi(w_fsubd), %g1
	or %g1, %lo(w_fsubd), %g1
	std %d6, [%g1]
	sethi %hi(w_fmuld), %g1
	or %g1, %lo(w_fmuld), %g1
	std %d8, [%g1]
	sethi %hi(w_fdivd), %g1
	or %g1, %lo(w_fdivd), %g1
	std %d14, [%g1]
! check d4 == 0x4008000000000000
	sethi %hi(w_faddd), %g1
	or %g1, %lo(w_faddd), %g1
	ldx [%g1], %g4
	sethi %hi(0x40080000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C6ok
	nop
	add %g5, 1, %g5
C6ok:
! check d6 == 0x3ff0000000000000
	sethi %hi(w_fsubd), %g1
	or %g1, %lo(w_fsubd), %g1
	ldx [%g1], %g4
	sethi %hi(0x3ff00000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C7ok
	nop
	add %g5, 1, %g5
C7ok:
! check d8 == 0x4000000000000000
	sethi %hi(w_fmuld), %g1
	or %g1, %lo(w_fmuld), %g1
	ldx [%g1], %g4
	sethi %hi(0x40000000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C8ok
	nop
	add %g5, 1, %g5
C8ok:
! check d14 == 0x4010000000000000
	sethi %hi(w_fdivd), %g1
	or %g1, %lo(w_fdivd), %g1
	ldx [%g1], %g4
	sethi %hi(0x40100000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C9ok
	nop
	add %g5, 1, %g5
C9ok:
	PRINT64 msg_faddd, w_faddd
	PRINT64 msg_fsubd, w_fsubd
	PRINT64 msg_fmuld, w_fmuld
	PRINT64 msg_fdivd, w_fdivd

! ---------- T3b: double halves after faddd (T2 set d4 = 3.0) ----------
! f4:f5 = 0x40080000:0x00000000 (singles read the double bits)
	sethi %hi(w_aliasf), %g1
	or %g1, %lo(w_aliasf), %g1
	st %f4, [%g1]
	st %f5, [%g1 + 4]
! check f4:f5 == 0x4008000000000000
	sethi %hi(w_aliasf), %g1
	or %g1, %lo(w_aliasf), %g1
	ldx [%g1], %g4
	sethi %hi(0x40080000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C11ok
	nop
	add %g5, 1, %g5
C11ok:
	PRINT64 msg_aliasf, w_aliasf
! reload fresh singles + upper doubles (T2 clobbered f0-f3)
	sethi %hi(c1f), %g1
	or %g1, %lo(c1f), %g1
	ld [%g1], %f0			! f0 = 1.0f
	sethi %hi(c2f), %g1
	or %g1, %lo(c2f), %g1
	ld [%g1], %f1			! f1 = 2.0f
	sethi %hi(c1d), %g1
	or %g1, %lo(c1d), %g1
	ldd [%g1], %d32			! d32 = 1.0 (upper double, no single alias)
	sethi %hi(c2d), %g1
	or %g1, %lo(c2d), %g1
	ldd [%g1], %d34			! d34 = 2.0

! ---------- T4a: fcc0 less + fcmpd ----------
	fcmps %fcc0, %f0, %f1		! 1.0 < 2.0
	sethi %hi(w_fsrl), %g1
	or %g1, %lo(w_fsrl), %g1
	stx %fsr, [%g1]
	PRINT64 msg_fsrl, w_fsrl
	mov 0, %g4
	fbl %fcc0, Lbl1
	nop
	ba Lbl2
	nop
Lbl1:	or %g4, 1, %g4
Lbl2:
	fbg %fcc0, Lbg1
	nop
	ba Lbg2
	nop
Lbg1:	or %g4, 2, %g4
Lbg2:
	fbe %fcc0, Lbe1
	nop
	ba Lbe2
	nop
Lbe1:	or %g4, 4, %g4
Lbe2:
	fbu %fcc0, Lbu1
	nop
	ba Lbu2
	nop
Lbu1:	or %g4, 8, %g4
Lbu2:
	fcmpd %fcc0, %d32, %d34		! 1.0 < 2.0 (double)
	fbl %fcc0, Lbd1
	nop
	ba Lbd2
	nop
Lbd1:	or %g4, 16, %g4
Lbd2:
	sethi %hi(w_brless), %g1
	or %g1, %lo(w_brless), %g1
	stx %g4, [%g1]
	cmp %g4, 0x11			! fbl-s + fbl-d taken only
	be C12ok
	nop
	add %g5, 1, %g5
C12ok:
	PRINT64 msg_brless, w_brless

! ---------- T4b: fcc0 equal ----------
	fcmps %fcc0, %f0, %f0
	sethi %hi(w_fsre), %g1
	or %g1, %lo(w_fsre), %g1
	stx %fsr, [%g1]
	PRINT64 msg_fsre, w_fsre
	mov 0, %g4
	fbe %fcc0, Leq1
	nop
	ba Leq2
	nop
Leq1:	or %g4, 1, %g4
Leq2:
	fbl %fcc0, Lne1
	nop
	ba Lne2
	nop
Lne1:	or %g4, 2, %g4
Lne2:
	sethi %hi(w_breq), %g1
	or %g1, %lo(w_breq), %g1
	stx %g4, [%g1]
	cmp %g4, 1			! fbe taken, fbl not
	be C13ok
	nop
	add %g5, 1, %g5
C13ok:
	PRINT64 msg_breq, w_breq

! ---------- T4c: fcc0 unordered (NaN) ----------
	sethi %hi(cnan), %g1
	or %g1, %lo(cnan), %g1
	ld [%g1], %f7			! f7 = QNaN
	fcmps %fcc0, %f7, %f0
	sethi %hi(w_fsru), %g1
	or %g1, %lo(w_fsru), %g1
	stx %fsr, [%g1]
	PRINT64 msg_fsru, w_fsru
	mov 0, %g4
	fbu %fcc0, Lu1
	nop
	ba Lu2
	nop
Lu1:	or %g4, 1, %g4
Lu2:
	fbo %fcc0, Lo1
	nop
	ba Lo2
	nop
Lo1:	or %g4, 2, %g4
Lo2:
	sethi %hi(w_brunord), %g1
	or %g1, %lo(w_brunord), %g1
	stx %g4, [%g1]
	cmp %g4, 1			! fbu taken, fbo not
	be C14ok
	nop
	add %g5, 1, %g5
C14ok:
	PRINT64 msg_brunord, w_brunord

! ---------- T4d: fcc1..fcc3 ----------
	fcmps %fcc1, %f0, %f1		! less -> fcc1
	fcmps %fcc2, %f0, %f0		! equal -> fcc2
	fcmps %fcc3, %f7, %f0		! unordered -> fcc3
	sethi %hi(w_fsr123), %g1
	or %g1, %lo(w_fsr123), %g1
	stx %fsr, [%g1]
	PRINT64 msg_fsr123, w_fsr123
	mov 0, %g4
	fbl %fcc1, Lcc1
	nop
	ba Lcc1d
	nop
Lcc1:	or %g4, 1, %g4
Lcc1d:
	fbe %fcc2, Lcc2
	nop
	ba Lcc2d
	nop
Lcc2:	or %g4, 2, %g4
Lcc2d:
	fbu %fcc3, Lcc3
	nop
	ba Lcc3d
	nop
Lcc3:	or %g4, 4, %g4
Lcc3d:
	sethi %hi(w_br123), %g1
	or %g1, %lo(w_br123), %g1
	stx %g4, [%g1]
	cmp %g4, 7
	be C15ok
	nop
	add %g5, 1, %g5
C15ok:
	PRINT64 msg_br123, w_br123

! ---------- T5a: FMOVcc on fcc0 ----------
	fcmps %fcc0, %f0, %f0		! equal
	sethi %hi(cmark), %g1
	or %g1, %lo(cmark), %g1
	ld [%g1], %f14			! marker
	fmovse %fcc0, %f0, %f12		! taken: f12 = 1.0f
	fmovsne %fcc0, %f1, %f14	! not taken: f14 stays marker
	sethi %hi(w_fmovfcc), %g1
	or %g1, %lo(w_fmovfcc), %g1
	st %f12, [%g1]
	sethi %hi(w_fmovfcchi), %g1
	or %g1, %lo(w_fmovfcchi), %g1
	st %f14, [%g1]
! check f12 == 0x3f800000
	sethi %hi(w_fmovfcc), %g1
	or %g1, %lo(w_fmovfcc), %g1
	ld [%g1], %g4
	sethi %hi(0x3f800000), %o3
	cmp %g4, %o3
	be C16ok
	nop
	add %g5, 1, %g5
C16ok:
! check f14 == marker 0xdeadbeef (lduw: ld would sign-extend)
	sethi %hi(w_fmovfcchi), %g1
	or %g1, %lo(w_fmovfcchi), %g1
	lduw [%g1], %g4
	sethi %hi(0xdeadbeef), %o3
	or %o3, %lo(0xdeadbeef), %o3
	cmp %g4, %o3
	be C17ok
	nop
	add %g5, 1, %g5
C17ok:
	PRINT32 msg_fmovfcc, w_fmovfcc
	PRINT32 msg_fmovfcchi, w_fmovfcchi
! FMOVd on fcc0 (equal): d16 = 1.0
	sethi %hi(cmarkd), %g1
	or %g1, %lo(cmarkd), %g1
	ldd [%g1], %d16			! marker pair
	fmovde %fcc0, %d32, %d16		! taken: d16 = 1.0 (d32 = 1.0)
	sethi %hi(w_fmovd), %g1
	or %g1, %lo(w_fmovd), %g1
	std %d16, [%g1]
	sethi %hi(w_fmovd), %g1
	or %g1, %lo(w_fmovd), %g1
	ldx [%g1], %g4
	sethi %hi(0x3ff00000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C18ok
	nop
	add %g5, 1, %g5
C18ok:
	PRINT64 msg_fmovd, w_fmovd

! ---------- T5b: FMOVr on icc ----------
	sethi %hi(cmark), %g1
	or %g1, %lo(cmark), %g1
	ld [%g1], %f18			! marker
	subcc %g1, %g1, %g0		! Z = 1 (icc zero)
	fmovse %icc, %f0, %f16		! taken: f16 = 1.0f
	fmovsne %icc, %f1, %f18		! not taken: marker stays
	sethi %hi(w_fmovicc), %g1
	or %g1, %lo(w_fmovicc), %g1
	st %f16, [%g1]
	sethi %hi(w_fmovicchi), %g1
	or %g1, %lo(w_fmovicchi), %g1
	st %f18, [%g1]
! check f16 == 0x3f800000
	sethi %hi(w_fmovicc), %g1
	or %g1, %lo(w_fmovicc), %g1
	ld [%g1], %g4
	sethi %hi(0x3f800000), %o3
	cmp %g4, %o3
	be C19ok
	nop
	add %g5, 1, %g5
C19ok:
! check f18 == marker (lduw: ld would sign-extend)
	sethi %hi(w_fmovicchi), %g1
	or %g1, %lo(w_fmovicchi), %g1
	lduw [%g1], %g4
	sethi %hi(0xdeadbeef), %o3
	or %o3, %lo(0xdeadbeef), %o3
	cmp %g4, %o3
	be C20ok
	nop
	add %g5, 1, %g5
C20ok:
	PRINT32 msg_fmovicc, w_fmovicc
	PRINT32 msg_fmovicchi, w_fmovicchi

! ---------- T6: VIS alignaddr + faligndata ----------
! v1 = 0x0102030405060708 in %g4, v2 = 0x1112131415161718 in %o3
	sethi %hi(0x01020304), %g4
	or %g4, %lo(0x01020304), %g4
	sllx %g4, 32, %g4
	sethi %hi(0x05060708), %g1
	or %g1, %lo(0x05060708), %g1
	or %g4, %g1, %g4
	sethi %hi(0x11121314), %o3
	or %o3, %lo(0x11121314), %o3
	sllx %o3, 32, %o3
	sethi %hi(0x15161718), %g1
	or %g1, %lo(0x15161718), %g1
	or %o3, %g1, %o3
	sethi %hi(w_visbuf), %g1
	or %g1, %lo(w_visbuf), %g1
	stx %g4, [%g1]
	stx %o3, [%g1 + 8]
	ldd [%g1], %f0
	ldd [%g1 + 8], %f2
	mov 3, %g4
	alignaddr %g4, %g0, %o3		! rd = 0, GSR.offset = 3
	rd %gsr, %g4
	faligndata %f0, %f2, %f4
	sethi %hi(w_vis), %g1
	or %g1, %lo(w_vis), %g1
	std %f4, [%g1]
	sethi %hi(w_gsr), %g1
	or %g1, %lo(w_gsr), %g1
	stx %g4, [%g1]
	sethi %hi(w_aard), %g1
	or %g1, %lo(w_aard), %g1
	stx %o3, [%g1]
! check faligndata == 0x0405060708111213
	sethi %hi(w_vis), %g1
	or %g1, %lo(w_vis), %g1
	ldx [%g1], %g4
	sethi %hi(0x04050607), %o3
	or %o3, %lo(0x04050607), %o3
	sllx %o3, 32, %o3
	sethi %hi(0x08111213), %o4
	or %o4, %lo(0x08111213), %o4
	or %o3, %o4, %o3
	cmp %g4, %o3
	be C21ok
	nop
	add %g5, 1, %g5
C21ok:
! check GSR == 3
	sethi %hi(w_gsr), %g1
	or %g1, %lo(w_gsr), %g1
	ldx [%g1], %g4
	cmp %g4, 3
	be C22ok
	nop
	add %g5, 1, %g5
C22ok:
! check alignaddr rd == 0
	sethi %hi(w_aard), %g1
	or %g1, %lo(w_aard), %g1
	ldx [%g1], %g4
	cmp %g4, %g0
	be C23ok
	nop
	add %g5, 1, %g5
C23ok:
	PRINT64 msg_falign, w_vis
	PRINT64 msg_gsr, w_gsr
	PRINT64 msg_aard, w_aard

! ---------- T7: quad-precision (last: reuses low FPU regs) ----------
	sethi %hi(c1q), %g1
	or %g1, %lo(c1q), %g1
	ldd [%g1], %f0
	ldd [%g1 + 8], %f2		! q0 = 1.0Q
	sethi %hi(c2q), %g1
	or %g1, %lo(c2q), %g1
	ldd [%g1], %f4
	ldd [%g1 + 8], %f6		! q4 = 2.0Q
	faddq %f0, %f4, %f8		! q8 = 3.0Q
	fmovq %f8, %f12			! q12 = q8 (f12..f15 free now)
	sethi %hi(w_quad), %g1
	or %g1, %lo(w_quad), %g1
	std %f8, [%g1]			! q8 hi (d8)
	std %f10, [%g1 + 8]		! q8 lo (d10)
	std %f12, [%g1 + 16]		! q12 hi (d12)
	std %f14, [%g1 + 24]		! q12 lo (d14)
! check quad hi == 0x4000800000000000
	ldx [%g1], %g4
	sethi %hi(0x40008000), %o3
	sllx %o3, 32, %o3
	cmp %g4, %o3
	be C24ok
	nop
	add %g5, 1, %g5
C24ok:
! check quad lo == 0
	ldx [%g1 + 8], %g4
	cmp %g4, %g0
	be C25ok
	nop
	add %g5, 1, %g5
C25ok:
! check fmovq halves match q8
	ldx [%g1 + 16], %g4
	cmp %g4, %o3
	be C26ok
	nop
	add %g5, 1, %g5
C26ok:
	ldx [%g1 + 24], %g4
	cmp %g4, %g0
	be C27ok
	nop
	add %g5, 1, %g5
C27ok:
	PRINT64 msg_quadhi, w_quad
	PRINT64 msg_quadlo, w_quadlo
	PRINT64 msg_quadmvhi, w_quadmv
	PRINT64 msg_quadmvlo, w_quadmvlo
! T7b: STQF quirk probe (observation only, no self-check).
! qemu-sparc64 7.2 duplicates the HIGH double into both halves.
	sethi %hi(w_stq), %g1
	or %g1, %lo(w_stq), %g1
	stq %f8, [%g1]
	PRINT64 msg_stqhi, w_stq
	PRINT64 msg_stqlo, w_stqlo

! ---------- verdict ----------
	cmp %g5, 0
	bne Lfail
	nop
	sethi %hi(msg_pass), %g4
	or %g4, %lo(msg_pass), %g4
	call puts
	nop
	mov 0, %o0
	mov 1, %g1
	ta 0x6d
Lfail:
	sethi %hi(msg_fail), %g4
	or %g4, %lo(msg_fail), %g4
	call puts
	nop
	mov 1, %o0
	mov 1, %g1
	ta 0x6d

! ---------- helpers (leaf; use %g1/%g4/%o0-%o4; preserve %g5) ----------
puts:					! %g4 = asciz ptr
	mov %g4, %o3
1:	ldub [%o3], %g1
	add %o3, 1, %o3
	cmp %g1, 0
	bne 1b
	nop
	sub %o3, %g4, %o2
	sub %o2, 1, %o2			! exclude NUL (add runs in delay slot)
	mov %g4, %o1
	mov 1, %o0
	mov 4, %g1
	ta 0x6d
	retl
	nop
puthex32:				! %g4 = value, prints low 8 nibbles
	sethi %hi(hexbuf), %o3
	or %o3, %lo(hexbuf), %o3
	mov 28, %o4
1:	srlx %g4, %o4, %g1
	and %g1, 0xf, %g1
	cmp %g1, 10
	bl 2f
	nop
	add %g1, 'a' - 10, %g1
	ba 3f
	nop
2:	add %g1, '0', %g1
3:	stb %g1, [%o3]
	add %o3, 1, %o3
	subcc %o4, 4, %o4
	bge 1b
	nop
	sethi %hi(hexbuf), %o1
	or %o1, %lo(hexbuf), %o1
	mov 1, %o0
	mov 8, %o2
	mov 4, %g1
	ta 0x6d
	retl
	nop
puthex64:				! %g4 = value, prints 16 nibbles
	sethi %hi(hexbuf), %o3
	or %o3, %lo(hexbuf), %o3
	mov 60, %o4
1:	srlx %g4, %o4, %g1
	and %g1, 0xf, %g1
	cmp %g1, 10
	bl 2f
	nop
	add %g1, 'a' - 10, %g1
	ba 3f
	nop
2:	add %g1, '0', %g1
3:	stb %g1, [%o3]
	add %o3, 1, %o3
	subcc %o4, 4, %o4
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
	mov '\n', %g4
putc:					! %g4 = char
	sethi %hi(charbuf), %o3
	or %o3, %lo(charbuf), %o3
	stb %g4, [%o3]
	mov 1, %o0
	mov %o3, %o1
	mov 1, %o2
	mov 4, %g1
	ta 0x6d
	retl
	nop

	.data
	.align 4
msg_head:	.asciz "E05 sparc64 V9 FPU+VIS\n"
msg_fsr0:	.asciz "fsr0="
msg_fadds:	.asciz "fadds="
msg_fsubs:	.asciz "fsubs="
msg_fmuls:	.asciz "fmuls="
msg_fdivs:	.asciz "fdivs="
msg_fsmuld:	.asciz "fsmuld="
msg_faddd:	.asciz "faddd="
msg_fsubd:	.asciz "fsubd="
msg_fmuld:	.asciz "fmuld="
msg_fdivd:	.asciz "fdivd="
msg_aliasd:	.asciz "aliasd="
msg_aliasf:	.asciz "aliasf="
msg_fsrl:	.asciz "fsr-less="
msg_brless:	.asciz "br-less="
msg_fsre:	.asciz "fsr-eq="
msg_breq:	.asciz "br-eq="
msg_fsru:	.asciz "fsr-unord="
msg_brunord:	.asciz "br-unord="
msg_fsr123:	.asciz "fsr-123="
msg_br123:	.asciz "br-123="
msg_fmovfcc:	.asciz "fmov-fcc="
msg_fmovfcchi:	.asciz "fmov-fcc-hi="
msg_fmovd:	.asciz "fmovd="
msg_fmovicc:	.asciz "fmov-icc="
msg_fmovicchi:	.asciz "fmov-icc-hi="
msg_falign:	.asciz "falign="
msg_gsr:	.asciz "gsr="
msg_aard:	.asciz "aard="
msg_quadhi:	.asciz "quad-hi="
msg_quadlo:	.asciz "quad-lo="
msg_quadmvhi:	.asciz "quadmv-hi="
msg_quadmvlo:	.asciz "quadmv-lo="
msg_stqhi:	.asciz "stq-hi="
msg_stqlo:	.asciz "stq-lo="
msg_pass:	.asciz "E05-PASS\n"
msg_fail:	.asciz "E05-FAIL\n"
	.align 4
c1f:	.word 0x3f800000
c2f:	.word 0x40000000
c8f:	.word 0x41000000
cnan:	.word 0x7fc00000
cmark:	.word 0xdeadbeef
	.align 8
c1d:	.xword 0x3ff0000000000000
c2d:	.xword 0x4000000000000000
c8d:	.xword 0x4020000000000000
cmarkd:	.xword 0xdeadbeefdeadbeef
	.align 8
c1q:	.xword 0x3fff000000000000
	.xword 0x0000000000000000
c2q:	.xword 0x4000000000000000
	.xword 0x0000000000000000
	.section .bss
	.align 8
hexbuf:	.skip 16
charbuf:	.skip 8
w_fsr0:	.skip 8
w_fadds:	.skip 4
w_fsubs:	.skip 4
w_fmuls:	.skip 4
w_fdivs:	.skip 4
w_fsmuld:	.skip 8
w_faddd:	.skip 8
w_fsubd:	.skip 8
w_fmuld:	.skip 8
w_fdivd:	.skip 8
w_aliasd:	.skip 8
w_aliasf:	.skip 8
w_fsrl:	.skip 8
w_brless:	.skip 8
w_fsre:	.skip 8
w_breq:	.skip 8
w_fsru:	.skip 8
w_brunord:	.skip 8
w_fsr123:	.skip 8
w_br123:	.skip 8
w_fmovfcc:	.skip 4
w_fmovfcchi:	.skip 4
w_fmovd:	.skip 8
w_fmovicc:	.skip 4
w_fmovicchi:	.skip 4
w_visbuf:	.skip 16
w_vis:	.skip 8
w_gsr:	.skip 8
w_aard:	.skip 8
	.align 16
w_quad:	.skip 8
w_quadlo:	.skip 8
w_quadmv:	.skip 8
w_quadmvlo:	.skip 8
	.align 16
w_stq:	.skip 8
w_stqlo:	.skip 8
	.section .note.GNU-stack,"",@progbits
