; Listing generated by Microsoft (R) Optimizing Compiler Version 15.00.30729.207 

include listing.inc

INCLUDELIB OLDNAMES

PUBLIC	PtrToUlong
EXTRN	__imp_KeSetTimerEx:PROC
EXTRN	__imp_RtlUnicodeStringToInteger:PROC
PUBLIC	KeSetCoalescableTimer_k8
;	COMDAT pdata
; File d:\develop\mods\ntoskrnl_emu\common.c
pdata	SEGMENT
$pdata$KeSetCoalescableTimer_k8 DD imagerel $LN3
	DD	imagerel $LN3+23
	DD	imagerel $unwind$KeSetCoalescableTimer_k8
pdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$KeSetCoalescableTimer_k8 DD 010401H
	DD	04204H
; Function compile flags: /Ogspy
xdata	ENDS
;	COMDAT KeSetCoalescableTimer_k8
_TEXT	SEGMENT
Timer$ = 48
DueTime$ = 56
Period$ = 64
TolerableDelay$ = 72
Dpc$ = 80
KeSetCoalescableTimer_k8 PROC				; COMDAT

; 21   : {

$LN3:
	sub	rsp, 40					; 00000028H

; 22   :    return KeSetTimerEx(
; 23   :             Timer,
; 24   :             DueTime,
; 25   :             Period,
; 26   :             Dpc );     

	mov	r9, QWORD PTR Dpc$[rsp]
	xor	r8d, r8d
	call	QWORD PTR __imp_KeSetTimerEx

; 27   : }

	add	rsp, 40					; 00000028H
	ret	0
KeSetCoalescableTimer_k8 ENDP
END
