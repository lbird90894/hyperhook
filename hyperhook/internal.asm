;;
 ; MIT License
 ;
 ; Copyright (c) 2024 lbird90894
 ;
 ; Permission is hereby granted, free of charge, to any person obtaining a copy
 ; of this software and associated documentation files (the "Software"), to deal
 ; in the Software without restriction, including without limitation the rights
 ; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 ; copies of the Software, and to permit persons to whom the Software is
 ; furnished to do so, subject to the following conditions:
 ;
 ; The above copyright notice and this permission notice shall be included in all
 ; copies or substantial portions of the Software.
 ;
 ; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 ; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 ; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 ; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 ; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 ; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ;;

EXTERN VmexitHandler:PROC
EXTERN VirtualizeProcessorInternal:PROC
EXTERN SetVmxOff:PROC
EXTERN LoggingResumeError:PROC

CONTEXT_SIZE EQU 15*8
LocalVariable EQU rsp + CONTEXT_SIZE
LOCAL_AREA_SIZE EQU 0100h
GARBAGE_SIZE EQU 0100h



;------------------------------------------------------------------------

AllocLocalArea MACRO; For temp variable
	sub rsp, LOCAL_AREA_SIZE
ENDM

;------------------------------------------------------------------------

AllocStackGuard MACRO
	sub rsp, GARBAGE_SIZE
ENDM

;------------------------------------------------------------------------

DeAllocStackGuard MACRO
	add rsp, GARBAGE_SIZE
ENDM

;------------------------------------------------------------------------

CaptureContext MACRO	
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push rbx
	push rdx
	push rcx
	push rax
	
ENDM

;------------------------------------------------------------------------

RestoreContext MACRO
	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	
ENDM

;------------------------------------------------------------------------

.code

;------------------------------------------------------------------------

GetContext PROC
	mov		[rcx],		cs
	mov		[rcx+2],	ds
	mov		[rcx+4],	es
	mov		[rcx+6],	fs
	mov		[rcx+8],	gs
	mov		[rcx+10],	ss

	str		ax			; get tr
	mov		[rcx+12],	ax

	sldt	ax			; get ldtr
	mov		[rcx+14],	ax

	sgdt	[rcx+16]	; get gdtr

	sidt	[rcx+26]	; get idtr
	
	ret

Getcontext ENDP

;------------------------------------------------------------------------

VirtualizeProcessor PROC
	pushfq
	CaptureContext
	mov rcx, rsp
	mov rdx, [rsp + CONTEXT_SIZE]

	AllocStackGuard; x64 calling convention may use more than 5 arguments
	call VirtualizeProcessorInternal; Restore context and jmp to Guest.
	DeAllocStackGuard; This code cannot be excuted.(Caller of VirtualizeProcessor handler this error)
	
	RestoreContext
	popfq
	ret

VirtualizeProcessor ENDP

;------------------------------------------------------------------------

GuestEntryPoint PROC
	RestoreContext
	popfq
	ret; return to VirtualizeProcessor
	
GuestEntryPoint ENDP

;------------------------------------------------------------------------

HostEntryPoint PROC
	pushfq
	AllocLocalArea; For temp variable
	CaptureContext

	mov rax, [rsp + CONTEXT_SIZE + GARBAGE_SIZE]
	mov [rsp + CONTEXT_SIZE], rax; [LocalVariable] = rflags
	mov rcx, rsp

	AllocStackGuard
	call VmexitHandler
	DeAllocStackGuard

	cmp	al, 1
	je devirtualize

	RestoreContext
	popfq

	vmresume

	AllocStackGuard
	call LoggingResumeError; This code cannot be excuted
	DeAllocStackGuard
	int 3; cannot be handled

devirtualize:
	lea rcx, [LocalVariable]; Not use rflags
	lea rdx, [LocalVariable + 8]

	AllocStackGuard
	call SetVmxOff; rcx = GuestRsp, rdx = GuestRip
	DeAllocStackGuard

	mov r10, [LocalVariable]
	mov r11, [LocalVariable + 8]
	mov [r10 - 8], r11; [GuestRsp - 8] = GuestRip
	lea r12, [r10 - 8];
	mov [LocalVariable], r12; [LocalVariable] = GuestRsp - 8
	
	RestoreContext

	mov rsp, [LocalVariable - Context_Size]; mov rsp, GuestRsp - 8
	ret; jmp GuestRip
	
HostEntryPoint ENDP

;------------------------------------------------------------------------

HostSendMessageInternal PROC
	pushfq
	vmcall
	popfq
	ret
HostSendMessageInternal ENDP

;------------------------------------------------------------------------

InvalidateEpt PROC
	invept rcx, oword ptr [rdx]
	ret
InvalidateEpt ENDP

;------------------------------------------------------------------------

SetGdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lgdt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
SetGdtr ENDP

;------------------------------------------------------------------------

SetIdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lidt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
SetIdtr ENDP

;------------------------------------------------------------------------


END