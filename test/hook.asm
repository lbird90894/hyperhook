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

EXTERN Filter_NtCreateFile:PROC
EXTERN Real_NtCreateFile:QWORD

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

Hook_NtCreateFile PROC
	CaptureContext

	mov rcx, r8
	call Filter_NtCreateFile
	
	RestoreContext
	
	sub rsp, 88h

	push Real_NtCreateFile
	ret; jmp Real_NtCreateFile

Hook_NtCreateFile ENDP

;------------------------------------------------------------------------

END