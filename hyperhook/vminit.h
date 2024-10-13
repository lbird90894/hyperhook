/*
 * MIT License
 *
 * Copyright (c) 2024 lbird90894
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once
#include <ntddk.h>
#include "vmcs.h"

#define GUEST_VPID 1


/****************************************************************
						Type Definition
****************************************************************/
typedef enum _VMX_STATUS
{
	VMX_START_ALL,
	VMX_STOP_ALL,
} VMX_STATUS;


typedef struct _VMXOFF_RESTORE_DATA
{
	UINT64 cr0;
	UINT64 cr4;
} VMXOFF_RESTORE_DATA, *PVMXOFF_RESTORE_DATA;


typedef struct _VIRTUAL_MACHINE_STATE
{
	BOOLEAN bHost;							// Indicate whether the core host or guest
	BOOLEAN bLaunched;						// Indicate whether the core is virtualized or not
	PVOID VmxonRegionVirtualAddress;
	PVOID VmcsRegionVirtualAddress;
	PVOID MsrBitmapVirtualAddress;
	UINT64 HostStack;
	VMXOFF_RESTORE_DATA VmxoffRestoreData;
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;


typedef struct _GUEST_CONTEXT
{
	UINT64 Rax;
	UINT64 Rcx;
	UINT64 Rdx;
	UINT64 Rbx;
	UINT64 Rbp;
	UINT64 Rsi;
	UINT64 Rdi;
	UINT64 R8;
	UINT64 R9;
	UINT64 R10;
	UINT64 R11;
	UINT64 R12;
	UINT64 R13;
	UINT64 R14;
	UINT64 R15;
} GUEST_CONTEXT, *PGUEST_CONTEXT;


/****************************************************************
					   Function Declaration
****************************************************************/
PVIRTUAL_MACHINE_STATE GetCurrentVmState();
UINT64 GetPhysicalAddress(IN PVOID pVirtualAddr);

VOID VirtualizeProcessorInternal(IN PVOID pGuestStack, IN UINT64 GuestRflags);
BOOLEAN VmxInitialize();
VOID VmxTerminate();
PVOID AllocateContiguousMemory(IN UINT64 NumberOfBytes);
VOID FreeContiguousMemory(IN PVOID pVirtualAddr);
VOID HostSendMessage(IN ULONG ulMsgId, IN OPTIONAL PVOID pContext);