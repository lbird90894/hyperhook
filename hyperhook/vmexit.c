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

#include "log.h"
#include "cpuid.h"
#include "vmcall.h"
#include "interrupt.h"
#include "hook.h"
#include "vminit.h"
#include "spinlock.h"
#include "vmexit.h"


/****************************************************************
					  Constant Definition
****************************************************************/
/* VM-exit Reasons */
#define EXIT_REASON_EXCEPTION_NMI					 0
#define EXIT_REASON_EXTERNAL_INTERRUPT				 1
#define EXIT_REASON_TRIPLE_FAULT					 2
#define EXIT_REASON_INIT							 3
#define EXIT_REASON_SIPI							 4
#define EXIT_REASON_IO_SMI							 5
#define EXIT_REASON_OTHER_SMI						 6
#define EXIT_REASON_PENDING_VIRT_INTR				 7
#define EXIT_REASON_PENDING_VIRT_NMI				 8
#define EXIT_REASON_TASK_SWITCH						 9
#define EXIT_REASON_CPUID							 10
#define EXIT_REASON_GETSEC							 11
#define EXIT_REASON_HLT								 12
#define EXIT_REASON_INVD							 13
#define EXIT_REASON_INVLPG							 14
#define EXIT_REASON_RDPMC							 15
#define EXIT_REASON_RDTSC							 16
#define EXIT_REASON_RSM								 17
#define EXIT_REASON_VMCALL							 18
#define EXIT_REASON_VMCLEAR							 19
#define EXIT_REASON_VMLAUNCH						 20
#define EXIT_REASON_VMPTRLD							 21
#define EXIT_REASON_VMPTRST							 22
#define EXIT_REASON_VMREAD							 23
#define EXIT_REASON_VMRESUME						 24
#define EXIT_REASON_VMWRITE							 25
#define EXIT_REASON_VMXOFF							 26
#define EXIT_REASON_VMXON							 27
#define EXIT_REASON_CR_ACCESS						 28
#define EXIT_REASON_DR_ACCESS						 29
#define EXIT_REASON_IO_INSTRUCTION					 30
#define EXIT_REASON_MSR_READ						 31
#define EXIT_REASON_MSR_WRITE						 32
#define EXIT_REASON_INVALID_GUEST_STATE				 33
#define EXIT_REASON_MSR_LOADING						 34
#define EXIT_REASON_MWAIT_INSTRUCTION				 36
#define EXIT_REASON_MONITOR_TRAP_FLAG				 37
#define EXIT_REASON_MONITOR_INSTRUCTION				 39
#define EXIT_REASON_PAUSE_INSTRUCTION				 40
#define EXIT_REASON_MCE_DURING_VMENTRY				 41
#define EXIT_REASON_TPR_BELOW_THRESHOLD				 43
#define EXIT_REASON_APIC_ACCESS						 44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR				 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR				 47
#define EXIT_REASON_EPT_VIOLATION					 48
#define EXIT_REASON_EPT_MISCONFIG					 49
#define EXIT_REASON_INVEPT							 50
#define EXIT_REASON_RDTSCP							 51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED     52
#define EXIT_REASON_INVVPID						     53
#define EXIT_REASON_WBINVD						     54
#define EXIT_REASON_XSETBV						     55
#define EXIT_REASON_APIC_WRITE					     56
#define EXIT_REASON_RDRAND						     57
#define EXIT_REASON_INVPCID						     58
#define EXIT_REASON_RDSEED						     61
#define EXIT_REASON_PML_FULL					     62
#define EXIT_REASON_XSAVES						     63
#define EXIT_REASON_XRSTORS						     64
#define EXIT_REASON_PCOMMIT						     65


/****************************************************************
						Type Definition
****************************************************************/
typedef union _EPT_VIOLATION_INFO
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;						// [0]	Reason of ept violation is read
		UINT64 Write : 1;						// [1]	Reason of ept violation is write
		UINT64 Execute : 1;						// [2]	Reason of ept violation is execute
		UINT64 EptRead : 1;						// [3]	Indicate ept paging entry's read bit
		UINT64 EptWrite : 1;					// [4]	Indicate ept paging entry's write bit
		UINT64 EptExecute : 1;					// [5]	Indicate ept paging entry's execute bit
		UINT64 EptUserModeExecute : 1;			// [6]	Indicate ept paging entry;s UserModeExecute bit

		UINT64 ValidGuestLinearAddress : 1;		// [7]	Indicate whether guest's linear address is valid
		// Most case linear address is valid, but mov cr makes linear address be invalid

		UINT64 CausedByTranslation : 1;			// [8]	This bit only has meaning following facts if ValidGuestLinearAddress is 1
		// This bit is set if reason of ept violation is address translation
		// This bit is clear if reason of ept violation is access or dirty(eptp's 6th bit must be set)

		/* 9 ~ 11 bit only has meaning if MSR_IA32_VMX_EPT_VPID_CAP's AdvancedEptViolation is 1 */
		UINT64 UserModeLinearAddress : 1;		// [9]
		UINT64 WritePage : 1;					// [10]
		UINT64 ExecuteDisablePage : 1;			// [11]
		UINT64 NmiUnblocking : 1;				// [12] nmi unblocking during iret
		UINT64 ShadowStack : 1;					// [13]	Reason of ept violation is shadow stack
		UINT64 EptShadowStack : 1;				// [14] Indicate ept paging entry's ShadowStack bit
		UINT64 VerifyGuestPaging : 1;			// [15] Reason of ept violation is guest paging verification
		UINT64 Asynchronous : 1;				// [16] Async instruction(interrupt) is excuted
		UINT64 Reserved1 : 47;					// [63:17]
	};
} EPT_VIOLATION_INFO, *PEPT_VIOLATION_INFO;


/****************************************************************
						Global Variable
****************************************************************/
extern UINT64 g_Eptp;
extern LIST_ENTRY g_LogWorkList;
extern LIST_ENTRY g_LogDispatchList;
extern volatile LONG g_LogWorkListLock;


/****************************************************************
					   Function Definition
****************************************************************/
static
BOOLEAN EptViolationHandler(IN EPT_VIOLATION_INFO EptViolationInfo)
{
	PVOID GuestVirtualAddress;
	UINT64 GuestPhysicalAddress;
	BOOLEAN bSuccess = FALSE;

	__vmx_vmread(GUEST_LINEAR_ADDRESS, &GuestVirtualAddress);
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddress);
	if (1 == EptViolationInfo.Read)
	{
		if (ReplaceFakeWithOrigin(GuestPhysicalAddress))
		{
			LogWrite(LOG_INFO, L"Ept read violation occured and handling success (pid: %d, tid: %d) -> (V: 0x%llx, P: 0x%llx)",
				PsGetCurrentProcessId(),
				PsGetCurrentThreadId(),
				GuestVirtualAddress,
				GuestPhysicalAddress);

			bSuccess = TRUE;
		}
		else
		{
			LogWrite(LOG_ERROR, L"Ept read violation occured and handling fail (pid: %d, tid: %d) -> (V: 0x%llx, P: 0x%llx)",
				PsGetCurrentProcessId(),
				PsGetCurrentThreadId(),
				GuestVirtualAddress,
				GuestPhysicalAddress);
		}
	}
	else if (1 == EptViolationInfo.Execute)
	{
		if (ReplaceOriginWithFake(GuestPhysicalAddress))
		{
			LogWrite(LOG_INFO, L"Ept execute violation occured and handling success (pid: %d, tid: %d) -> (V: 0x%llx, P: 0x%llx)",
				PsGetCurrentProcessId(),
				PsGetCurrentThreadId(),
				GuestVirtualAddress,
				GuestPhysicalAddress);

			bSuccess = TRUE;
		}
		else
		{
			LogWrite(LOG_ERROR, L"Ept execute violation occured and handling fail (pid: %d, tid: %d) -> (V: 0x%llx, P: 0x%llx)",
				PsGetCurrentProcessId(),
				PsGetCurrentThreadId(),
				GuestVirtualAddress,
				GuestPhysicalAddress);
		}
	}

	return bSuccess;
}


static
BOOLEAN VmcallHandler(IN ULONG ulMsgId, IN PVOID pContext, OUT PBOOLEAN pbVmxOff)
{
	if (NULL == pbVmxOff)
	{
		return FALSE;
	}
	*pbVmxOff = FALSE;

	if (HOST_MSG_ID_MODIFY_EPT_PTE == ulMsgId)
	{
		PHOST_MSG_MODIFY_PAGE_DATA pModifyPageData = pContext;

		InterlockedExchange64(pModifyPageData->pEptPte, pModifyPageData->PageEntryValue);
		InvalidateAddress(g_Eptp);

	}
	else if (HOST_MSG_ID_VMX_OFF == ulMsgId)
	{
		*pbVmxOff = TRUE;
	}
	else if (HOST_MSG_ID_LOG == ulMsgId)
	{
		PHOST_MSG_LOG_DATA pLogData = pContext;

		if (pLogData->pListEntry)
		{
			AcquireHostLock(&g_LogWorkListLock);
			InsertTailList(&g_LogWorkList, pLogData->pListEntry);
			ReleaseHostLock(&g_LogWorkListLock);
		}
		else
		{
			AcquireHostLock(&g_LogWorkListLock);

			g_LogDispatchList.Flink = g_LogWorkList.Flink;
			g_LogDispatchList.Blink = g_LogWorkList.Blink;
			g_LogWorkList.Flink->Blink = &g_LogDispatchList;
			g_LogWorkList.Blink->Flink = &g_LogDispatchList;
			InitializeListHead(&g_LogWorkList);

			ReleaseHostLock(&g_LogWorkListLock);
		}
	}

	return TRUE;
}


static
VOID ResumeNextInstruction()
{
	UINT64 CurrentRip, ResumeRip, InstructionLength;
	UINT64 ExitInstrLength;

	__vmx_vmread(GUEST_RIP, &CurrentRip);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &InstructionLength);

	ResumeRip = CurrentRip + InstructionLength;

	__vmx_vmread(VM_ENTRY_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(GUEST_RIP, ResumeRip);
}


/* During vmx root mode, paging is normal pml4 not ept paging */
BOOLEAN VmexitHandler(IN PGUEST_CONTEXT pGuestContext)
{
	BOOLEAN bVmxoff = FALSE;
	BOOLEAN bResumeNextInstruction = FALSE;
	UINT64 ExitReason;

	GetCurrentVmState()->bHost = TRUE;
	__vmx_vmread(EXIT_REASON, &ExitReason);
	ExitReason &= 0xffff;

	switch (ExitReason)
	{
	case EXIT_REASON_CPUID:
	{
		CPUID CpuInfo;

		__cpuidex((int*)&CpuInfo, (int)pGuestContext->Rax, (int)pGuestContext->Rcx);
		pGuestContext->Rax = CpuInfo.eax;
		pGuestContext->Rbx = CpuInfo.ebx;
		pGuestContext->Rcx = CpuInfo.ecx;
		pGuestContext->Rdx = CpuInfo.edx;

		bResumeNextInstruction = TRUE;
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		LARGE_INTEGER MsrValue;

		MsrValue.QuadPart = __readmsr(pGuestContext->Rcx);
		pGuestContext->Rax = MsrValue.LowPart;
		pGuestContext->Rdx = MsrValue.HighPart;

		bResumeNextInstruction = TRUE;
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		LARGE_INTEGER MsrValue;

		MsrValue.LowPart = (ULONG)pGuestContext->Rax;
		MsrValue.HighPart = (ULONG)pGuestContext->Rdx;
		__writemsr(pGuestContext->Rcx, MsrValue.QuadPart);

		bResumeNextInstruction = TRUE;
		break;
	}
	case EXIT_REASON_EXCEPTION_NMI:// guest cause exception or NMI(0 <= interrupt vector < 32)
	{
		UINT64 InterruptExit;

		__vmx_vmread(VM_EXIT_INTR_INFO, &InterruptExit);
		ExceptionHandler(InterruptExit);

		bResumeNextInstruction = FALSE;
		break;
	}
	case EXIT_REASON_EPT_VIOLATION:
	{
		UINT64 EptViolationInfo;

		__vmx_vmread(EXIT_QUALIFICATION, &EptViolationInfo);
		bResumeNextInstruction = !EptViolationHandler(*(PEPT_VIOLATION_INFO)(&EptViolationInfo));

		break;
	}
	case EXIT_REASON_EPT_MISCONFIG:
	{
		UINT64 GuestPhysicalAddress;
		PVOID GuestRip;

		__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddress);
		__vmx_vmread(GUEST_RIP, &GuestRip);

		LogWrite(LOG_INFO, L"Ept paging error at guest physical address: 0x%llx (guest rip: 0x%llx)", GuestPhysicalAddress, GuestRip);

		bResumeNextInstruction = TRUE;
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		UINT64 Identifier = pGuestContext->Rcx;
		ULONG ulMsgId = pGuestContext->Rdx;
		PVOID pContext = pGuestContext->R8;

		if (HOST_ID != Identifier)
		{
			LogWrite(LOG_INFO, L"This vmcall is not supported");
			bResumeNextInstruction = TRUE;
			break;
		}

		VmcallHandler(ulMsgId, pContext, &bVmxoff);

		bResumeNextInstruction = TRUE;
		break;
	}
	default:
	{
		LogWrite(LOG_INFO, L"Skip vmexit reason: %d", ExitReason);
		bResumeNextInstruction = TRUE;
		break;
	}
	}

	GetCurrentVmState()->bHost = FALSE;

	if (bResumeNextInstruction)
	{
		ResumeNextInstruction();
	}

	return bVmxoff;
}
