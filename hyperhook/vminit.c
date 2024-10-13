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
#include "interrupt.h"
#include "vmcall.h"
#include "hook.h"
#include "ept.h"
#include "cpuid.h"
#include "vminit.h"


/****************************************************************
					  Constant Definition
****************************************************************/
#define MEM_TAG_INIT			'tiyH'// Hyit

#define VMX_REGION_SIZE			0x1000// cpu architecture allow vmx region size at most 4096
#define VMX_MSR_BITMAP_SIZE		0x1000
#define HOST_STACK_SIZE			0x8000

#define MSR_FS_BASE				0xC0000100
#define MSR_GS_BASE				0xC0000101

#define CPU_BASED_CTR2_BASIC	CPU_BASED_CTL2_RDTSCP | \
								CPU_BASED_CTL2_ENABLE_EPT | \
								CPU_BASED_CTL2_ENABLE_INVPCID | \
								CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | \
								CPU_BASED_CTL2_ENABLE_VPID


/****************************************************************
						Type Definition
****************************************************************/
typedef enum _MSR_TYPE
{
	MSR_READ,
	MSR_WRITE,
	MSR_ALL
} MSR_TYPE;


#pragma pack(push, 1)
typedef union _IA32_VMX_BASIC_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 RevisionIdentifier : 31;		// [30:0]
		UINT64 Reserved1 : 1;				// [31]
		UINT64 RegionSize : 13;				// [32-44] 0 < RegionSize <= 4096
		UINT64 Reserved2 : 3;				// [45-47]
		UINT64 SupportedIA64 : 1;			// [48]
		UINT64 SupportedDualMoniter : 1;	// [49]
		UINT64 MemoryType : 4;				// [50-53]
		UINT64 VmExitReport : 1;			// [54]
		UINT64 VmxCapabilityHint : 1;		// [55]
		UINT64 Reserved3 : 8;				// [56-63]
	} Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;


typedef union _IA32_FEATURE_CONTROL_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 Lock : 1;					// [0]
		UINT64 EnableVmxInSMX : 1;			// [1]
		UINT64 EnableVmxOutSMX : 1;			// [2]
		UINT64 Reserved1 : 5;				// [7:3]
		UINT64 EnableLocalSENTER : 7;		// [14:8]
		UINT64 EnableGlobalSENTER : 1;		// [15]
		UINT64 Reserved2 : 1;				// [16]
		UINT64 EnableLocalSGX : 1;			// [17]
		UINT64 EnableGlobalSGX : 1;			// [18]
		UINT64 Reserved3 : 1;				// [19]
		UINT64 LMCEOn : 1;					// [20]
		UINT64 Reserved4 : 32;				// [63:21]
	} Fields;
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;


typedef union _ACCESS_RIGHT {
	UINT32 Value;
	struct
	{
		UINT32 Type : 4;			// [3:0]
		UINT32 S : 1;				// [4]
		UINT32 DPL : 2;				// [6:5]
		UINT32 P : 1;				// [7]
		UINT32 Reserved1 : 4;		// [11:8]
		UINT32 AVL : 1;				// [12]
		UINT32 L : 1;				// [13]
		UINT32 DB : 1;				// [14]
		UINT32 G : 1;				// [15]
		UINT32 U : 1;				// [16] segment selector is NULL <=> Flag on
		UINT32 Reserved2 : 15;		// [31:17]
	} Fields;
} ACCESS_RIGHT, *PACCESS_RIGHT;


typedef struct _SEGMENT_INFO
{
	UINT64 Base;
	UINT32 Limit;
	ACCESS_RIGHT AccessRight;
} SEGMENT_INFO, *PSEGMENT_INFO;


typedef struct _SEGMENT_DESCRIPTOR
{
	UINT64 Limit15_0 : 16;		// [15:0]
	UINT64 Base15_0 : 16;		// [31:16]
	UINT64 Base23_16 : 8;		// [39:32]
	UINT64 Type : 4;			// [43:40]              
	UINT64 S : 1;				// [44]                
	UINT64 DPL : 2;				// [46:45]               
	UINT64 P : 1;				// [47]                
	UINT64 Limit19_16 : 4;		// [51:48]
	UINT64 AVL : 1;				// [52]               
	UINT64 L : 1;				// [53]                 
	UINT64 DB : 1;				// [54]                
	UINT64 G : 1;				// [55]                 
	UINT64 Base31_24 : 8;		// [63:56]
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;


typedef struct _REG_CONTEXT
{
	UINT16 Cs;
	UINT16 Ds;
	UINT16 Es;
	UINT16 Fs;
	UINT16 Gs;
	UINT16 Ss;
	UINT16 Tr;
	UINT16 Ldtr;
	UINT16 GdtLimit;
	UINT64 GdtBase;
	UINT16 IdtLimit;
	UINT64 IdtBase;
} REG_CONTEXT, *PREG_CONTEXT;
#pragma pack(pop)


/****************************************************************
						Global Variable
****************************************************************/
extern VOID GuestEntryPoint();
extern VOID HostEntryPoint();
extern VOID GetContext(IN PREG_CONTEXT pContext);
extern VOID SetGdtr(IN PVOID GdtBase, IN SHORT GdtLimit);
extern VOID SetIdtr(IN PVOID IdtBase, IN SHORT IdtLimit);
extern ULONG_PTR VirtualizeProcessor(IN OPTIONAL ULONG_PTR pContext);
extern VOID HostSendMessageInternal(IN UINT64 Identifier, IN ULONG ulMsgId, IN PVOID pContext);
extern UINT64 g_Eptp;

static VIRTUAL_MACHINE_STATE* st_pVmState;
static UINT64 st_SystemCr3;
ULONG g_VmxStatus = VMX_STOP_ALL;


/****************************************************************
					   Function Definition
****************************************************************/
PVIRTUAL_MACHINE_STATE GetCurrentVmState()
{
	ULONG uCurrentProcessorId;

	if (NULL == st_pVmState)
	{
		return NULL;
	}

	uCurrentProcessorId = KeGetCurrentProcessorNumberEx(NULL);
	return &st_pVmState[uCurrentProcessorId];
}


PVOID AllocateContiguousMemory(IN UINT64 NumberOfBytes)
{
	PHYSICAL_ADDRESS PhysicalMax;
	PhysicalMax.QuadPart = MAXULONG64;
	return MmAllocateContiguousMemory(NumberOfBytes, PhysicalMax);
}


VOID FreeContiguousMemory(IN PVOID pVirtualAddr)
{
	if (pVirtualAddr)
	{
		MmFreeContiguousMemory(pVirtualAddr);
	}
}


UINT64 GetPhysicalAddress(IN PVOID pVirtualAddr)
{
	if (NULL == pVirtualAddr)
	{
		return 0;
	}

	return MmGetPhysicalAddress(pVirtualAddr).QuadPart;
}


VOID HostSendMessage(IN ULONG ulMsgId, IN OPTIONAL PVOID pContext)
{
	HostSendMessageInternal(HOST_ID, ulMsgId, pContext);
}


static
BOOLEAN AllocVmxRegion(OUT PVIRTUAL_MACHINE_STATE pVmState)
{
	PHYSICAL_ADDRESS PhysicalMax;
	PhysicalMax.QuadPart = MAXULONG64;
	IA32_VMX_BASIC_MSR VMXBasicMsr;// Set Revision Identifier
	PVOID AlignedVmxonRegionVirtualAddr, AlignedVmcsRegionVirtualAddr, AlignedMsrBitmapVirtualAddr;

	if (NULL == pVmState)
	{
		return FALSE;
	}

	AlignedVmxonRegionVirtualAddr = AllocateContiguousMemory(VMX_REGION_SIZE);
	AlignedVmcsRegionVirtualAddr = AllocateContiguousMemory(VMX_REGION_SIZE);
	AlignedMsrBitmapVirtualAddr = AllocateContiguousMemory(VMX_MSR_BITMAP_SIZE);

	if (NULL == AlignedVmxonRegionVirtualAddr || NULL == AlignedVmcsRegionVirtualAddr || NULL == AlignedMsrBitmapVirtualAddr)
	{
		goto CleanUp;
	}

	RtlZeroMemory(AlignedVmxonRegionVirtualAddr, VMX_REGION_SIZE);
	RtlZeroMemory(AlignedVmcsRegionVirtualAddr, VMX_REGION_SIZE);
	RtlZeroMemory(AlignedMsrBitmapVirtualAddr, VMX_MSR_BITMAP_SIZE);

	VMXBasicMsr.Value = __readmsr(MSR_IA32_VMX_BASIC);

	*(PUINT64)AlignedVmxonRegionVirtualAddr = VMXBasicMsr.Fields.RevisionIdentifier;
	*(PUINT64)AlignedVmcsRegionVirtualAddr = VMXBasicMsr.Fields.RevisionIdentifier;

	pVmState->VmxonRegionVirtualAddress = AlignedVmxonRegionVirtualAddr;
	pVmState->VmcsRegionVirtualAddress = AlignedVmcsRegionVirtualAddr;
	pVmState->MsrBitmapVirtualAddress = AlignedMsrBitmapVirtualAddr;

	return TRUE;

CleanUp:
	if (AlignedVmxonRegionVirtualAddr)
	{
		FreeContiguousMemory(AlignedVmxonRegionVirtualAddr);
	}
	if (AlignedVmcsRegionVirtualAddr)
	{
		FreeContiguousMemory(AlignedVmcsRegionVirtualAddr);
	}
	if (AlignedMsrBitmapVirtualAddr)
	{
		FreeContiguousMemory(AlignedMsrBitmapVirtualAddr);
	}

	pVmState->VmxonRegionVirtualAddress = NULL;
	pVmState->VmcsRegionVirtualAddress = NULL;
	pVmState->MsrBitmapVirtualAddress = NULL;

	return FALSE;
}


static
VOID FreeVmxRegion(IN OUT PVIRTUAL_MACHINE_STATE pVmState)
{
	if (pVmState)
	{
		FreeContiguousMemory(pVmState->VmxonRegionVirtualAddress);
		FreeContiguousMemory(pVmState->VmcsRegionVirtualAddress);
		FreeContiguousMemory(pVmState->MsrBitmapVirtualAddress);

		pVmState->VmxonRegionVirtualAddress = NULL;
		pVmState->VmcsRegionVirtualAddress = NULL;
		pVmState->MsrBitmapVirtualAddress = NULL;
	}
}


/* There is no DisableVmx */
static
BOOLEAN EnableVmx()
{
	CPUID CpuInfo;
	IA32_FEATURE_CONTROL_MSR FeatureControl;

	__cpuid((int*)&CpuInfo, 1);
	if (FALSE == (CpuInfo.ecx & 0x20))// 5th bit indicates whether VMX is supported 
	{
		LogWrite(LOG_ERROR, L"Cpu does not support VMX");
		return FALSE;
	}

	FeatureControl.Value = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (1 == FeatureControl.Fields.Lock)
	{
		if (0 == FeatureControl.Fields.EnableVmxOutSMX)
		{
			// Once set Lock bit, MSR can't be written
			LogWrite(LOG_ERROR, L"VMX is locked in OS or BIOS");
			return FALSE;
		}
	}
	else
	{
		FeatureControl.Fields.Lock = 1;
		FeatureControl.Fields.EnableVmxOutSMX = 1;
		__writemsr(MSR_IA32_FEATURE_CONTROL, FeatureControl.Value);
	}

	return TRUE;
}


static
BOOLEAN AllocHostStack(OUT PVIRTUAL_MACHINE_STATE pVmState)
{
	if (NULL == pVmState)
	{
		return FALSE;
	}

	pVmState->HostStack = ExAllocatePoolWithTag(NonPagedPool, HOST_STACK_SIZE, MEM_TAG_INIT);
	if (NULL == pVmState->HostStack)
	{
		return FALSE;
	}

	RtlZeroMemory(pVmState->HostStack, HOST_STACK_SIZE);

	return TRUE;
}


static
VOID FreeHostStack(IN OUT PVIRTUAL_MACHINE_STATE pVmState)
{
	if (NULL == pVmState)
	{
		return;
	}

	if (NULL != pVmState->HostStack)
	{
		ExFreePool(pVmState->HostStack);
	}

	pVmState->HostStack = NULL;
}


static
ULONG_PTR DevirtualizeProcessor(IN OPTIONAL ULONG_PTR pContext)
{
	if (GetCurrentVmState()->bLaunched)
	{
		HostSendMessage(HOST_MSG_ID_VMX_OFF, NULL);
	}
}


BOOLEAN VmxInitialize()
{
	ULONG ulNumOfProcessor;
	BOOLEAN bSuccessEpt = FALSE;

	if (FALSE == EnableVmx())
	{
		LogWrite(LOG_ERROR, L"Enable VMX fail");
		goto CleanUp;
	}

	ulNumOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	st_pVmState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * ulNumOfProcessor, MEM_TAG_INIT);
	if (NULL == st_pVmState)
	{
		LogWrite(LOG_ERROR, L"Allocate virtual machine state fail");
		goto CleanUp;
	}

	RtlZeroMemory(st_pVmState, sizeof(VIRTUAL_MACHINE_STATE) * ulNumOfProcessor);

	bSuccessEpt = InitializeEpt();
	if (FALSE == bSuccessEpt)
	{
		LogWrite(LOG_ERROR, L"Initialize EPT fail");
		goto CleanUp;
	}

	InitializeHook();

	for (ULONG i = 0; i < ulNumOfProcessor; ++i)
	{
		if (FALSE == AllocVmxRegion(&st_pVmState[i]))
		{
			LogWrite(LOG_ERROR, L"Allocate VMCS fail");
			goto CleanUp;
		}
		if (FALSE == AllocHostStack(&st_pVmState[i]))
		{
			LogWrite(LOG_ERROR, L"Allocate host stack fail");
			goto CleanUp;
		}
	}

	st_SystemCr3 = __readcr3();

	LogPause();
	KeIpiGenericCall(VirtualizeProcessor, NULL);

	/* here is guest mode */
	for (ULONG i = 0; i < ulNumOfProcessor; ++i)
	{
		if (FALSE == st_pVmState[i].bLaunched)
		{
			goto CleanUp;
		}
	}

	InterlockedExchange(&g_VmxStatus, VMX_START_ALL);
	LogRestart();

	return TRUE;

CleanUp:
	if (bSuccessEpt)
	{
		FinalizeEpt();
	}

	if (st_pVmState)
	{
		KeIpiGenericCall(DevirtualizeProcessor, NULL);

		for (ULONG i = 0; i < ulNumOfProcessor; ++i)
		{
			FreeHostStack(&st_pVmState[i]);
			FreeVmxRegion(&st_pVmState[i]);
		}

		ExFreePool(st_pVmState);

		st_pVmState = NULL;
	}
	LogRestart();

	return FALSE;
}


VOID VmxTerminate()
{
	ULONG ulNumOfProcessor;

	if (NULL == st_pVmState)
	{
		return;
	}

	ClearHook();

	ulNumOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	LogPause();
	KeIpiGenericCall(DevirtualizeProcessor, NULL);

	InterlockedExchange(&g_VmxStatus, VMX_STOP_ALL);
	LogRestart();

	for (ULONG i = 0; i < ulNumOfProcessor; ++i)
	{
		FreeHostStack(&st_pVmState[i]);
		FreeVmxRegion(&st_pVmState[i]);
	}

	ExFreePool(st_pVmState);
	FinalizeEpt();

	LogWrite(LOG_INFO, L"Terminate VMX success");
}


static
VOID SetVmxRegister(OUT PVIRTUAL_MACHINE_STATE pVmState)
{
	UINT64 cr0, cr4;

	cr0 = __readcr0();
	pVmState->VmxoffRestoreData.cr0 = cr0;// After vmxoff, cr0 and cr4 must be restored

	/*
	Bit Xth of cr0 must be set if Bit Xth of MSR_IA32_VMX_CR0_FIXED0 is 1
	(If bit Xth of MSR_IA32_VMX_CR0_FIXED0 is 1, then bit Xth of IA32_VMX_CR0_FIXED1 is 1
	*/
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);

	/*
	Bit Xth of cr0 must be clear if Bit Xth of MSR_IA32_VMX_CR0_FIXED1 is 0
	(If bit Xth of MSR_IA32_VMX_CR0_FIXED1 is 0, then bit Xth of IA32_VMX_CR0_FIXED0 is 0
	*/
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);

	__writecr0(cr0);

	cr4 = __readcr4();
	pVmState->VmxoffRestoreData.cr4 = cr4;
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	__writecr4(cr4);
}


static
VOID GetSegInfo(IN UINT64 GdtBase, IN USHORT Selector, OUT PSEGMENT_INFO pSegInfo)
{
	PSEGMENT_DESCRIPTOR pDescriptor;

	if (NULL == pSegInfo)
	{
		return;
	}

	pDescriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + (Selector & ~3));

	pSegInfo->Base = (pDescriptor->Base15_0 & 0xffff) | (pDescriptor->Base23_16 & 0xff) << 16 | (pDescriptor->Base31_24 & 0xff) << 24;
	pSegInfo->Limit = (pDescriptor->Limit15_0 & 0xffff) | (pDescriptor->Limit19_16 & 0xf) << 16;

	pSegInfo->AccessRight.Fields.Type = pDescriptor->Type;
	pSegInfo->AccessRight.Fields.S = pDescriptor->S;
	pSegInfo->AccessRight.Fields.DPL = pDescriptor->DPL;
	pSegInfo->AccessRight.Fields.P = pDescriptor->P;
	pSegInfo->AccessRight.Fields.Reserved1 = 0;
	pSegInfo->AccessRight.Fields.AVL = pDescriptor->AVL;
	pSegInfo->AccessRight.Fields.L = pDescriptor->L;
	pSegInfo->AccessRight.Fields.DB = pDescriptor->DB;
	pSegInfo->AccessRight.Fields.G = pDescriptor->G;
	pSegInfo->AccessRight.Fields.U = 0;
	pSegInfo->AccessRight.Fields.Reserved2 = 0;

	if (NULL == Selector)
	{
		pSegInfo->AccessRight.Fields.U = 1;
	}

	if (0 == pDescriptor->S)// system segment
	{
		UINT64 Base63_32 = *(PUINT64)((PUCHAR)pDescriptor + 8);
		pSegInfo->Base |= (Base63_32 << 32);
	}
}


static
VOID SetGuestSelector(IN PREG_CONTEXT pContext)
{
	if (NULL == pContext)
	{
		return;
	}

	__vmx_vmwrite(GUEST_CS_SELECTOR, pContext->Cs);
	__vmx_vmwrite(GUEST_DS_SELECTOR, pContext->Ds);
	__vmx_vmwrite(GUEST_ES_SELECTOR, pContext->Es);
	__vmx_vmwrite(GUEST_FS_SELECTOR, pContext->Fs);
	__vmx_vmwrite(GUEST_GS_SELECTOR, pContext->Gs);
	__vmx_vmwrite(GUEST_SS_SELECTOR, pContext->Ss);
	__vmx_vmwrite(GUEST_TR_SELECTOR, pContext->Tr);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, pContext->Ldtr);
}


static
VOID SetHostSelector(IN PREG_CONTEXT pContext)
{
	if (NULL == pContext)
	{
		return;
	}

	__vmx_vmwrite(HOST_CS_SELECTOR, pContext->Cs & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, pContext->Ds & 0xF8);
	__vmx_vmwrite(HOST_ES_SELECTOR, pContext->Es & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, pContext->Fs & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, pContext->Gs & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, pContext->Ss & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, pContext->Tr & 0xF8);
}


static
VOID SetHostBase(IN PREG_CONTEXT pContext)
{
	SEGMENT_INFO SegTrInfo;

	if (NULL == pContext)
	{
		return;
	}

	GetSegInfo(pContext->GdtBase, pContext->Tr, &SegTrInfo);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	__vmx_vmwrite(HOST_TR_BASE, SegTrInfo.Base);
	__vmx_vmwrite(HOST_GDTR_BASE, pContext->GdtBase);
	__vmx_vmwrite(HOST_IDTR_BASE, pContext->IdtBase);
}


static
VOID SetGuestSegment(IN PREG_CONTEXT pContext)
{
	SEGMENT_INFO SegEsInfo, SegCsInfo, SegSsInfo, SegDsInfo, SegFsInfo, SegGsInfo, SegLdtrInfo, SegTrInfo;

	if (NULL == pContext)
	{
		return;
	}

	GetSegInfo(pContext->GdtBase, pContext->Cs, &SegCsInfo);
	GetSegInfo(pContext->GdtBase, pContext->Ds, &SegDsInfo);
	GetSegInfo(pContext->GdtBase, pContext->Es, &SegEsInfo);
	GetSegInfo(pContext->GdtBase, pContext->Fs, &SegFsInfo);
	GetSegInfo(pContext->GdtBase, pContext->Gs, &SegGsInfo);
	GetSegInfo(pContext->GdtBase, pContext->Ss, &SegSsInfo);

	GetSegInfo(pContext->GdtBase, pContext->Tr, &SegTrInfo);
	GetSegInfo(pContext->GdtBase, pContext->Ldtr, &SegLdtrInfo);

	__vmx_vmwrite(GUEST_CS_LIMIT, SegCsInfo.Limit);
	__vmx_vmwrite(GUEST_CS_ACCESS_RIGHT, SegCsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_CS_BASE, SegCsInfo.Base);

	__vmx_vmwrite(GUEST_DS_LIMIT, SegDsInfo.Limit);
	__vmx_vmwrite(GUEST_DS_ACCESS_RIGHT, SegDsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_DS_BASE, SegDsInfo.Base);

	__vmx_vmwrite(GUEST_ES_LIMIT, SegEsInfo.Limit);
	__vmx_vmwrite(GUEST_ES_ACCESS_RIGHT, SegEsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_ES_BASE, SegEsInfo.Base);

	__vmx_vmwrite(GUEST_FS_LIMIT, SegFsInfo.Limit);
	__vmx_vmwrite(GUEST_FS_ACCESS_RIGHT, SegFsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));

	__vmx_vmwrite(GUEST_GS_LIMIT, SegGsInfo.Limit);
	__vmx_vmwrite(GUEST_GS_ACCESS_RIGHT, SegGsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_SS_LIMIT, SegSsInfo.Limit);
	__vmx_vmwrite(GUEST_SS_ACCESS_RIGHT, SegSsInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_SS_BASE, SegSsInfo.Base);

	__vmx_vmwrite(GUEST_TR_LIMIT, SegTrInfo.Limit);
	__vmx_vmwrite(GUEST_TR_ACCESS_RIGHT, SegTrInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_TR_BASE, SegTrInfo.Base);

	__vmx_vmwrite(GUEST_LDTR_LIMIT, SegLdtrInfo.Limit);
	__vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHT, SegLdtrInfo.AccessRight.Value);
	__vmx_vmwrite(GUEST_LDTR_BASE, SegLdtrInfo.Base);

	__vmx_vmwrite(GUEST_GDTR_LIMIT, pContext->GdtLimit);
	__vmx_vmwrite(GUEST_GDTR_BASE, pContext->GdtBase);

	__vmx_vmwrite(GUEST_IDTR_LIMIT, pContext->IdtLimit);
	__vmx_vmwrite(GUEST_IDTR_BASE, pContext->IdtBase);
}


static
BOOLEAN SetPinControl(IN UINT32 ulControl)
{
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	UINT32 ControlMsr;
	LARGE_INTEGER MsrValue;

	VmxBasicMsr.Value = __readmsr(MSR_IA32_VMX_BASIC);
	if (VmxBasicMsr.Fields.VmxCapabilityHint)
	{
		ControlMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
	}
	else
	{
		ControlMsr = MSR_IA32_VMX_PINBASED_CTLS;
	}

	/*
	MSR_IA32_VMX_TRUE_PINBASED_CTLS or MSR_IA32_VMX_PINBASED_CTLS indicates
	which bits of PIN_BASED_VM_EXEC_CONTROL must be set or clear
	*/
	MsrValue.QuadPart = __readmsr(ControlMsr);
	ulControl &= MsrValue.HighPart;/* If bit Xth of HighPart is 0, bit Xth of ulControl must be 0 */
	if ((MsrValue.HighPart & ulControl) != ulControl)
	{
		return FALSE;
	}

	ulControl |= MsrValue.LowPart;// If bit Xth of LowPart is 1, bit Xth of ulControl must be 1
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, ulControl);

	return TRUE;
}


/* To use SetSecondaryProcessorControl, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS must be set */
static
BOOLEAN SetPrimaryProcessorControl(IN UINT32 ulControl)
{
	IA32_VMX_BASIC_MSR VmxBasicMsr;
	UINT32 ControlMsr;
	LARGE_INTEGER MsrValue;

	VmxBasicMsr.Value = __readmsr(MSR_IA32_VMX_BASIC);
	if (VmxBasicMsr.Fields.VmxCapabilityHint)
	{
		ControlMsr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
	}
	else
	{
		ControlMsr = MSR_IA32_VMX_PROCBASED_CTLS;
	}

	MsrValue.QuadPart = __readmsr(ControlMsr);
	ulControl &= MsrValue.HighPart;
	if ((MsrValue.HighPart & ulControl) != ulControl)
	{
		return FALSE;
	}

	ulControl |= MsrValue.LowPart;
	__vmx_vmwrite(PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL, ulControl);

	return TRUE;
}


static
BOOLEAN SetSecondaryProcessorControl(IN UINT32 ulControl)
{
	LARGE_INTEGER MsrValue;

	MsrValue.QuadPart = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	ulControl &= MsrValue.HighPart;// If bit Xth of HighPart is 0, bit Xth of ulControl must be 0
	if ((MsrValue.HighPart & ulControl) != ulControl)
	{
		return FALSE;
	}

	// LowPart of MSR_IA32_VMX_PROCBASED_CTLS2 always zero
	__vmx_vmwrite(SECONDARY_PROCESSOR_BASED_VM_EXEC_CONTROL, ulControl);

	return TRUE;
}


static
BOOLEAN SetExitControl(IN UINT32 ulControl)
{
	IA32_VMX_BASIC_MSR VmxBasicMsr;
	UINT32 ControlMsr;
	LARGE_INTEGER MsrValue;

	VmxBasicMsr.Value = __readmsr(MSR_IA32_VMX_BASIC);
	if (VmxBasicMsr.Fields.VmxCapabilityHint)
	{
		ControlMsr = MSR_IA32_VMX_TRUE_EXIT_CTLS;
	}
	else
	{
		ControlMsr = MSR_IA32_VMX_EXIT_CTLS;
	}

	MsrValue.QuadPart = __readmsr(ControlMsr);
	ulControl &= MsrValue.HighPart;// If bit Xth of HighPart is 0, bit Xth of ulControl must be 0
	if ((MsrValue.HighPart & ulControl) != ulControl)
	{
		return FALSE;
	}

	ulControl |= MsrValue.LowPart;// If bit Xth of LowPart is 1, bit Xth of ulControl must be 1
	__vmx_vmwrite(PRIMARY_VM_EXIT_CONTROLS, ulControl);

	return TRUE;
}


static
BOOLEAN SetEntryControl(IN UINT32 ulControl)
{
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	UINT32 ControlMsr;
	LARGE_INTEGER MsrValue;

	VmxBasicMsr.Value = __readmsr(MSR_IA32_VMX_BASIC);
	if (VmxBasicMsr.Fields.VmxCapabilityHint)
	{
		ControlMsr = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
	}
	else
	{
		ControlMsr = MSR_IA32_VMX_ENTRY_CTLS;
	}

	MsrValue.QuadPart = __readmsr(ControlMsr);
	ulControl &= MsrValue.HighPart;// If bit Xth of HighPart is 0, bit Xth of ulControl must be 0
	if ((MsrValue.HighPart & ulControl) != ulControl)
	{
		return FALSE;
	}

	ulControl |= MsrValue.LowPart;// If bit Xth of LowPart is 1, bit Xth of ulControl must be 1
	__vmx_vmwrite(VM_ENTRY_CONTROLS, ulControl);

	return TRUE;
}


static
BOOLEAN SetMsrBitmap(IN PVOID pMsrBitmap, IN UINT64 Msr, IN MSR_TYPE MsrType)
{
	PUCHAR pMsrReadBitmap, pMsrWriteBitmap;

	if (NULL == pMsrBitmap)
	{
		return FALSE;
	}

	if (Msr < 0x2000)
	{
		pMsrReadBitmap = (PUCHAR)pMsrBitmap;
		pMsrWriteBitmap = (PUCHAR)pMsrBitmap + 2048;
		switch (MsrType)
		{
		case MSR_READ:
			pMsrReadBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		case MSR_WRITE:
			pMsrWriteBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		case MSR_ALL:
			pMsrReadBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			pMsrWriteBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		default:
			return FALSE;
		}
	}
	else if (0xC0000000 <= Msr && Msr < 0xC0002000)
	{
		pMsrReadBitmap = (PUCHAR)pMsrBitmap + 1024;
		pMsrWriteBitmap = (PUCHAR)pMsrBitmap + 3072;
		Msr = Msr - 0xC0000000;
		switch (MsrType)
		{
		case MSR_READ:
			pMsrReadBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		case MSR_WRITE:
			pMsrWriteBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		case MSR_ALL:
			pMsrReadBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			pMsrWriteBitmap[(Msr / 8)] |= 1 << (Msr % 8);
			break;
		default:
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}


static
BOOLEAN ClearMsrBitmap(IN PVOID pMsrBitmap, IN UINT64 Msr, IN MSR_TYPE MsrType)
{
	PUCHAR pMsrReadBitmap, pMsrWriteBitmap;

	if (NULL == pMsrBitmap)
	{
		return FALSE;
	}

	if (Msr < 0x2000)
	{
		pMsrReadBitmap = (PUCHAR)pMsrBitmap;
		pMsrWriteBitmap = (PUCHAR)pMsrBitmap + 2048;
		switch (MsrType)
		{
		case MSR_READ:
			pMsrReadBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		case MSR_WRITE:
			pMsrWriteBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		case MSR_ALL:
			pMsrReadBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			pMsrWriteBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		default:
			return FALSE;
		}
	}
	else if (0xC0000000 <= Msr && Msr < 0xC0002000)
	{
		pMsrReadBitmap = (PUCHAR)pMsrBitmap + 1024;
		pMsrWriteBitmap = (PUCHAR)pMsrBitmap + 3072;
		Msr = Msr - 0xC0000000;
		switch (MsrType)
		{
		case MSR_READ:
			pMsrReadBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		case MSR_WRITE:
			pMsrWriteBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		case MSR_ALL:
			pMsrReadBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			pMsrWriteBitmap[(Msr / 8)] &= ~(1 << (Msr % 8));
			break;
		default:
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}


static
BOOLEAN SetBasicVmcs(OUT PVIRTUAL_MACHINE_STATE pVirtualMachineState, IN PVOID pGuestStack, IN UINT64 GuestRflags)
{
	UINT32 CpuBasedVmExecControls, SecondaryProcBasedVmExecControls;
	UINT64 GdtBase = 0;
	BOOLEAN bResult;
	REG_CONTEXT Context;

	if (NULL == pVirtualMachineState || NULL == pGuestStack || 0 == st_SystemCr3 || 0 == g_Eptp)
	{
		return FALSE;
	}

	GetContext(&Context);

	SetGuestSegment(&Context);
	SetGuestSelector(&Context);
	SetHostSelector(&Context);
	SetHostBase(&Context);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_CR3, st_SystemCr3);

	__vmx_vmwrite(GUEST_RSP, (UINT64)pGuestStack);
	__vmx_vmwrite(GUEST_RIP, (UINT64)GuestEntryPoint);

	__vmx_vmwrite(HOST_RSP, pVirtualMachineState->HostStack + HOST_STACK_SIZE - 8);
	__vmx_vmwrite(HOST_RIP, (UINT64)HostEntryPoint);

	__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, GUEST_VPID);
	__vmx_vmwrite(GUEST_RFLAGS, GuestRflags);
	__vmx_vmwrite(GUEST_DR7, __readdr(7));

	__vmx_vmwrite(EXCEPTION_BITMAP, MAKE_BITMAP(BREAKPOINT_EXCEPTION));

	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);// Not support nested virtualization

	if (FALSE == SetPinControl(0))
	{
		LogWrite(LOG_ERROR, L"SetPinControl fail");
		return FALSE;
	}

	if (FALSE == SetExitControl(VM_EXIT_IA32E_MODE))
	{
		LogWrite(LOG_ERROR, L"SetExitControl fail");
		return FALSE;
	}

	if (FALSE == SetEntryControl(VM_ENTRY_IA32E_MODE))
	{
		LogWrite(LOG_ERROR, L"SetEntryControl fail");
		return FALSE;
	}

	if (SetPrimaryProcessorControl(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS))
	{
		__vmx_vmwrite(ADDR_OF_MSR_BITMAP, GetPhysicalAddress(pVirtualMachineState->MsrBitmapVirtualAddress));
	}
	else
	{
		LogWrite(LOG_ERROR, L"SetPrimaryProcessorControl fail");
		return FALSE;
	}

	if (SetSecondaryProcessorControl(CPU_BASED_CTR2_BASIC))
	{
		__vmx_vmwrite(EPT_POINTER, g_Eptp);
	}
	else
	{
		LogWrite(LOG_ERROR, L"SetSecondaryProcessorControl fail");
		return FALSE;
	}

	return TRUE;
}


VOID VirtualizeProcessorInternal(IN PVOID pGuestStack, IN UINT64 GuestRflags)
{
	PVIRTUAL_MACHINE_STATE pVmState;
	UINT64 ulStatus, VmxonRegionPhysicalAddress, VmcsRegionPhysicalAddress;

	if (NULL == pGuestStack)
	{
		return;
	}

	pVmState = GetCurrentVmState();
	if (NULL == pVmState)
	{
		return;
	}

	VmxonRegionPhysicalAddress = GetPhysicalAddress(pVmState->VmxonRegionVirtualAddress);
	VmcsRegionPhysicalAddress = GetPhysicalAddress(pVmState->VmcsRegionVirtualAddress);
	if (NULL == VmxonRegionPhysicalAddress || NULL == VmcsRegionPhysicalAddress)
	{
		return;
	}

	SetVmxRegister(pVmState);
	ulStatus = __vmx_on(&VmxonRegionPhysicalAddress);
	if (0 != ulStatus)
	{
		LogWrite(LOG_ERROR, L"Vmxon fail: %d", ulStatus);
		return;
	}

	ulStatus = __vmx_vmclear(&VmcsRegionPhysicalAddress);
	if (0 != ulStatus)
	{
		LogWrite(LOG_ERROR, L"Vmclear fail: %d, start vmxoff...", ulStatus);
		__vmx_off();
		return;
	}

	ulStatus = __vmx_vmptrld(&VmcsRegionPhysicalAddress);
	if (0 != ulStatus)
	{
		LogWrite(LOG_ERROR, L"Vmptrld fail: %d, start vmxoff...", ulStatus);
		__vmx_off();
		return;
	}

	if (FALSE == SetBasicVmcs(pVmState, pGuestStack, GuestRflags))
	{
		LogWrite(LOG_ERROR, L"Set VMCS fail, start vmxoff...");
		__vmx_off();
		return;
	}

	pVmState->bLaunched = TRUE;

	ulStatus = __vmx_vmlaunch();// enter guest

	/* If vmlaunch success, this code cannot be executed */
	pVmState->bLaunched = FALSE;

	if (1 == ulStatus)
	{
		UINT64 ErrorCode;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
		LogWrite(LOG_ERROR, L"Vmlaunch fail: %d, start vmxoff...", ErrorCode);
	}
	else
	{
		LogWrite(LOG_ERROR, L"Vmlaunch fail, start vmxoff...");
	}

	__vmx_off();
}


static
VOID RestoreVmxRegister(IN PVIRTUAL_MACHINE_STATE pVmState)
{
	UINT64 cr0, cr4;

	if (NULL == pVmState)
	{
		return;
	}

	cr0 = pVmState->VmxoffRestoreData.cr0;
	__writecr0(cr0);

	cr4 = pVmState->VmxoffRestoreData.cr4;
	__writecr4(cr4);
}


VOID SetVmxOff(OUT PUINT64 pGuestRsp, OUT PUINT64 pGuestRip)
{
	PVIRTUAL_MACHINE_STATE pVmState;
	UINT64 FsBase, GsBase, GuestCr3;
	PVOID GdtrBase, IdtrBase;
	UINT64 GdtrLimit, IdtrLimit;

	if (NULL == pGuestRsp || NULL == pGuestRip)
	{
		return;
	}

	__vmx_vmread(GUEST_CR3, &GuestCr3);
	__writecr3(GuestCr3);

	__vmx_vmread(GUEST_RSP, pGuestRsp);
	__vmx_vmread(GUEST_RIP, pGuestRip);

	__vmx_vmread(GUEST_FS_BASE, &FsBase);
	__writemsr(MSR_FS_BASE, FsBase);

	__vmx_vmread(GUEST_GS_BASE, &GsBase);
	__writemsr(MSR_GS_BASE, GsBase);

	__vmx_vmread(GUEST_GDTR_BASE, &GdtrBase);
	__vmx_vmread(GUEST_GDTR_LIMIT, &GdtrLimit);
	SetGdtr(GdtrBase, GdtrLimit);

	__vmx_vmread(GUEST_IDTR_BASE, &IdtrBase);
	__vmx_vmread(GUEST_IDTR_LIMIT, &IdtrLimit);
	SetIdtr(IdtrBase, IdtrLimit);

	__vmx_off();

	pVmState = GetCurrentVmState();
	RestoreVmxRegister(pVmState);

	pVmState->bLaunched = FALSE;
}


VOID LoggingResumeError()
{
	UINT64 ErrorCode, ExitCode;
	UCHAR ErrorStatus, ExitStatus;

	ErrorStatus = __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	ExitStatus = __vmx_vmread(EXIT_REASON, &ExitCode);
	if (2 == ErrorStatus)
	{
		if (0 != ExitStatus)
		{
			LogWrite(LOG_ERROR, L"Vmresume fail, start vmxoff...");
		}
		else
		{
			LogWrite(LOG_ERROR, L"Vmresume fail with exit reason: %d, start vmxoff...", ExitCode);
		}
	}
	else
	{
		if (0 != ExitStatus)
		{
			LogWrite(LOG_ERROR, L"Vmresume fail: %d, start vmxoff...", ErrorCode);
		}
		else
		{
			LogWrite(LOG_ERROR, L"Vmresume fail: %d(exit reason: %d), start vmxoff...", ErrorCode, ExitCode);
		}
	}
}
