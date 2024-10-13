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

#include "vminit.h"
#include "mtrr.h"
#include "vmcall.h"
#include "ept.h"


/****************************************************************
					  Constant Definition
****************************************************************/
#define MEM_TAG_PAGE	'gpyH'// Hypg

#define LARGE_PAGE_SIZE	((SIZE_T)(512 * PAGE_SIZE))

// Memory Types
#define MEMORY_TYPE_UNCACHEABLE			0x00000000
#define MEMORY_TYPE_WRITE_COMBINING		0x00000001
#define MEMORY_TYPE_WRITE_THROUGH		0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED		0x00000005
#define MEMORY_TYPE_WRITE_BACK			0x00000006
#define MEMORY_TYPE_INVALID				0x000000FF


/****************************************************************
						Type Definition
****************************************************************/
typedef struct _EPT_STATE
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPTP Eptp;
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[1];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPE_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE_2MB Pd[EPT_PDPE_COUNT][EPT_PDE_COUNT];
} EPT_STATE, *PEPT_STATE;


typedef struct _EPT_PAGE_TABLE_DATA
{
	PVOID pAlignedVirtualEptPageTable;
	UINT64 AlignedPhysicalEptPageTable;
} EPT_PAGE_TABLE_DATA, *PEPT_PAGE_TABLE_DATA;


typedef enum _INVEPT_TYPE
{
	INVEPT_SINGLE_CONTEXT = 0x00000001,
	INVEPT_ALL_CONTEXT = 0x00000002,
} INVEPT_TYPE;


typedef struct _INVEPT_DESCRIPTOR
{
	UINT64 Eptp;
	UINT64 Reserved;
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;


/****************************************************************
						Global Variable
****************************************************************/
extern VOID InvalidateEpt(IN UINT64 Type, IN PVOID pDescriptor);

static EPT_STATE st_EptState;
static RTL_AVL_TABLE st_StaticEptPageTableTree;
static RTL_AVL_TABLE st_DynamicEptPageTableTree;
UINT64 g_Eptp;


/****************************************************************
					   Function Definition
****************************************************************/
/* flush current core cache */
VOID InvalidateAddress(IN OPTIONAL UINT64 Eptp)
{
	INVEPT_DESCRIPTOR Descriptor = { 0, };

	if (Eptp)
	{
		Descriptor.Eptp = Eptp;
		InvalidateEpt(INVEPT_SINGLE_CONTEXT, &Descriptor);
	}
	else
	{
		InvalidateEpt(INVEPT_ALL_CONTEXT, &Descriptor);
	}
}


static
RTL_GENERIC_COMPARE_RESULTS
EptPageTableCompare(
	IN	struct _RTL_AVL_TABLE  *Table,
	IN	PVOID  FirstStruct,
	IN	PVOID  SecondStruct
)
{
	PEPT_PAGE_TABLE_DATA pFirst = (PEPT_PAGE_TABLE_DATA)FirstStruct;
	PEPT_PAGE_TABLE_DATA pSecond = (PEPT_PAGE_TABLE_DATA)SecondStruct;

	if (pFirst->AlignedPhysicalEptPageTable < pSecond->AlignedPhysicalEptPageTable)
	{
		return GenericLessThan;
	}
	if (pFirst->AlignedPhysicalEptPageTable > pSecond->AlignedPhysicalEptPageTable)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}


static
PVOID AllocateMemoryInTree(IN struct _RTL_AVL_TABLE* Table, IN CLONG ByteSize)
{
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, MEM_TAG_PAGE);
}


static
VOID FreeMemoryInTree(IN struct _RTL_AVL_TABLE* Table, IN PVOID Buffer)
{
	ExFreePool(Buffer);
}


static
PEPT_PAGE_TABLE_DATA AcquireStaticEptPageTable()
{
	PVOID pAlignedPageTable;
	PEPT_PAGE_TABLE_DATA pEptPageTableData;
	EPT_PAGE_TABLE_DATA EptPageTableData;

	pAlignedPageTable = AllocateContiguousMemory(EPT_PTE_COUNT * sizeof(EPT_PTE));
	if (NULL == pAlignedPageTable)
	{
		return NULL;
	}

	EptPageTableData.pAlignedVirtualEptPageTable = pAlignedPageTable;
	EptPageTableData.AlignedPhysicalEptPageTable = GetPhysicalAddress(pAlignedPageTable);

	pEptPageTableData = (PEPT_PAGE_TABLE_DATA)RtlInsertElementGenericTableAvl(&st_StaticEptPageTableTree, &EptPageTableData, sizeof(EPT_PAGE_TABLE_DATA), NULL);
	if (NULL == pEptPageTableData)
	{
		FreeContiguousMemory(pAlignedPageTable);
		return NULL;
	}

	return pEptPageTableData;
}


static
PEPT_PAGE_TABLE_DATA AllocateDynamicEptPageTable()
{
	PVOID pAlignedPageTable;
	PEPT_PAGE_TABLE_DATA pEptPageTableData;
	EPT_PAGE_TABLE_DATA EptPageTableData;

	pAlignedPageTable = AllocateContiguousMemory(EPT_PTE_COUNT * sizeof(EPT_PTE));
	if (NULL == pAlignedPageTable)
	{
		return NULL;
	}

	EptPageTableData.pAlignedVirtualEptPageTable = pAlignedPageTable;
	EptPageTableData.AlignedPhysicalEptPageTable = GetPhysicalAddress(pAlignedPageTable);

	pEptPageTableData = (PEPT_PAGE_TABLE_DATA)RtlInsertElementGenericTableAvl(&st_DynamicEptPageTableTree, &EptPageTableData, sizeof(EPT_PAGE_TABLE_DATA), NULL);
	if (NULL == pEptPageTableData)
	{
		FreeContiguousMemory(pAlignedPageTable);
		return NULL;
	}

	return pEptPageTableData;
}


static
PEPT_PAGE_TABLE_DATA FindStaticEptPageTable(IN UINT64 PhysicalPageTable)
{
	EPT_PAGE_TABLE_DATA EptPageTableData;
	PEPT_PAGE_TABLE_DATA pFoundData;

	if (NULL == PhysicalPageTable)
	{
		return NULL;
	}

	EptPageTableData.AlignedPhysicalEptPageTable = PhysicalPageTable;
	pFoundData = (PEPT_PAGE_TABLE_DATA)RtlLookupElementGenericTableAvl(&st_StaticEptPageTableTree, &EptPageTableData);
	if (NULL == pFoundData)
	{
		return NULL;
	}

	return pFoundData;
}


static
PEPT_PAGE_TABLE_DATA FindDynamicEptPageTable(IN UINT64 PhysicalPageTable)
{
	EPT_PAGE_TABLE_DATA EptPageTableData;
	PEPT_PAGE_TABLE_DATA pFoundData;

	if (NULL == PhysicalPageTable)
	{
		return NULL;
	}

	EptPageTableData.AlignedPhysicalEptPageTable = PhysicalPageTable;
	pFoundData = (PEPT_PAGE_TABLE_DATA)RtlLookupElementGenericTableAvl(&st_DynamicEptPageTableTree, &EptPageTableData);
	if (NULL == pFoundData)
	{
		return NULL;
	}

	return pFoundData;
}


static
VOID DeleteDynamicEptPageTable(IN UINT64 PhysicalPageTable)
{
	EPT_PAGE_TABLE_DATA EptPageTableData;
	PEPT_PAGE_TABLE_DATA pFoundData;

	if (NULL == PhysicalPageTable)
	{
		return;
	}

	EptPageTableData.AlignedPhysicalEptPageTable = PhysicalPageTable;
	pFoundData = (PEPT_PAGE_TABLE_DATA)RtlLookupElementGenericTableAvl(&st_DynamicEptPageTableTree, &EptPageTableData);
	if (NULL == pFoundData)
	{
		return;
	}

	FreeContiguousMemory(pFoundData->pAlignedVirtualEptPageTable);
	RtlDeleteElementGenericTableAvl(&st_DynamicEptPageTableTree, pFoundData);
}


static
PEPT_PML4E GetEptPml4e(IN UINT64 PhysicalAddress)
{
	return &st_EptState.Pml4[0];
}


static
PEPT_PDPTE GetEptPdpte(IN UINT64 PhysicalAddress)
{

	return &st_EptState.Pdpt[(PhysicalAddress >> 39) & 0x1FF];
}


static
PEPT_PDE_2MB GetEptPde2Mb(IN UINT64 PhysicalAddress)
{
	return &st_EptState.Pd[(PhysicalAddress >> 30) & 0x1FF][(PhysicalAddress >> 21) & 0x1FF];
}


PEPT_PDE GetEptPde(IN UINT64 PhysicalAddress)
{
	return &st_EptState.Pd[(PhysicalAddress >> 30) & 0x1FF][(PhysicalAddress >> 21) & 0x1FF];
}


PEPT_PTE GetEptPte(IN UINT64 PhysicalAddress)
{
	PEPT_PAGE_TABLE_DATA pEptPageTableData, pDynamicEptPageTableData;
	PEPT_PTE pEptPte;
	PEPT_PDE pEptPde;

	pEptPde = GetEptPde(PhysicalAddress);
	pEptPageTableData = FindStaticEptPageTable(pEptPde->Pte * PAGE_SIZE);
	if (NULL != pEptPageTableData)
	{
		pEptPte = (PEPT_PTE)(pEptPageTableData->pAlignedVirtualEptPageTable) + ((PhysicalAddress >> 12) & 0x1FF);
	}
	else
	{
		pDynamicEptPageTableData = FindDynamicEptPageTable(pEptPde->Pte * PAGE_SIZE);
		if (NULL == pDynamicEptPageTableData)
		{
			return NULL;
		}

		pEptPte = (PEPT_PTE)(pDynamicEptPageTableData->pAlignedVirtualEptPageTable) + ((PhysicalAddress >> 12) & 0x1FF);
	}

	return pEptPte;
}


BOOLEAN IsLargePde(IN UINT64 PhysicalAddress)
{
	return st_EptState.Pd[(PhysicalAddress >> 30) & 0x1FF][(PhysicalAddress >> 21) & 0x1FF].LargePage;
}


static
VOID SetupPageTable(IN EPT_PDE_2MB EptPde2Mb, OUT PEPT_PAGE_TABLE pPageTable, OUT PEPT_PDE pEptPde)
{
	PEPT_PTE pEptPte;

	if (NULL == pPageTable || NULL == pEptPde)
	{
		return;
	}

	RtlZeroMemory(pPageTable, EPT_PTE_COUNT * sizeof(EPT_PTE));

	for (ULONG i = 0; i < EPT_PTE_COUNT; ++i)
	{
		pEptPte = pPageTable + i;

		pEptPte->Read = 1;
		pEptPte->Write = 1;
		pEptPte->Execute = 1;
		pEptPte->MemoryType = EptPde2Mb.MemoryType;
		pEptPte->Pfn = ((EptPde2Mb.LargePfn * LARGE_PAGE_SIZE) / PAGE_SIZE) + i;
	}

	pEptPde->Value = 0;
	pEptPde->Read = 1;
	pEptPde->Write = 1;
	pEptPde->Execute = 1;
	pEptPde->LargePage = 0;
	pEptPde->Pte = GetPhysicalAddress(pPageTable) / PAGE_SIZE;
}


static
PEPT_PAGE_TABLE SplitPde2Mb(IN PEPT_PDE_2MB pEptPde2Mb, OUT PEPT_PDE pEptPde)
{
	PEPT_PAGE_TABLE_DATA pEptPageTableData;

	if (NULL == pEptPde2Mb || NULL == pEptPde)
	{
		return NULL;
	}

	if (0 == pEptPde2Mb->LargePage)
	{
		return NULL;
	}

	pEptPageTableData = AcquireStaticEptPageTable();
	if (NULL == pEptPageTableData)
	{
		return NULL;
	}

	SetupPageTable(*pEptPde2Mb, pEptPageTableData->pAlignedVirtualEptPageTable, pEptPde);

	return pEptPageTableData->pAlignedVirtualEptPageTable;
}


/* Set cache policy in ept pte. Memory region covered by ept pte is contained lots of mtrr is considered */
static
VOID SetPteMemoryType(
	IN OUT PEPT_PTE pEptPte,
	IN PMEMORY_TYPE_INFO MemoryTypeTable,
	IN ULONG NumberOfMemoryTypeEntry,
	IN ULONG DefaultMemoryType
)
{
	UINT64 PhysicalAddress;
	UCHAR TargetMemoryType;
	BOOLEAN IsWriteThrough = FALSE;

	if (NULL == pEptPte || NULL == MemoryTypeTable)
	{
		return;
	}

	PhysicalAddress = pEptPte->Pfn * PAGE_SIZE;
	TargetMemoryType = DefaultMemoryType;
	for (ULONG i = 0; i < NumberOfMemoryTypeEntry; ++i)
	{
		// Ept pte is contained in some mtrr
		if ((PhysicalAddress >= MemoryTypeTable[i].PhysicalBase) &&
			((PhysicalAddress + PAGE_SIZE - 1) <= MemoryTypeTable[i].PhysicalEnd))
		{
			TargetMemoryType = MemoryTypeTable[i].Type;

			// In cpu architecture, cache policy of memory region contained both mtrr A and mtrr B must be UC if A or B is UC 
			if (MEMORY_TYPE_UNCACHEABLE == TargetMemoryType)
			{
				(pEptPte)->MemoryType = TargetMemoryType;
				return;
			}
			else if (MEMORY_TYPE_WRITE_THROUGH == TargetMemoryType)
			{
				IsWriteThrough = TRUE;
			}
		}
	}

	// In cpu architecture, memory region contained both WT mtrr and WB mtrr must be WT, other case is not defined
	if (TRUE == IsWriteThrough)
	{
		(pEptPte)->MemoryType = MEMORY_TYPE_WRITE_THROUGH;
	}

	(pEptPte)->MemoryType = TargetMemoryType;
}


/* Set cache policy in ept pte 2mb. If mtrr is contained in ept pte 2mb, then ept pte 2mb can be splitt */
static
VOID SetPde2MbMemoryType(
	IN OUT PEPT_PDE_2MB pEptPde2Mb,
	IN OPTIONAL PMEMORY_TYPE_INFO MemoryTypeTable,
	IN ULONG NumberOfMemoryTypeEntry,
	IN ULONG DefaultMemoryType
)
{
	EPT_PDE EptPde;
	PEPT_PAGE_TABLE pPageTable;
	UINT64 PhysicalAddress;
	UCHAR TargetMemoryType;
	BOOLEAN IsWriteThrough = FALSE;

	if (NULL == pEptPde2Mb)
	{
		return;
	}

	PhysicalAddress = pEptPde2Mb->LargePfn * LARGE_PAGE_SIZE;
	TargetMemoryType = DefaultMemoryType;

	if (NULL == MemoryTypeTable)
	{
		pEptPde2Mb->MemoryType = TargetMemoryType;
		return;
	}

	for (ULONG i = 0; i < NumberOfMemoryTypeEntry; ++i)
	{
		if ((PhysicalAddress >= MemoryTypeTable[i].PhysicalBase) &&
			((PhysicalAddress + LARGE_PAGE_SIZE - 1) <= MemoryTypeTable[i].PhysicalEnd))// Ept pte 2mb is contained in some mtrr
		{
			TargetMemoryType = MemoryTypeTable[i].Type;

			if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
			{
				pEptPde2Mb->MemoryType = TargetMemoryType;
				return;
			}
			else if (MEMORY_TYPE_WRITE_THROUGH == TargetMemoryType)
			{
				IsWriteThrough = TRUE;
			}
		}
		else if ((PhysicalAddress > MemoryTypeTable[i].PhysicalEnd) ||
			((PhysicalAddress + LARGE_PAGE_SIZE - 1) < MemoryTypeTable[i].PhysicalBase))
		{
			// Do nothing, If ept pte 2mb is not contained in any mtrr
		}
		else// Intersection ept pde 2mb and some mtrr is not empty
		{
			pPageTable = SplitPde2Mb(pEptPde2Mb, &EptPde);
			if (NULL == pPageTable)
			{
				return;
			}

			for (ULONG j = 0; j < EPT_PTE_COUNT; ++j)// After split, check again
			{
				SetPteMemoryType(pPageTable + i, MemoryTypeTable, NumberOfMemoryTypeEntry, DefaultMemoryType);
			}

			return;
		}
	}

	if (TRUE == IsWriteThrough)
	{
		pEptPde2Mb->MemoryType = MEMORY_TYPE_WRITE_THROUGH;
	}

	pEptPde2Mb->MemoryType = TargetMemoryType;
}


BOOLEAN InitializeEpt()
{
	ULONG NumberOfMemoryType;
	PMEMORY_TYPE_INFO MemoryTypeInfoTable = NULL;
	EPT_PML4E EptPml4e;
	EPT_PDPTE EptPdpte;
	EPT_PDE_2MB EptPde2Mb;
	ULONG DefaultMemoryType;

	IA32_VMX_EPT_VPID_CAP_MSR VpidCap;
	VpidCap.Value = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	if (0 == VpidCap.Pml4 || 0 == VpidCap.WriteBack ||
		0 == VpidCap.LargePde || 0 == VpidCap.ExecuteOnly /*|| 0 == VpidCap.AdvancedEptViolationInfo*/)
	{
		return FALSE;
	}

	st_EptState.Eptp.Value = 0;
	st_EptState.Eptp.MemoryType = WB;
	st_EptState.Eptp.PageWalkLength = 3;// pml4 - 1
	st_EptState.Eptp.Pfn = GetPhysicalAddress(st_EptState.Pml4) / PAGE_SIZE;
	g_Eptp = st_EptState.Eptp.Value;

	GetDefaultMemoryType(&DefaultMemoryType);
	RtlInitializeGenericTableAvl(&st_StaticEptPageTableTree, EptPageTableCompare, AllocateMemoryInTree, FreeMemoryInTree, NULL);
	RtlInitializeGenericTableAvl(&st_DynamicEptPageTableTree, EptPageTableCompare, AllocateMemoryInTree, FreeMemoryInTree, NULL);

	GetMemoryType(NULL, &NumberOfMemoryType);
	if (0 != NumberOfMemoryType)
	{
		MemoryTypeInfoTable = (PMEMORY_TYPE_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(MEMORY_TYPE_INFO) * NumberOfMemoryType, MEM_TAG_PAGE);
		if (NULL == MemoryTypeInfoTable)
		{
			return FALSE;
		}

		GetMemoryType(MemoryTypeInfoTable, NULL);
	}

	EptPml4e.Value = 0;
	EptPml4e.Read = 1;
	EptPml4e.Write = 1;
	EptPml4e.Execute = 1;
	EptPml4e.Pdpt = GetPhysicalAddress(st_EptState.Pdpt) / PAGE_SIZE;
	st_EptState.Pml4[0] = EptPml4e;

	for (ULONG i = 0; i < EPT_PDPE_COUNT; ++i)
	{
		EptPdpte.Value = 0;
		EptPdpte.Read = 1;
		EptPdpte.Write = 1;
		EptPdpte.Execute = 1;
		EptPdpte.Pd = GetPhysicalAddress(st_EptState.Pd[i]) / PAGE_SIZE;

		st_EptState.Pdpt[i] = EptPdpte;
	}

	for (ULONG i = 0; i < EPT_PDPE_COUNT; ++i)
	{
		for (ULONG j = 0; j < EPT_PDE_COUNT; ++j)
		{
			EptPde2Mb.Value = 0;
			EptPde2Mb.Read = 1;
			EptPde2Mb.Write = 1;
			EptPde2Mb.Execute = 1;
			EptPde2Mb.LargePage = 1;
			EptPde2Mb.LargePfn = (i * EPT_PDE_COUNT) + j;
			SetPde2MbMemoryType(&EptPde2Mb, MemoryTypeInfoTable, NumberOfMemoryType, DefaultMemoryType);

			st_EptState.Pd[i][j] = EptPde2Mb;
		}
	}

	if (MemoryTypeInfoTable)
	{
		ExFreePool(MemoryTypeInfoTable);
	}

	return TRUE;
}


VOID FinalizeEpt()
{
	PEPT_PAGE_TABLE_DATA pFoundData;

	pFoundData = RtlEnumerateGenericTableAvl(&st_StaticEptPageTableTree, TRUE);
	while (NULL != pFoundData)
	{
		FreeContiguousMemory(pFoundData->pAlignedVirtualEptPageTable);
		RtlDeleteElementGenericTableAvl(&st_StaticEptPageTableTree, pFoundData);
		pFoundData = RtlEnumerateGenericTableAvl(&st_StaticEptPageTableTree, FALSE);
	}
}


static
ULONG_PTR ModifyEptPteAndInvalidateTLB(IN ULONG_PTR pContext)
{
	HostSendMessage(HOST_MSG_ID_MODIFY_EPT_PTE, pContext);
	return NULL;
}


static
VOID ModifyEptPte(
	IN PVOID pOriginPageEntry,
	IN UINT64 PageEntryValue,
	IN OPTIONAL PVOID pVirtualPageFrame
)
{
	HOST_MSG_MODIFY_PAGE_DATA ModifyPageData;
	ModifyPageData.pEptPte = pOriginPageEntry;
	ModifyPageData.PageEntryValue = PageEntryValue;
	ModifyPageData.pVirtualPageFrame = pVirtualPageFrame;

	KeIpiGenericCall(ModifyEptPteAndInvalidateTLB, &ModifyPageData);
}


/* Split large page. If page is small, then return TRUE */
BOOLEAN DynamicSplitPage(IN PEPT_PDE_2MB pEptPde2Mb)
{
	PEPT_PAGE_TABLE_DATA pDynamicEptPageTableData;
	EPT_PDE EptPde;

	if (NULL == pEptPde2Mb)
	{
		return FALSE;
	}

	if (1 == pEptPde2Mb->LargePage)
	{
		pDynamicEptPageTableData = AllocateDynamicEptPageTable();
		if (NULL == pDynamicEptPageTableData)
		{
			return FALSE;
		}

		SetupPageTable(*pEptPde2Mb, pDynamicEptPageTableData->pAlignedVirtualEptPageTable, &EptPde);
		ModifyEptPte(pEptPde2Mb, EptPde.Value, NULL);
	}

	return TRUE;
}


/* Merge small page. If page is large, do nothing.(StaticEptPageTable cannot be merged) */
VOID DynamicMergePage(IN PEPT_PDE pEptPde)
{
	PEPT_PAGE_TABLE_DATA pStaticEptPageTableData, pDynamicEptPageTableData;
	EPT_PDE_2MB EptPde2Mb;
	EPT_PTE EptPte;

	if (NULL == pEptPde)
	{
		return;
	}

	if (1 == pEptPde->LargePage)
	{
		return;
	}

	pStaticEptPageTableData = FindStaticEptPageTable(pEptPde->Pte * PAGE_SIZE);// Check this memory is for mtrr memory region
	if (NULL != pStaticEptPageTableData)
	{
		return;
	}

	pDynamicEptPageTableData = FindDynamicEptPageTable(pEptPde->Pte * PAGE_SIZE);
	if (NULL == pDynamicEptPageTableData)
	{
		return;
	}

	EptPte.Value = *(PEPT_PTE*)pDynamicEptPageTableData->pAlignedVirtualEptPageTable;
	EptPde2Mb.Value = 0;

	EptPde2Mb.Read = 1;
	EptPde2Mb.Write = 1;
	EptPde2Mb.Execute = 1;
	EptPde2Mb.LargePage = 1;
	EptPde2Mb.MemoryType = EptPte.MemoryType;// Get 0th page table entry memory type
	EptPde2Mb.LargePfn = (EptPte.Pfn * PAGE_SIZE) / LARGE_PAGE_SIZE;

	ModifyEptPte(pEptPde, EptPde2Mb.Value, NULL);

	DeleteDynamicEptPageTable(pDynamicEptPageTableData->AlignedPhysicalEptPageTable);
}


/*
Each core may have different memory status by TLB flush and no lock. But entire logic is correct
Since logic depend on each core
*/
VOID
ModifyEptPfn(
	IN PEPT_PTE pEptPte,
	IN PVOID pVirtualPageFrame,
	IN ULONG AccessRight,
	IN BOOLEAN bHost
)
{
	EPT_PTE EptPte;

	EptPte.Value = pEptPte->Value;

	switch (AccessRight)
	{
	case MEMORY_READ:
		EptPte.Read = 1;
		EptPte.Write = 0;
		EptPte.Execute = 0;
		break;
	case MEMORY_READ_WRITE:
		EptPte.Read = 1;
		EptPte.Write = 1;
		EptPte.Execute = 0;
		break;
	case MEMORY_EXECUTE:
		EptPte.Read = 0;
		EptPte.Write = 0;
		EptPte.Execute = 1;
		break;
	case MEMORY_READ_EXECUTE:
		EptPte.Read = 1;
		EptPte.Write = 0;
		EptPte.Execute = 1;
		break;
	case MEMORY_READ_WRITE_EXECUTE:
		EptPte.Read = 1;
		EptPte.Write = 1;
		EptPte.Execute = 1;
		break;
	default:
		EptPte.Read = 1;
		EptPte.Write = 1;
		EptPte.Execute = 1;
	}

	EptPte.Pfn = GetPhysicalAddress(pVirtualPageFrame) / PAGE_SIZE;

	if (bHost)
	{
		InterlockedExchange64(pEptPte, EptPte.Value);
		InvalidateAddress(g_Eptp);
	}
	else
	{
		ModifyEptPte(pEptPte, EptPte.Value, pVirtualPageFrame);
	}
}
