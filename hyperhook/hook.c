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
#include "spinlock.h"
#include "ept.h"
#include "lwstr.h"
#include "hook.h"


#define MEM_TAG_HOOK	'khyH'// Hyhk

/****************************************************************
						Type Definition
****************************************************************/
typedef struct _HOOK_NODE
{
	UINT64 PhysicalTargetFunction;// key
	PVOID VirtualTargetFunction;
	PVOID HookFunction;
	UCHAR PrevCode;
	WCHAR wszFunctionName[MAX_CCH_NAME];
} HOOK_NODE, *PHOOK_NODE;


typedef struct _FAKE_PAGE_FRAME_DATA
{
	PEPT_PDE pKey;// pointer of pde is key
	PVOID pAlignedFakePageFrame[EPT_PTE_COUNT];
	PVOID pAlignedOriginalTarget[EPT_PTE_COUNT];
} FAKE_PAGE_FRAME_DATA, *PFAKE_PAGE_FRAME_DATA;


/****************************************************************
						Global Variable
****************************************************************/
static RTL_AVL_TABLE st_HookTree;
static RTL_AVL_TABLE st_FakePageTree;
BOOLEAN st_bHookStart = FALSE;


/****************************************************************
					   Function Definition
****************************************************************/
static
PVOID AllocateMemoryInTree(IN struct _RTL_AVL_TABLE* Table, IN CLONG ByteSize)
{
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, MEM_TAG_HOOK);
}


static
VOID FreeMemoryInTree(IN struct _RTL_AVL_TABLE* Table, IN PVOID Buffer)
{
	ExFreePool(Buffer);
}


static
RTL_GENERIC_COMPARE_RESULTS
HookCompare(
	IN	struct _RTL_AVL_TABLE  *Table,
	IN	PVOID  FirstStruct,
	IN	PVOID  SecondStruct
)
{
	PHOOK_NODE pFirst = (PHOOK_NODE)FirstStruct;
	PHOOK_NODE pSecond = (PHOOK_NODE)SecondStruct;

	if (pFirst->PhysicalTargetFunction < pSecond->PhysicalTargetFunction)
	{
		return GenericLessThan;
	}
	if (pFirst->PhysicalTargetFunction > pSecond->PhysicalTargetFunction)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}


static
RTL_GENERIC_COMPARE_RESULTS
FakePageCompare(
	IN	struct _RTL_AVL_TABLE  *Table,
	IN	PVOID  FirstStruct,
	IN	PVOID  SecondStruct
)
{
	PFAKE_PAGE_FRAME_DATA pFirst = (PFAKE_PAGE_FRAME_DATA)FirstStruct;
	PFAKE_PAGE_FRAME_DATA pSecond = (PFAKE_PAGE_FRAME_DATA)SecondStruct;

	if (pFirst->pKey < pSecond->pKey)
	{
		return GenericLessThan;
	}
	if (pFirst->pKey > pSecond->pKey)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}


static
PVOID MakeFakePageFrame(IN PVOID VirtualTargetAddress)
{
	FAKE_PAGE_FRAME_DATA FakePageFrameData;
	PFAKE_PAGE_FRAME_DATA pFoundData;
	PVOID pAlignedFakePage;
	UINT64 PhysicalTargetAddress;

	PhysicalTargetAddress = GetPhysicalAddress(VirtualTargetAddress);
	if (IsLargePde(PhysicalTargetAddress))
	{
		return NULL;
	}

	FakePageFrameData.pKey = GetEptPde(PhysicalTargetAddress);

	pFoundData = (PFAKE_PAGE_FRAME_DATA)RtlLookupElementGenericTableAvl(&st_FakePageTree, &FakePageFrameData);
	if (NULL == pFoundData)
	{
		RtlZeroMemory(&FakePageFrameData, sizeof(FakePageFrameData));
		FakePageFrameData.pKey = GetEptPde(PhysicalTargetAddress);
		pAlignedFakePage = AllocateContiguousMemory(PAGE_SIZE);
		if (NULL == pAlignedFakePage)
		{
			return NULL;
		}

		RtlCopyMemory(pAlignedFakePage, (UINT64)VirtualTargetAddress & ~(0xFFFLL), PAGE_SIZE);

		FakePageFrameData.pAlignedFakePageFrame[(PhysicalTargetAddress >> 12) & 0x1FF] = pAlignedFakePage;
		FakePageFrameData.pAlignedOriginalTarget[(PhysicalTargetAddress >> 12) & 0x1FF] = (UINT64)VirtualTargetAddress & ~0xFFF;

		if (NULL == RtlInsertElementGenericTableAvl(&st_FakePageTree, &FakePageFrameData, sizeof(FAKE_PAGE_FRAME_DATA), NULL))
		{
			FreeContiguousMemory(pAlignedFakePage);
			return NULL;
		}
	}
	else
	{
		if (NULL == pFoundData->pAlignedFakePageFrame[(PhysicalTargetAddress >> 12) & 0x1FF])
		{
			pAlignedFakePage = AllocateContiguousMemory(PAGE_SIZE);
			if (NULL == pAlignedFakePage)
			{
				return NULL;
			}

			RtlCopyMemory(pAlignedFakePage, (UINT64)VirtualTargetAddress & ~(0xFFFLL), PAGE_SIZE);

			pFoundData->pAlignedFakePageFrame[(PhysicalTargetAddress >> 12) & 0x1FF] = pAlignedFakePage;
			pFoundData->pAlignedOriginalTarget[(PhysicalTargetAddress >> 12) & 0x1FF] = (UINT64)VirtualTargetAddress & ~0xFFF;
		}
		else
		{
			pAlignedFakePage = pFoundData->pAlignedFakePageFrame[(PhysicalTargetAddress >> 12) & 0x1FF];
		}
	}

	return pAlignedFakePage;
}


BOOLEAN
GetFakeAndOriginalPageData(
	IN UINT64 PhysicalTargetAddress,
	OUT OPTIONAL PVOID *ppOriginalPageFrame,
	OUT OPTIONAL PVOID *ppFakePageFrame
)
{
	FAKE_PAGE_FRAME_DATA FakePageFrameData;
	PFAKE_PAGE_FRAME_DATA pFoundData;

	if (0 == PhysicalTargetAddress)
	{
		return FALSE;
	}

	FakePageFrameData.pKey = GetEptPde(PhysicalTargetAddress);

	pFoundData = (PFAKE_PAGE_FRAME_DATA)RtlLookupElementGenericTableAvl(&st_FakePageTree, &FakePageFrameData);
	if (NULL == pFoundData)
	{
		return FALSE;
	}

	if (NULL != ppOriginalPageFrame)
	{
		*ppOriginalPageFrame = pFoundData->pAlignedOriginalTarget[(PhysicalTargetAddress >> 12) & 0x1FF];
	}

	if (NULL != ppFakePageFrame)
	{
		*ppFakePageFrame = pFoundData->pAlignedFakePageFrame[(PhysicalTargetAddress >> 12) & 0x1FF];
	}

	return TRUE;
}


BOOLEAN ReplaceFakeWithOrigin(IN UINT64 PhysicalTargetAddress)
{
	PEPT_PTE pEptPte;
	PVOID pOriginalPageFrame;

	if (FALSE == _InterlockedCompareExchange8(&st_bHookStart, 0, 0))
	{
		return FALSE;
	}

	pEptPte = GetEptPte(PhysicalTargetAddress);
	if (FALSE == GetFakeAndOriginalPageData(PhysicalTargetAddress, &pOriginalPageFrame, NULL))
	{
		return FALSE;
	}

	ModifyEptPfn(pEptPte, pOriginalPageFrame, MEMORY_READ, TRUE);

	return TRUE;
	// If hooking function is called after return, then ReplaceFakeWithOrigin will be called again
}


BOOLEAN ReplaceOriginWithFake(IN UINT64 PhysicalTargetAddress)
{
	PEPT_PTE pEptPte;
	PVOID pFakePageFrame;

	if (FALSE == _InterlockedCompareExchange8(&st_bHookStart, 0, 0))
	{
		return FALSE;
	}

	pEptPte = GetEptPte(PhysicalTargetAddress);

	if (FALSE == GetFakeAndOriginalPageData(PhysicalTargetAddress, NULL, &pFakePageFrame))
	{
		return FALSE;
	}

	ModifyEptPfn(pEptPte, pFakePageFrame, MEMORY_EXECUTE, TRUE);

	return TRUE;
}


VOID InitializeHook()
{
	RtlInitializeGenericTableAvl(&st_HookTree, HookCompare, AllocateMemoryInTree, FreeMemoryInTree, NULL);
	RtlInitializeGenericTableAvl(&st_FakePageTree, FakePageCompare, AllocateMemoryInTree, FreeMemoryInTree, NULL);
}


static
BOOLEAN SetHookInternal(IN HOOK_INFO HookInfo, OUT PVOID *ppFakePageFrame)
{
	HOOK_NODE HookData = { 0, };
	PHOOK_NODE pFoundData;
	UINT64 PhysicalTargetFunction;
	PVOID pFakePageFrame, pFakePageTargetFunction;
	PEPT_PDE pEptPde;
	PEPT_PDE_2MB pEptPde2Mb;

	if (NULL == ppFakePageFrame)
	{
		return FALSE;
	}

	if (NULL != HookInfo.pwszTargetName)
	{
		if (0 != HookInfo.pwszTargetName[0])
		{
			if (0 != wcscpy_s(HookData.wszFunctionName, MAX_CCH_NAME, HookInfo.pwszTargetName))
			{
				return FALSE;
			}
		}
	}

	PhysicalTargetFunction = GetPhysicalAddress(HookInfo.pTargetFunction);
	HookData.PhysicalTargetFunction = PhysicalTargetFunction;
	HookData.VirtualTargetFunction = HookInfo.pTargetFunction;
	HookData.HookFunction = HookInfo.pHookFunction;

	pFoundData = (PHOOK_NODE)RtlLookupElementGenericTableAvl(&st_HookTree, &HookData);
	if (NULL != pFoundData)
	{
		return FALSE;
	}

	pEptPde = GetEptPde(PhysicalTargetFunction);
	pEptPde2Mb = pEptPde;
	if (FALSE == DynamicSplitPage(pEptPde2Mb))
	{
		return FALSE;
	}

	if (NULL == RtlInsertElementGenericTableAvl(&st_HookTree, &HookData, sizeof(HOOK_NODE), NULL))
	{
		DynamicMergePage(pEptPde);
		return FALSE;
	}

	pFakePageFrame = MakeFakePageFrame(HookInfo.pTargetFunction);
	if (NULL == pFakePageFrame)
	{
		DynamicMergePage(pEptPde);
		return FALSE;
	}

	pFakePageTargetFunction = (UINT64)pFakePageFrame + ((UINT64)HookInfo.pTargetFunction & 0xFFF);

	HookData.PrevCode = *(UCHAR*)pFakePageTargetFunction;
	*(UCHAR*)pFakePageTargetFunction = 0xcc;

	*ppFakePageFrame = pFakePageFrame;

	return TRUE;
}


static
VOID DestroyFakePageTree()
{
	PFAKE_PAGE_FRAME_DATA pFoundNode;

	pFoundNode = RtlEnumerateGenericTableAvl(&st_FakePageTree, TRUE);
	while (NULL != pFoundNode)
	{
		DynamicMergePage(pFoundNode->pKey);
		for (ULONG i = 0; i < EPT_PTE_COUNT; ++i)
		{
			if (pFoundNode->pAlignedFakePageFrame[i])
			{
				FreeContiguousMemory(pFoundNode->pAlignedFakePageFrame[i]);
			}
		}

		RtlDeleteElementGenericTableAvl(&st_FakePageTree, pFoundNode);
		pFoundNode = RtlEnumerateGenericTableAvl(&st_FakePageTree, FALSE);
	}

	pFoundNode = RtlEnumerateGenericTableAvl(&st_HookTree, TRUE);
	while (NULL != pFoundNode)
	{
		RtlDeleteElementGenericTableAvl(&st_HookTree, pFoundNode);
		pFoundNode = RtlEnumerateGenericTableAvl(&st_HookTree, FALSE);
	}
}


BOOLEAN SetHook(IN PHOOK_INFO pHookInfo, IN ULONG NumberOfElement)
{
	PVOID* FakePageFrameList;
	UINT64 PhysicalTargetFunction;

	if (NULL == pHookInfo || 0 == NumberOfElement)
	{
		return FALSE;
	}

	FakePageFrameList = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, NumberOfElement * sizeof(PVOID), MEM_TAG_HOOK);
	if (NULL == FakePageFrameList)
	{
		return FALSE;
	}

	for (ULONG i = 0; i < NumberOfElement; ++i)
	{
		if (FALSE == SetHookInternal(pHookInfo[i], &FakePageFrameList[i]))
		{
			DestroyFakePageTree();
			ExFreePool(FakePageFrameList);
			return FALSE;
		}
	}

	InterlockedExchange(&st_bHookStart, TRUE);

	for (ULONG i = 0; i < NumberOfElement; ++i)
	{
		PhysicalTargetFunction = GetPhysicalAddress(pHookInfo[i].pTargetFunction);
		ModifyEptPfn(GetEptPte(PhysicalTargetFunction), FakePageFrameList[i], MEMORY_EXECUTE, FALSE);
	}

	ExFreePool(FakePageFrameList);
	return TRUE;
}


VOID ClearHook()
{
	PFAKE_PAGE_FRAME_DATA pFoundNode;
	UINT64 PhysicalTargetFunction;

	pFoundNode = RtlEnumerateGenericTableAvl(&st_FakePageTree, TRUE);
	while (NULL != pFoundNode)
	{
		for (ULONG i = 0; i < EPT_PTE_COUNT; ++i)
		{
			if (pFoundNode->pAlignedFakePageFrame[i])
			{
				PhysicalTargetFunction = GetPhysicalAddress(pFoundNode->pAlignedOriginalTarget[i]);
				ModifyEptPfn(GetEptPte(PhysicalTargetFunction), pFoundNode->pAlignedOriginalTarget[i], MEMORY_READ_EXECUTE, FALSE);
			}
		}

		pFoundNode = RtlEnumerateGenericTableAvl(&st_FakePageTree, FALSE);
	}

	InterlockedExchange(&st_bHookStart, FALSE);

	DestroyFakePageTree();
}


BOOLEAN IsHook(IN PVOID VirtualAddress, OUT PHOOK_DATA pHookData)
{
	HOOK_NODE HookData;
	PHOOK_NODE pFoundData;
	UINT64 PhysicalAddress;

	if (NULL == VirtualAddress || NULL == pHookData)
	{
		return FALSE;
	}

	if (FALSE == _InterlockedCompareExchange8(&st_bHookStart, 0, 0))
	{
		return FALSE;
	}

	PhysicalAddress = GetPhysicalAddress(VirtualAddress);
	HookData.PhysicalTargetFunction = PhysicalAddress;

	pFoundData = (PHOOK_NODE)RtlLookupElementGenericTableAvl(&st_HookTree, &HookData);
	if (NULL != pFoundData)
	{
		pHookData->pHookFunction = pFoundData->HookFunction;
		pHookData->pTargetFunction = pFoundData->VirtualTargetFunction;
		LightWcscpy(pHookData->wszFunctionName, MAX_CCH_NAME, pFoundData->wszFunctionName);// always success

		return TRUE;
	}

	return FALSE;
}
