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
#include <ntdef.h>


/****************************************************************
					  Constant Definition
****************************************************************/
#define EPT_PML4E_COUNT 512
#define EPT_PDPE_COUNT 512
#define EPT_PDE_COUNT 512
#define EPT_PTE_COUNT 512
#define EPT_ENTRY_COUNT 512

#define MEMORY_READ 1
#define MEMORY_READ_WRITE 3
#define MEMORY_EXECUTE 4
#define MEMORY_READ_EXECUTE 5
#define MEMORY_READ_WRITE_EXECUTE 7


/****************************************************************
						Type Definition
****************************************************************/
typedef union _EPTP
{
	UINT64 Value;
	struct
	{
		UINT64 MemoryType : 3;				// [2:0]	
		/*
		This value can be only 0(uncacheable) or 6(write back) as cache policy of eptp paging structure cache
		This value is only meaning when CR0.CD = 0
		Eptp paging structure cache is paging structure cache not related to guest paging but eptp paging
		*/

		UINT64 PageWalkLength : 3;			// [5:3]	If PML4, it must be 3
		UINT64 EnableAccessAndDirty : 1;	// [6]		If this set, cpu mark ept page entry's accessed and dirty bit during paging
		UINT64 ShadowStack : 1;				// [7]		associated with supervisor shadow stack
		UINT64 Reserved1 : 4;				// [11:8]
		UINT64 Pfn : 52;					// [63:12]	physical address of PML4 or PML5
	};
} EPTP, *PEPTP;


typedef union _EPT_PML4E
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;					// [0]
		UINT64 Write : 1;					// [1]
		UINT64 Execute : 1;					// [2]
		UINT64 Reserved1 : 5;				// [7:3]
		UINT64 Accessed : 1;				// [8]
		UINT64 Reserved2 : 1;				// [9]
		UINT64 UserModeExecute : 1;			// [10]
		UINT64 Reserved3 : 1;				// [11]
		UINT64 Pdpt : 40;					// [51:12]
		UINT64 Reserved4 : 12;				// [63:52]
	};
} EPT_PML4E, *PEPT_PML4E;


typedef union _EPT_PDPTE
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;					// [0]		
		UINT64 Write : 1;					// [1]
		UINT64 Execute : 1;					// [2]
		UINT64 Reserved1 : 5;				// [7:3]
		UINT64 Accessed : 1;				// [8]
		UINT64 Reserved2 : 1;				// [9]
		UINT64 UserModeExecute : 1;			// [10]
		UINT64 Reserved3 : 1;				// [11]
		UINT64 Pd : 40;						// [51:12]
		UINT64 Reserved4 : 12;				// [63:52]
	};
} EPT_PDPTE, *PEPT_PDPTE;


typedef union _EPT_PDE_2MB
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;					// [0]
		UINT64 Write : 1;					// [1]
		UINT64 Execute : 1;					// [2]
		UINT64 MemoryType : 3;				// [5:3]
		UINT64 IgnorePat : 1;				// [6]
		UINT64 LargePage : 1;				// [7]		Must be set
		UINT64 Accessed : 1;				// [8]
		UINT64 Dirty : 1;					// [9]
		UINT64 UserModeExecute : 1;			// [10]
		UINT64 Reserved1 : 10;				// [20:11]
		UINT64 LargePfn : 31;				// [51:21]	page frame index of 2Mb unit.(PFN * 2Mb = physical address)
		UINT64 Reserved2 : 5;				// [56:52]
		UINT64 VerifyGuestPaging : 1;		// [57]
		UINT64 PagingWrite : 1;				// [58]
		UINT64 Reserved3 : 1;				// [59]
		UINT64 ShadowStack : 1;				// [60]
		UINT64 Reserved4 : 2;				// [62:61]
		UINT64 SuppressVe : 1;				// [63]
	};
} EPT_PDE_2MB, *PEPT_PDE_2MB;


typedef union _EPT_PDE
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;					// [0]
		UINT64 Write : 1;					// [1]
		UINT64 Execute : 1;					// [2]
		UINT64 Reserved1 : 4;				// [6:3]
		UINT64 LargePage : 1;				// [7]		Must be clear
		UINT64 Accessed : 1;				// [8]
		UINT64 Reserved2 : 1;				// [9]
		UINT64 UserModeExecute : 1;			// [10]
		UINT64 Reserved3 : 1;				// [11]
		UINT64 Pte : 40;					// [51:12]
		UINT64 Reserved4 : 12;				// [63:52]
	};
} EPT_PDE, *PEPT_PDE;


typedef union _EPT_PTE
{
	UINT64 Value;
	struct
	{
		UINT64 Read : 1;					// [0]
		UINT64 Write : 1;					// [1]
		UINT64 Execute : 1;					// [2]
		/*
		Secondary Processor-Based VM-Execution Controls's mode-based execute bit is 0 and this bit is 1 => any type of guest address can be executed
		Secondary Processor-Based VM-Execution Controls's mode-based execute bit is 1 and this bit is 1 => only supervisor mode guest address can be executed
		*/

		UINT64 MemoryType : 3;				// [5:3]
		/*
		This value is combined with guest PAT memory type for cache policy.(This value is only meaning when CR0.CD = 0)
		The combination can be obtained by changing MTRR to this value in the MTRR and PAT combination table.
		If CR0.PG = 0, the guest's PAT memory type is considered write back
		If CR0.PG = 1, the guest's PAT memory type is considered an index of IA32_PAT(MSR)
		*/

		UINT64 IgnorePat : 1;				// [6]		If this bit is set, then cache policy is decided only MemoryType
		UINT64 Reserved1 : 1;				// [7]
		UINT64 Accessed : 1;				// [8]		If EPTP's 6th bit is 1 and entry is accessed, then cpu set this bit
		UINT64 Dirty : 1;					// [9]		If EPTP's 6th bit is 1 and write is occured through this entry, then cpu set this bit
		UINT64 UserModeExecute : 1;			// [10]
		/*
		Secondary Processor-Based VM-Execution Controls's mode-based execute bit is 1 and this bit is 1 => only user mode guest address can be executed
		*/

		UINT64 Reserved2 : 1;				// [11]
		UINT64 Pfn : 40;					// [51:12]
		UINT64 Reserved3 : 5;				// [56:52]
		UINT64 VerifyGuestPaging : 1;		// [57]		This bit is only meaning if specific bit of Tertiary Processor-Based VM-Execution Controls is 1
		UINT64 PagingWrite : 1;				// [58]		This bit is only meaning if specific bit of Tertiary Processor-Based VM-Execution Controls is 1
		UINT64 Reserved4 : 1;				// [59]
		UINT64 ShadowStack : 1;				// [60]		This bit is only meaning if specific bit of EPTP is 1
		UINT64 SubPageWrite : 1;			// [61]		This bit is only meaning if specific bit of Secondary Processor-Based VM-Execution Controls is 1
		UINT64 Reserved5 : 1;				// [62]
		UINT64 SuppressVe : 1;				// [63]		This bit is only meaning if specific bit of Secondary Processor-Based VM-Execution Controls is 1
	};
} EPT_PTE, *PEPT_PTE;

typedef EPT_PTE* PEPT_PAGE_TABLE;


typedef struct _VARIABLE_MTRR_DATA
{
	UINT64 PhysicalBase;
	UINT64 PhysicalEnd;
	UCHAR MemoryType;
} VARIABLE_MTRR_DATA, *PVARIABLE_MTRR_DATA;


/****************************************************************
					   Function Declaration
****************************************************************/
BOOLEAN DynamicSplitPage(IN PEPT_PDE_2MB pEptPde2Mb);
VOID DynamicMergePage(IN PEPT_PDE pEptPde);
VOID ModifyEptPfn(IN PEPT_PTE pEptPte, IN PVOID pVirtualPageFrame, IN ULONG AccessRight, IN BOOLEAN bHost);
BOOLEAN IsLargePde(IN UINT64 PhysicalAddress);

BOOLEAN InitializeEpt();
VOID FinalizeEpt();

VOID InvalidateAddress(IN OPTIONAL UINT64 Eptp);

PEPT_PDE GetEptPde(IN UINT64 PhysicalAddress);
PEPT_PTE GetEptPte(IN UINT64 PhysicalAddress);
