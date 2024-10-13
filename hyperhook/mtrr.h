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
						Type Definition
****************************************************************/
typedef enum _MTRR_MEMORY_TYPE
{
	UC = 0,
	WC = 1,
	WT = 4,
	WP = 5,
	WB = 6
} MTRR_MEMORY_TYPE;


typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 ExecuteOnly : 1;						// [0] Support excute only in ept(read, write may cause ept violation)
													// INT3 hook use this bit

		UINT64 Reserved1 : 5;						// [5:1]
		UINT64 Pml4 : 1;							// [6] Support pml4 in ept
		UINT64 Pml5 : 1;							// [7] Support pml5 in ept
		UINT64 Uncacheable : 1;						// [8] This bit indicates whether ept support uncacheable cache policy
		UINT64 Reserved2 : 5;						// [13:9]
		UINT64 WriteBack : 1;						// [14] This bit indicates whether ept support write-back cache policy
		UINT64 Reserved3 : 1;						// [15]
		UINT64 LargePde : 1;						// [16] Support 2Mb page directory entry in ept
		UINT64 LargePdpte : 1;						// [17] Support 1Gb page directory pointer table entry in ept
		UINT64 Reserved4 : 2;						// [19:18]
		UINT64 Invept : 1;							// [20] Support INVEPT
		UINT64 EptAccessedAndDirtyFlag : 1;			// [21] Support accessed flag and dirty flag in ept
		UINT64 AdvancedEptViolationInfo : 1;		// [22] This bit indicates Whether more infomation can be optained during vmexit caused by ept violation
													// During vmexit caused by ept violation, more information can be optained by vmread(EXIT_QUALIFICATION)

		UINT64 Reserved5 : 2;						// [24:23]
		UINT64 InveptSingleContext : 1;				// [25] Support single-context INVEPT
		UINT64 InveptAllContext : 1;				// [26] Support all-context INVEPT
		UINT64 Reserved6 : 5;						// [31:27]
		UINT64 Invvpid : 1;							// [32] Support INVVPID
		UINT64 Reserved7 : 7;						// [39:33]
		UINT64 InvvpidIndividualAddress : 1;		// [40] Support individual-address INVVPID
		UINT64 InvvpidSingleContext : 1;			// [41] Support single-context INVVPID
		UINT64 InvvpidAllContext : 1;				// [42] Support all-context INVVPID
		UINT64 InvvpidSingleContextGlobal : 1;		// [43] Support single-context-retaining-global INVVPID
		UINT64 Reserved8 : 4;						// [47:44]
		UINT64 HLAT : 6;							// [53:48] Max size of HLAT prefix
		UINT64 Reserved9 : 10;						// [63:54]
	};
} IA32_VMX_EPT_VPID_CAP_MSR, *PIA32_VMX_EPT_VPID_CAP_MSR;


typedef struct _MEMORY_TYPE_INFO
{
	UINT64 PhysicalBase;
	UINT64 PhysicalEnd;
	UCHAR Type;
} MEMORY_TYPE_INFO, *PMEMORY_TYPE_INFO;


/****************************************************************
					   Function Declaration
****************************************************************/
VOID GetMemoryType(OUT OPTIONAL PMEMORY_TYPE_INFO pMemoryType, OUT OPTIONAL PULONG pNumberOfMemoryType);
VOID GetDefaultMemoryType(IN PULONG pulDefaultMemoryType);