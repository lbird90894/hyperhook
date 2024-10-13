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
#include "mtrr.h"


/****************************************************************
					  Constant Definition
****************************************************************/
#define MSR_IA32_MTRR_DEF_TYPE			0x000002FF
#define MSR_IA32_VMX_EPT_VPID_CAP		0x0000048C
#define MSR_IA32_MTRR_DEF_TYPE			0x000002FF
#define MSR_IA32_MTRR_CAPABILITIES		0x000000FE
#define MSR_IA32_MTRR_PHYSBASE0			0x00000200
#define MSR_IA32_MTRR_PHYSMASK0			0x00000201

#define NUM_FIXED_MTRR					11


/****************************************************************
						Type Definition
****************************************************************/
typedef union _IA32_MTRR_DEF_TYPE_REGISTER
{
	UINT64 Value;
	struct
	{
		UINT64 DefaultMemoryType : 8;		// [7:0] Indicated default cache policy for memory range that is not covered by mtrr;
		UINT64 Reserved1 : 2;				// [9:8]
		UINT64 FixedRangeMtrrEnable : 1;	// [10] To enable fixed range mtrr, this bit must be set
		UINT64 MtrrEnable : 1;				// [11] To enable mtrr, this bit must be set
		UINT64 Reserved2 : 52;				// [63:12]
	};
} IA32_MTRR_DEF_TYPE_REGISTER, *PIA32_MTRR_DEF_TYPE_REGISTER;


typedef union _IA32_MTRRCAP_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 VariableRangeCount : 8;		// [7:0]
		UINT64 FixedRangeSupport : 1;		// [8]
		UINT64 Reserved1 : 1;				// [9]
		UINT64 WriteCombiningSupport : 1;	// [10]
		UINT64 SmrrSupport : 1;				// [11]
		UINT64 Reserved2 : 52;				// [63:12]
	};
} IA32_MTRRCAP_MAR, *PIA32_MTRRCAP_MAR;


typedef union _IA32_MTRR_PHYSBASE_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 MemoryType : 8;				// [7:0]	Indicates cache Type of memory region covered by variable range mtrr
		UINT64 Reserved1 : 4;				// [11:8]
		UINT64 PhysicalBase : 52;			// [63:12]	Indicated start address of memory region covered by variable range mtrr
	};
} IA32_MTRR_PHYSBASE_MSR, *PIA32_MTRR_PHYSBASE_MSR;


typedef union _IA32_MTRR_PHYSMASK_MSR
{
	UINT64 Value;
	struct
	{
		UINT64 Reserved1 : 11;				// [10:0]
		UINT64 Valid : 1;					// [11]		To enable variable range mtrr, it must be set
		UINT64 PhysicalMask : 52;			// [63:12]	If memory region & PhysicalMask == PhysicalBase & PhysicalMask, that memory region follows variable range mtrr policy
	};
} IA32_MTRR_PHYSMASK_MSR, *PIA32_MTRR_PHYSMASK_MSR;


typedef union _IA32_FIXED_MTRR_MSR
{
	UINT64 Value;
	UCHAR Partition[8];
} IA32_FIXED_MTRR_MSR, *PIA32_FIXED_MTRR_MSR;


/****************************************************************
					   Function Definition
****************************************************************/
static
PCWSTR GetMemoryTypeStr(IN MTRR_MEMORY_TYPE MemoryType)
{
	PCWSTR pMemoryType;
	switch (MemoryType)
	{
	case UC:
		pMemoryType = L"UC";
		break;
	case WC:
		pMemoryType = L"WC";
		break;
	case WT:
		pMemoryType = L"WP";
		break;
	case WB:
		pMemoryType = L"WB";
		break;
	default:
		pMemoryType = L"NA";
	}

	return pMemoryType;
}


/* Get 8 partitions of one fixed range mtrr */
static
VOID GetFixedMtrrInfo(IN PMEMORY_TYPE_INFO pMemoryType, IN ULONG FixedMtrrMsr, IN ULONG BaseMemory, IN ULONG MemorySize)
{
	IA32_FIXED_MTRR_MSR FixedMtrr;
	FixedMtrr.Value = __readmsr(FixedMtrrMsr);

	for (ULONG i = 0; i < 8; ++i)
	{
		pMemoryType[i].PhysicalBase = BaseMemory + (i * MemorySize);
		pMemoryType[i].PhysicalEnd = pMemoryType[i].PhysicalBase + (MemorySize - 1);
		pMemoryType[i].Type = FixedMtrr.Partition[i];
		LogWrite(LOG_INFO, L"%s:%05llx-%05llx  ", GetMemoryTypeStr(pMemoryType[i].Type), pMemoryType[i].PhysicalBase, pMemoryType[i].PhysicalEnd);
	}
}


/* windows os use memory range with no hole */
static
BOOLEAN GetVariableMtrrInfo(IN PMEMORY_TYPE_INFO pMemoryType, IN ULONG VariableMtrrBaseMsr, IN ULONG VariableMtrrMaskMsr)
{
	IA32_MTRR_PHYSBASE_MSR MtrrBaseMsr;
	IA32_MTRR_PHYSMASK_MSR MtrrMaskMsr;
	ULONG LsbIndex;

	MtrrBaseMsr.Value = __readmsr(VariableMtrrBaseMsr);
	MtrrMaskMsr.Value = __readmsr(VariableMtrrMaskMsr);
	if (MtrrMaskMsr.Valid)
	{
		if (TRUE == _BitScanForward64(&LsbIndex, MtrrMaskMsr.PhysicalMask * PAGE_SIZE))
		{
			pMemoryType->PhysicalBase = MtrrBaseMsr.PhysicalBase * PAGE_SIZE;
			pMemoryType->PhysicalEnd = MtrrBaseMsr.PhysicalBase * PAGE_SIZE + ((1ULL << LsbIndex) - 1ULL);
			pMemoryType->Type = MtrrBaseMsr.MemoryType;

			LogWrite(LOG_INFO, L"%s:%016llx-%016llx", GetMemoryTypeStr(pMemoryType->Type), pMemoryType->PhysicalBase, pMemoryType->PhysicalEnd);
		}

		return TRUE;
	}

	return FALSE;
}


VOID GetDefaultMemoryType(IN PULONG pulDefaultMemoryType)
{
	CPUID CpuInfo;
	IA32_MTRR_DEF_TYPE_REGISTER MtrrDefType;

	if (NULL == pulDefaultMemoryType)
	{
		return;
	}

	__cpuid((int*)&CpuInfo, 1);
	if (0 == (CpuInfo.ecx & (1 << 12)))// Bit 12th indicates whether mtrr is supported 
	{
		*pulDefaultMemoryType = UC;// If not support mtrr, cache policy is UC
		return;
	}

	MtrrDefType.Value = __readmsr(MSR_IA32_MTRR_DEF_TYPE);
	if (0 == MtrrDefType.MtrrEnable)// Once bios set this value, this value will not be changed
	{
		*pulDefaultMemoryType = UC;
		return;
	}

	*pulDefaultMemoryType = MtrrDefType.DefaultMemoryType;
}


VOID GetMemoryType(OUT OPTIONAL PMEMORY_TYPE_INFO pMemoryType, OUT OPTIONAL PULONG pNumberOfMemoryType)
{
	ULONG DefaultMemoryType;
	IA32_MTRRCAP_MAR MtrrCapMsr;
	IA32_MTRR_PHYSMASK_MSR MtrrMaskMsr;
	ULONG NumberOfMtrrInfo = NUM_FIXED_MTRR * 8;
	ULONG ulIndex = 0;

	if (NULL == pMemoryType && NULL == pNumberOfMemoryType)
	{
		return;
	}

	MtrrCapMsr.Value = __readmsr(MSR_IA32_MTRR_CAPABILITIES);
	if (NULL == pMemoryType)
	{
		for (ULONG i = 0; i < MtrrCapMsr.VariableRangeCount; ++i)
		{
			MtrrMaskMsr.Value = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (i * 2));
			if (MtrrMaskMsr.Valid)
			{
				++NumberOfMtrrInfo;
			}
		}
		*pNumberOfMemoryType = NumberOfMtrrInfo;
		return;
	}

	GetDefaultMemoryType(&DefaultMemoryType);
	LogWrite(LOG_INFO, L"Default memory type: %s", GetMemoryTypeStr(DefaultMemoryType));

	LogWrite(LOG_INFO, L"Fixed memory type range");
	GetFixedMtrrInfo(pMemoryType, 0x250, 0, 0x10000);// 64Kb fixed range mtrr
	GetFixedMtrrInfo(pMemoryType + 8, 0x258, 0x80000, 0x4000);// 16Kb fixed range mtrr
	GetFixedMtrrInfo(pMemoryType + 16, 0x259, 0xA0000, 0x4000);// 16Kb fixed range mtrr
	for (ULONG i = 0; i < 8; ++i)
	{
		GetFixedMtrrInfo(pMemoryType + 24 + 8 * i, 0x268 + i, 0xC0000 + 0x8000 * i, 0x1000);// 4Kb fixed range mtrr
	}

	LogWrite(LOG_INFO, L"Variable memory type range");
	for (ULONG i = 0; i < MtrrCapMsr.VariableRangeCount; ++i)
	{
		if (TRUE == GetVariableMtrrInfo(pMemoryType + 8 * NUM_FIXED_MTRR + ulIndex, MSR_IA32_MTRR_PHYSBASE0 + (i * 2), MSR_IA32_MTRR_PHYSMASK0 + (i * 2)))
		{
			++ulIndex;
		}
	}

	return STATUS_SUCCESS;
}


