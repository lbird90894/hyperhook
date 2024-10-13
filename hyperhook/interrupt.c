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
#include "hook.h"
#include "log.h"
#include "interrupt.h"


/****************************************************************
						Type Definition
****************************************************************/
typedef enum _INTERRUPT_TYPE
{
	EXTERNAL_INTERRUPT = 0,
	RESERVED = 1,
	NMI = 2,
	HARDWARE_EXCEPTION = 3,
	SOFTWARE_INTERRUPT = 4,
	PRIVILEGED_SOFTWARE_INTERRUPT = 5,
	SOFTWARE_EXCEPTION = 6,
	OTHER_EVENT = 7
} INTERRUPT_TYPE;


typedef union _INTERRUPT_INFO {
	UINT32 Value;
	struct {
		UINT32 Vector : 8;		// [7:0]	index of IDT
		UINT32 Type : 3;		// [10:8]	This bits indicates type of event injection like exception or interrupt etc... 
		/*
		Breakpoint exception and overflow exception must be set as software exception.
		For debug exception by INT1, this type must be set as privileged software exception.
		Other case, this type must be set as hardware exception
		*/

		UINT32 ErrorCode : 1;	// [11]		For event injection, this bit indicates whether cpu push error code onto guest stack
		UINT32 Reserved : 19;	// [30:12]
		UINT32 Valid : 1;		// [31]		This bit must be set
	};
} INTERRUPT_INFO, *PINTERRUPT_INFO;


/****************************************************************
					   Function Definition
****************************************************************/
static
VOID InjectEvent(
	IN INTERRUPT_TYPE InterruptType,
	IN INTERRUPT_VECTOR InterruptVector
)
{
	INTERRUPT_INFO InterruptInfo = { 0 };
	UINT32 ulInstructionLen;
	InterruptInfo.Valid = 1;
	InterruptInfo.Type = InterruptType;
	InterruptInfo.Vector = InterruptVector;

	__vmx_vmwrite(VM_ENTRY_INTR_INFO, InterruptInfo.Value);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ulInstructionLen);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ulInstructionLen);// VM_ENTRY_INSTRUCTION_LEN is only meaning for trap
}


static
VOID InjectEventWithErrorCode(
	IN INTERRUPT_TYPE InterruptType,
	IN INTERRUPT_VECTOR InterruptVector,
	IN UINT32 ulErrorCode
)
{
	INTERRUPT_INFO InterruptInfo = { 0 };
	UINT32 ulInstructionLen;
	InterruptInfo.Valid = 1;
	InterruptInfo.Type = InterruptType;
	InterruptInfo.Vector = InterruptVector;
	InterruptInfo.ErrorCode = 1;

	__vmx_vmwrite(VM_ENTRY_INTR_INFO, InterruptInfo.Value);
	__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ulErrorCode);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ulInstructionLen);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ulInstructionLen);// VM_ENTRY_INSTRUCTION_LEN is only meaning for trap
}


VOID ExceptionHandler(IN UINT32 ulInterruptInfo)
{
	UINT64 GuestPhysicalAddress;
	PVOID GuestRip;
	HOOK_DATA HookData;
	INTERRUPT_INFO InterruptInfo;
	InterruptInfo.Value = ulInterruptInfo;

	if (InterruptInfo.Type == SOFTWARE_EXCEPTION && InterruptInfo.Vector == BREAKPOINT_EXCEPTION)
	{
		__vmx_vmread(GUEST_RIP, &GuestRip);
		if (IsHook(GuestRip, &HookData))
		{
			__vmx_vmwrite(GUEST_RIP, HookData.pHookFunction);
			if (0 != HookData.wszFunctionName[0])
			{
				LogWrite(LOG_INFO, L"%s(0x%llx) hook => 0x%llx", HookData.wszFunctionName, HookData.pTargetFunction, HookData.pHookFunction);
			}
		}
		else
		{
			InjectEvent(SOFTWARE_EXCEPTION, BREAKPOINT_EXCEPTION);
		}
	}
	else if (InterruptInfo.Type == HARDWARE_EXCEPTION && InterruptInfo.Vector == DIVIDE_BY_ZERO_EXCEPTION)
	{
		InjectEvent(HARDWARE_EXCEPTION, DIVIDE_BY_ZERO_EXCEPTION);
	}
}
