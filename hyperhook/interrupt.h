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

/*
 trap : execute next instruction after handling exception(increment rip)
 fault : execute same instruction after handling exception(not increment rip)
 abort : hardware error

 cpu architecture pushes error code onto stack for some exceptions
*/
typedef enum _INTERRUPT_VECTOR
{
	DIVIDE_BY_ZERO_EXCEPTION = 0,					// not push error code onto stack
	DEBUG_EXCEPTION = 1,							// not push error code onto stack
	NMI_INTERRUPT = 2,								// not push error code onto stack
	BREAKPOINT_EXCEPTION = 3,						// not push error code onto stack
	OVERFLOW_EXCEPTION = 4,							// not push error code onto stack
	BOUND_RANGE_EXCEEDED_EXCEPTION = 5,				// not push error code onto stack
	INVALID_OPCODE_EXCEPTION = 6,					// not push error code onto stack
	DEVICE_NOT_AVAILABLE_EXCEPTION = 7,				// not push error code onto stack
	DOUBLE_FAULT = 8,								// push error code onto stack
	COPROCESSOR_SEGMENT_OVERRUN_EXCEPTION = 9,		// not push error code onto stack
	INVALID_TASK_SEGMENT_SELECTOR_EXCEPTION = 10,	// push error code onto stack
	SEGMENT_NOT_PRESENT_EXCEPTION = 11,				// push error code onto stack
	STACK_SEGMENT_FAULT_EXCEPTION = 12,				// push error code onto stack
	GENERAL_PROTECTION_EXCEPTION = 13,				// push error code onto stack
	PAGE_FAULT_EXCEPTION = 14,						// push error code onto stack
	RESERVED1 = 15,
	FLOATION_POINT_ERROR_EXCEPTION = 16,			// not push error code onto stack
	ALIGNMENT_CHECK_ERROR_EXCEPTION = 17,			// push error code onto stack
	MACHINE_CHECK_ERROR_EXCEPTION = 18,				// not push error code onto stack
	SIMD_FLOATING_POINT_EXCEPTION = 19,				// not push error code onto stack
	VIRTUALIZATIOIN_EXCEPTION = 20,					// not push error code onto stack
	CONTROL_PROTECTION_EXCEPTION = 21,				// push error code onto stack
	RESERVED2 = 22,
	RESERVED3 = 23,
	RESERVED4 = 24,
	RESERVED5 = 25,
	RESERVED6 = 26,
	RESERVED7 = 27,
	RESERVED8 = 28,
	RESERVED9 = 29,
	RESERVED10 = 30,
	RESERVED11 = 31,
} INTERRUPT_VECTOR;

#define MAKE_BITMAP(N) (1 << N)
VOID ExceptionHandler(IN UINT32 ulInterruptInfo);
