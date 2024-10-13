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
#define HOST_ID 'HyHk'

#define HOST_MSG_ID_MODIFY_EPT_PTE	1
#define HOST_MSG_ID_VMX_OFF			2
#define HOST_MSG_ID_LOG				3


/****************************************************************
						Type Definition
****************************************************************/
typedef struct _HOST_MSG_MODIFY_PAGE_DATA
{
	PVOID pEptPte;
	UINT64 PageEntryValue;
	PVOID pVirtualPageFrame;
} HOST_MSG_MODIFY_PAGE_DATA, *PHOST_MSG_MODIFY_PAGE_DATA;


typedef struct _HOST_MSG_LOG_DATA
{
	PLIST_ENTRY pListEntry;
} HOST_MSG_LOG_DATA, *PHOST_MSG_LOG_DATA;