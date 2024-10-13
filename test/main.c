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

#include <wdm.h>
#include "../hyperhook/hyperhook.h"

#define MILLI_SECOND -10000LL

extern VOID Hook_NtCreateFile();
UINT64 Real_NtCreateFile;


VOID
UnloadDriver(
	IN PDRIVER_OBJECT pDriverObject
)
{
	LARGE_INTEGER li;
	li.QuadPart = 100 * MILLI_SECOND;

	ClearHook();
	KeDelayExecutionThread(KernelMode, FALSE, &li);
	/*
	Unloading driver can cause a BSOD with DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS.
	(Filter_NtCreateFile is not valid, but it may exist in another thread by context switching)
	*/

	VmxTerminate();
	LogFinalize();
}


__declspec(code_seg(".test"))
__declspec(noinline) VOID OriginTest()
{
	LogWrite(LOG_INFO, L"**************** This is OriginTest ****************");
}

__declspec(noinline) VOID HookTest()
{
	LogWrite(LOG_INFO, L"**************** This is HookTest ****************");
}


VOID Filter_NtCreateFile(IN POBJECT_ATTRIBUTES poaFileName)
{
	WCHAR wszFileName[1024] = { 0, };

	memcpy(wszFileName, poaFileName->ObjectName->Buffer, poaFileName->ObjectName->Length);
	LogWrite(LOG_INFO, L"%s", wszFileName);
}

UINT64 GetNtCreateFile()
{
	UINT64 NtCreateFile;
	UNICODE_STRING usFuncName;
	RtlInitUnicodeString(&usFuncName, L"NtCreateFile");
	NtCreateFile = MmGetSystemRoutineAddress(&usFuncName);
	Real_NtCreateFile = NtCreateFile + 7;

	return NtCreateFile;
}


NTSTATUS
DriverEntry(
	IN	PDRIVER_OBJECT	pDriverObject,
	IN	PUNICODE_STRING	puszRegistryPath
	)
{
	UCHAR HookPrefix;
	UINT64 NtCreateFile;
	HOOK_INFO HookInfo[2];

	HookInfo[0].pTargetFunction = OriginTest;
	HookInfo[0].pwszTargetName = L"OriginTest";
	HookInfo[0].pHookFunction = HookTest;

	NtCreateFile = GetNtCreateFile();
	HookInfo[1].pTargetFunction = NtCreateFile;
	HookInfo[1].pwszTargetName = L"NtCreateFile";
	HookInfo[1].pHookFunction = Hook_NtCreateFile;

	LogInitialize();

	if (FALSE == VmxInitialize())
	{
		goto CleanUp;
	}

	if (FALSE == SetHook(&HookInfo, 2))
	{
		goto CleanUp;
	}

	OriginTest();
	HookPrefix = *(CHAR*)((CHAR*)OriginTest);
	LogWrite(LOG_INFO, L"======================= OriginTest one byte prefix 0x%02x", HookPrefix);

	pDriverObject->DriverUnload = UnloadDriver;

	return STATUS_SUCCESS;

CleanUp:
	LogFinalize();
	return STATUS_UNSUCCESSFUL;
}