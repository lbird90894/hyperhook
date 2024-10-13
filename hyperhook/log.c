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
#include "vmcall.h"
#include "lwstr.h"
#include "log.h"


/****************************************************************
					  Constant Definition
****************************************************************/
#define MILLI_SECOND			-10000LL

#define MAX_LOG_BUF_CCH			1024

#define MAX_REG_INFO			(1024 << 1)

#define MAX_LOG_ENTRY			1024

#define REG_LOG_CONFIG_KEY		L"\\REGISTRY\\MACHINE\\SYSTEM\\hyperhook"
#define REG_LOG_TYPE_VALUE		L"LogType"
#define REG_LOG_LEVEL_VALUE		L"LogLevel"
#define REG_LOG_PATH_VALUE		L"LogPath"
#define MAX_LOG_PATH			1024
#define UTF_16_BOM				L"\uFEFF"

#define MEM_TAG_LOG				'glyH'// Hylg


/****************************************************************
						Type Definition
****************************************************************/
typedef enum _LOG_TYPE
{
	LOG_PRINT = 1,
	LOG_WRITE,
	LOG_ALL,
} LOG_TYPE;

typedef struct _LOG_ENTRY
{
	LIST_ENTRY llNext;
	BOOLEAN bHost;
	WCHAR wszLogBuf[MAX_LOG_BUF_CCH];
} LOG_ENTRY, *PLOG_ENTRY;

typedef enum _LOG_STATUS
{
	LOG_START,
	LOG_STOP_PENDING,
	LOG_STOP,
} LOG_STATUS;


/****************************************************************
						Global Variable
****************************************************************/
extern ULONG g_VmxStatus;

static KEVENT st_PauseEvent;
static PVOID st_pThreadObject;
static BOOLEAN st_bLogDispatherRunning;
static BOOLEAN st_bLogInit = FALSE;
static ULONG st_LogStatus;
static ULONG st_LogLevel = LOG_NONE;
LIST_ENTRY g_LogWorkList, g_LogDispatchList, st_FreeLogList;
volatile LONG g_LogWorkListLock, st_LogFreeListLock;
static __declspec(align(8)) KGUARDED_MUTEX st_GuardedMutex;


/****************************************************************
					   Function Definition
****************************************************************/
static
PLOG_ENTRY AcquireLogEntry(IN BOOLEAN bHost, OUT PBOOLEAN pbLast)
{
	PLOG_ENTRY pLogEntry;

	if (NULL == pbLast)
	{
		return NULL;
	}

	*pbLast = FALSE;

	if (bHost)
	{
		AcquireHostLock(&st_LogFreeListLock);

		if (IsListEmpty(&st_FreeLogList))
		{
			ReleaseHostLock(&st_LogFreeListLock);
			return NULL;
		}

		pLogEntry = CONTAINING_RECORD(RemoveHeadList(&st_FreeLogList), LOG_ENTRY, llNext);

		if (IsListEmpty(&st_FreeLogList))
		{
			*pbLast = TRUE;
		}

		pLogEntry->bHost = TRUE;
		ReleaseHostLock(&st_LogFreeListLock);
	}
	else
	{
		pLogEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(LOG_ENTRY), MEM_TAG_LOG);
		if (pLogEntry)
		{
			pLogEntry->bHost = FALSE;
		}
	}

	return pLogEntry;
}


static
VOID ReleaseLogEntry(IN PLOG_ENTRY pLogEntry)
{
	if (NULL == pLogEntry)
	{
		return;
	}

	if (pLogEntry->bHost)
	{
		AcquireHostLock(&st_LogFreeListLock);
		InsertHeadList(&st_FreeLogList, &pLogEntry->llNext);
		ReleaseHostLock(&st_LogFreeListLock);
	}
	else
	{
		ExFreePool(pLogEntry);
	}
}


VOID LogWrite(IN LOG_LEVEL LogLevel, IN PCWCH pFormat, ...)
{
	va_list ArgList;
	ULONG RegLogLevel, cchLogBuf;
	PLOG_ENTRY pLogEntry;
	BOOLEAN bLaunched, bHost, bLast;
	LARGE_INTEGER SystemTime, LocalTime;
	TIME_FIELDS TimeFields;
	WCHAR *LogLevelTable[] = { NULL, L"ERROR", L"WARNING", L"INFO" };
	HOST_MSG_LOG_DATA HostSendLogData;

	if (FALSE == _InterlockedCompareExchange8(&st_bLogInit, 0, 0))
	{
		return;
	}

	RegLogLevel = InterlockedOr(&st_LogLevel, 0);

	if (RegLogLevel < LogLevel)
	{
		return;
	}

	KeQuerySystemTime(&SystemTime);
	ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &TimeFields);

	if (VMX_STOP_ALL == InterlockedCompareExchange(&g_VmxStatus, 0, 0))
	{
		bLaunched = FALSE;
		bHost = FALSE;
	}
	else if (GetCurrentVmState()->bHost)
	{
		bLaunched = TRUE;
		bHost = TRUE;
	}
	else
	{
		bLaunched = GetCurrentVmState()->bLaunched;
		bHost = FALSE;
	}

	pLogEntry = AcquireLogEntry(bHost, &bLast);

	if (NULL == pLogEntry)
	{
		return;
	}

	if (TRUE == bLast)
	{
		LightWcscpy(pLogEntry->wszLogBuf, MAX_LOG_BUF_CCH, L"Log buffer is full");
	}
	else
	{
		LightStringPrintfW(pLogEntry->wszLogBuf,
			MAX_LOG_BUF_CCH,
			L"%s,%d:%d:%d.%d,%d,%s,",
			bHost ? L"HOST" : L"GUEST",
			TimeFields.Hour,
			TimeFields.Minute,
			TimeFields.Second,
			TimeFields.Milliseconds,
			KeGetCurrentProcessorNumberEx(NULL),
			LogLevelTable[LogLevel]);

		cchLogBuf = LightWcslen(pLogEntry->wszLogBuf);

		va_start(ArgList, pFormat);
		LightStringVPrintfW(pLogEntry->wszLogBuf + cchLogBuf, MAX_LOG_BUF_CCH, pFormat, ArgList);
		va_end(ArgList);
	}

	if (FALSE == bLaunched)
	{
		KeAcquireGuardedMutex(&st_GuardedMutex);
		InsertTailList(&g_LogWorkList, &pLogEntry->llNext);
		KeReleaseGuardedMutex(&st_GuardedMutex);
	}
	else if (bHost)
	{
		AcquireHostLock(&g_LogWorkListLock);
		InsertTailList(&g_LogWorkList, &pLogEntry->llNext);
		ReleaseHostLock(&g_LogWorkListLock);
	}
	else
	{
		HostSendLogData.pListEntry = &pLogEntry->llNext;
		HostSendMessage(HOST_MSG_ID_LOG, &HostSendLogData);
	}
}


static
BOOLEAN UpdateLogConfig(OUT OPTIONAL PULONG pulLogType, OUT OPTIONAL PCWSTR pszFilePath)
{
	NTSTATUS ntStatus;
	BOOLEAN bRet = FALSE;
	HANDLE hKey = NULL;
	UNICODE_STRING usLogRegKey, usLogType, usLogLevel, usLogPath;
	OBJECT_ATTRIBUTES objectAttributes;
	PKEY_VALUE_PARTIAL_INFORMATION pLogRegValueInfo;
	ULONG LogType, LogLevel, ulInfoSize;

	RtlInitUnicodeString(&usLogRegKey, REG_LOG_CONFIG_KEY);
	RtlInitUnicodeString(&usLogType, REG_LOG_TYPE_VALUE);
	RtlInitUnicodeString(&usLogLevel, REG_LOG_LEVEL_VALUE);
	RtlInitUnicodeString(&usLogPath, REG_LOG_PATH_VALUE);
	InitializeObjectAttributes(&objectAttributes, &usLogRegKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	pLogRegValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, MAX_REG_INFO, MEM_TAG_LOG);
	if (NULL == pLogRegValueInfo)
	{
		goto CleanUp;
	}

	ntStatus = ZwOpenKey(&hKey, KEY_READ, &objectAttributes);
	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}

	ntStatus = ZwQueryValueKey(hKey, &usLogType, KeyValuePartialInformation, pLogRegValueInfo, MAX_REG_INFO, &ulInfoSize);
	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}
	if (REG_DWORD != pLogRegValueInfo->Type)
	{
		goto CleanUp;
	}

	LogType = *(ULONG*)pLogRegValueInfo->Data;
	if (LOG_PRINT != LogType && LOG_WRITE != LogType && LOG_ALL != LogType)
	{
		goto CleanUp;
	}

	ntStatus = ZwQueryValueKey(hKey, &usLogLevel, KeyValuePartialInformation, pLogRegValueInfo, MAX_REG_INFO, &ulInfoSize);
	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}
	if (REG_DWORD != pLogRegValueInfo->Type)
	{
		goto CleanUp;
	}

	LogLevel = *(ULONG*)pLogRegValueInfo->Data;
	if (LOG_ERROR != LogLevel && LOG_WARNING != LogLevel && LOG_INFO != LogLevel)
	{
		goto CleanUp;
	}

	ntStatus = ZwQueryValueKey(hKey, &usLogPath, KeyValuePartialInformation, pLogRegValueInfo, MAX_REG_INFO, &ulInfoSize);
	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}
	if (REG_SZ != pLogRegValueInfo->Type)
	{
		goto CleanUp;
	}

	if (NULL != pulLogType)
	{
		*pulLogType = LogType;
	}

	if (NULL != pszFilePath)
	{
		RtlCopyBytes(pszFilePath, pLogRegValueInfo->Data, pLogRegValueInfo->DataLength);
	}

	InterlockedExchange(&st_LogLevel, LogLevel);
	bRet = TRUE;

CleanUp:
	if (NULL != pLogRegValueInfo)
	{
		ExFreePool(pLogRegValueInfo);
	}
	if (NULL != hKey)
	{
		ZwClose(hKey);
	}

	return bRet;
}


static
VOID LogFlush(IN LOG_TYPE LogType, IN OPTIONAL PCWSTR pwszFilePath)
{
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	HANDLE hFile = NULL;
	UNICODE_STRING usFilePath;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInfo;
	WCHAR wszFilePath[MAX_LOG_PATH];

	PLOG_ENTRY pLogEntry;
	PLIST_ENTRY pListEntry;

	if (IsListEmpty(&g_LogDispatchList))
	{
		li.QuadPart = 10 * MILLI_SECOND;
		KeDelayExecutionThread(KernelMode, FALSE, &li);
		return;
	}

	if (LOG_PRINT == LogType)
	{
		while (FALSE == IsListEmpty(&g_LogDispatchList))
		{
			pListEntry = RemoveHeadList(&g_LogDispatchList);
			pLogEntry = CONTAINING_RECORD(pListEntry, LOG_ENTRY, llNext);

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%ws\n", pLogEntry->wszLogBuf);
			ReleaseLogEntry(pLogEntry);
		}

		return;
	}

	if (NULL == pwszFilePath)
	{
		goto CleanUp;
	}

	wcscpy(wszFilePath, L"\\??\\");
	wcscat(wszFilePath, pwszFilePath);
	RtlInitUnicodeString(&usFilePath, wszFilePath);
	InitializeObjectAttributes(&objectAttributes, &usFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = ZwCreateFile(&hFile,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&objectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}

	ntStatus = ZwQueryInformationFile(hFile, &IoStatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
	if (STATUS_SUCCESS != ntStatus)
	{
		goto CleanUp;
	}

	// BOM for new file
	if (0 == FileInfo.EndOfFile.QuadPart)
	{
		ntStatus = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, UTF_16_BOM, 2 * wcslen(UTF_16_BOM), NULL, NULL);
		if (STATUS_SUCCESS != ntStatus)
		{
			goto CleanUp;
		}
	}

	while (FALSE == IsListEmpty(&g_LogDispatchList))
	{
		pListEntry = RemoveHeadList(&g_LogDispatchList);
		pLogEntry = CONTAINING_RECORD(pListEntry, LOG_ENTRY, llNext);

		if (LOG_ALL == LogType)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%ws\n", pLogEntry->wszLogBuf);
		}

		wcscat(pLogEntry->wszLogBuf, L"\r\n");
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pLogEntry->wszLogBuf, 2 * wcslen(pLogEntry->wszLogBuf), NULL, NULL);

		ReleaseLogEntry(pLogEntry);
	}

	ZwClose(hFile);

	return;

CleanUp:
	if (NULL != hFile)
	{
		ZwClose(hFile);
	}
	while (FALSE == IsListEmpty(&g_LogDispatchList))
	{
		pListEntry = RemoveHeadList(&g_LogDispatchList);
		pLogEntry = CONTAINING_RECORD(pListEntry, LOG_ENTRY, llNext);
		ReleaseLogEntry(pLogEntry);
	}
}


static
VOID LogDispather(IN PVOID pContext)
{
	ULONG LogType;
	HOST_MSG_LOG_DATA HostSendLogData = { 0, };
	WCHAR wszFilePath[MAX_LOG_PATH];
	ULONG VmxStatus;

	UNREFERENCED_PARAMETER(pContext);

	while (TRUE == _InterlockedCompareExchange8(&st_bLogDispatherRunning, 0, 0))
	{
		if (LOG_STOP_PENDING == InterlockedCompareExchange(&st_LogStatus, 0, 0))
		{
			InterlockedExchange(&st_LogStatus, LOG_STOP);
			KeWaitForSingleObject(&st_PauseEvent, Executive, KernelMode, FALSE, NULL);
			KeClearEvent(&st_PauseEvent);
		}

		if (FALSE == UpdateLogConfig(&LogType, wszFilePath))
		{
			continue;
		}

		VmxStatus = InterlockedCompareExchange(&g_VmxStatus, 0, 0);

		if (VMX_STOP_ALL == VmxStatus)
		{
			KeAcquireGuardedMutex(&st_GuardedMutex);

			g_LogDispatchList.Flink = g_LogWorkList.Flink;
			g_LogDispatchList.Blink = g_LogWorkList.Blink;
			g_LogWorkList.Flink->Blink = &g_LogDispatchList;
			g_LogWorkList.Blink->Flink = &g_LogDispatchList;
			InitializeListHead(&g_LogWorkList);

			KeReleaseGuardedMutex(&st_GuardedMutex);

			LogFlush(LogType, (LOG_PRINT == LogType) ? NULL : wszFilePath);
		}
		else if (VMX_START_ALL == VmxStatus)
		{
			HostSendMessage(HOST_MSG_ID_LOG, &HostSendLogData);
			LogFlush(LogType, (LOG_PRINT == LogType) ? NULL : wszFilePath);
		}
	}

	InterlockedExchange(&st_LogLevel, LOG_NONE);
}


static
BOOLEAN InitializeFreeLogList()
{
	PLOG_ENTRY pLogEntry;

	InitializeListHead(&st_FreeLogList);
	for (ULONG i = 0; i < MAX_LOG_ENTRY; ++i)
	{
		pLogEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(LOG_ENTRY), MEM_TAG_LOG);
		if (NULL == pLogEntry)
		{
			for (ULONG j = 0; j < i; ++j)
			{
				pLogEntry = RemoveHeadList(&st_FreeLogList);
				ExFreePool(pLogEntry);
			}
			return FALSE;
		}

		InsertTailList(&st_FreeLogList, &pLogEntry->llNext);
	}

	return TRUE;
}


static
VOID DestroyFreeLogList()
{
	PLOG_ENTRY pLogEntry;

	while (FALSE == IsListEmpty(&st_FreeLogList))
	{
		pLogEntry = RemoveHeadList(&st_FreeLogList);
		ExFreePool(pLogEntry);
	}
}


BOOLEAN LogInitialize()
{
	NTSTATUS ntStatus;
	HANDLE hThread;
	OBJECT_ATTRIBUTES ObjectAttributes;

	KeInitializeEvent(&st_PauseEvent, NotificationEvent, FALSE);
	KeInitializeGuardedMutex(&st_GuardedMutex);

	InitializeHostLock(&st_LogFreeListLock);
	InitializeHostLock(&g_LogWorkListLock);

	InitializeListHead(&g_LogWorkList);
	InitializeListHead(&g_LogDispatchList);

	if (FALSE == InitializeFreeLogList())
	{
		return FALSE;
	}

	InterlockedExchange(&st_bLogDispatherRunning, TRUE);
	InterlockedExchange(&st_LogStatus, LOG_START);

	// worker thread
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, LogDispather, NULL);
	if (STATUS_SUCCESS != ntStatus)
	{
		InterlockedExchange(&st_bLogDispatherRunning, FALSE);
		DestroyFreeLogList();
		return FALSE;
	}

	UpdateLogConfig(NULL, NULL);

	ntStatus = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &st_pThreadObject, NULL);
	if (STATUS_SUCCESS != ntStatus)
	{
		InterlockedExchange(&st_bLogDispatherRunning, FALSE);
		DestroyFreeLogList();
		return FALSE;
	}

	ZwClose(hThread);

	InterlockedExchange(&st_bLogInit, TRUE);
	return TRUE;
}


VOID LogFinalize()
{
	InterlockedExchange(&st_bLogInit, FALSE);
	InterlockedExchange(&st_bLogDispatherRunning, FALSE);

	if (NULL != st_pThreadObject)
	{
		KeWaitForSingleObject(st_pThreadObject, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(st_pThreadObject);
	}

	DestroyFreeLogList();
}


BOOLEAN IsLogInit()
{
	return _InterlockedCompareExchange8(&st_bLogInit, 0, 0);
}


BOOLEAN LogPause()
{
	if (FALSE == IsLogInit())
	{
		return FALSE;
	}

	InterlockedExchange(&st_LogStatus, LOG_STOP_PENDING);
	while (TRUE)
	{
		if (LOG_STOP == InterlockedCompareExchange(&st_LogStatus, 0, 0))
		{
			break;
		}
	}

	return TRUE;
}


BOOLEAN LogRestart()
{
	if (FALSE == IsLogInit())
	{
		return FALSE;
	}

	InterlockedExchange(&st_LogStatus, LOG_START);
	KeSetEvent(&st_PauseEvent, 0, FALSE);

	return TRUE;
}