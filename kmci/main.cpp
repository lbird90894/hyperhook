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

#include <windows.h>
#include <stdio.h>

#define MAX_PATH 1024
#define CUSTOM_SIGN_ENABLE 1
#define CUSTOM_KERENL_SIGNER L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners"


#pragma pack(push, 1)
typedef struct _POLICY_HEADER
{
	DWORD TotalSize;
	DWORD DataSize;
	DWORD EndSize;
	DWORD Reserved1;
	DWORD Version;
} POLICY_HEADER, *PPOLICY_HEADER;


typedef struct _DATA_HEADER
{
	WORD TotalSize;
	WORD NameLength;
	WORD DataType;
	WORD DataSize;
	DWORD Flags;
	DWORD Reserved1;
} DATA_HEADER, *PDATA_HEADER;
#pragma pack(pop)


DWORD st_PolicySize;


BOOLEAN RegisterSetupMode()
{
	HKEY hKey = NULL;
	DWORD SetupType = 1;
	WCHAR wszPath[MAX_PATH];
	WCHAR wszCommand[MAX_PATH];
	BOOLEAN bSuccess = FALSE;

	if (0 == GetModuleFileNameW(NULL, wszPath, MAX_PATH))
	{
		goto CleanUp;
	}

	if (-1 == swprintf_s(wszCommand, L"\"%s\" \"boot\"", wszPath))
	{
		goto CleanUp;
	}

	if (ERROR_SUCCESS != RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", NULL, KEY_WRITE, &hKey))
	{
		goto CleanUp;
	}

	if (ERROR_SUCCESS != RegSetValueExW(hKey, L"CmdLine", NULL, REG_SZ, (const BYTE*)wszCommand, 2 * wcslen(wszCommand) + 2))
	{
		goto CleanUp;
	}

	if (ERROR_SUCCESS != RegSetValueExW(hKey, L"SetupType", NULL, REG_DWORD, (const BYTE*)&SetupType, sizeof(DWORD)))
	{
		goto CleanUp;
	}
	bSuccess = TRUE;

CleanUp:
	if (NULL != hKey)
	{
		RegCloseKey(hKey);
	}

	return bSuccess;
}


BOOLEAN UnRegisterSetupMode()
{
	HKEY hKey = NULL;
	DWORD SetupType = 1;
	WCHAR wszCommand[1] = { 0, };
	BOOLEAN bSuccess = FALSE;

	if (ERROR_SUCCESS != RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", NULL, KEY_WRITE, &hKey))
	{
		goto CleanUp;
	}

	if (ERROR_SUCCESS != RegSetValueExW(hKey, L"CmdLine", NULL, REG_SZ, (const BYTE*)wszCommand, 2))
	{
		goto CleanUp;
	}
	bSuccess = TRUE;

CleanUp:
	if (NULL != hKey)
	{
		RegCloseKey(hKey);
	}

	return bSuccess;
}


PDATA_HEADER GetNextBlock(IN PPOLICY_HEADER pPolicyHeader)
{
	static ULONG CurrentPos = 0;
	PDATA_HEADER pDataHeader = NULL;

	if (NULL == pPolicyHeader)
	{
		return NULL;
	}

	if (0 == CurrentPos)
	{
		pDataHeader = (PDATA_HEADER)((BYTE*)pPolicyHeader + sizeof(POLICY_HEADER));
		CurrentPos += sizeof(POLICY_HEADER);
		st_PolicySize = pPolicyHeader->TotalSize;
	}
	else if (CurrentPos + 1 > st_PolicySize)
	{
		return NULL;
	}
	else
	{
		pDataHeader = (PDATA_HEADER)((BYTE*)pPolicyHeader + CurrentPos);
		CurrentPos += pDataHeader->TotalSize;
	}

	return pDataHeader;
}


BOOLEAN GetValueName(IN PDATA_HEADER pDataHeader, OUT PWSTR pwszValueName, IN DWORD cchValueName, OUT PWORD pDataType)
{
	DWORD NameLength;

	if (NULL == pDataHeader || NULL == pwszValueName || NULL == pDataType)
	{
		return FALSE;
	}

	NameLength = pDataHeader->NameLength;
	if (NameLength + 2 > (cchValueName << 1))
	{
		return FALSE;
	}

	pwszValueName[NameLength >> 1] = 0;
	memcpy(pwszValueName, (PBYTE)pDataHeader + sizeof(DATA_HEADER), NameLength);
	*pDataType = pDataHeader->DataType;

	return TRUE;
}


BOOLEAN SetValueData(IN PDATA_HEADER pDataHeader, IN PBYTE pDataBuf, IN DWORD cbDataBuf, IN WORD DataType)
{
	PBYTE pData;

	pData = (PBYTE)pDataHeader;
	if (NULL == pData || NULL == pDataBuf)
	{
		return FALSE;
	}

	if (REG_DWORD != DataType || cbDataBuf < 4)
	{
		return FALSE;
	}

	*(PDWORD)(pData + sizeof(DATA_HEADER) + pDataHeader->NameLength) = *(PDWORD)pDataBuf;

	return TRUE;
}


BOOLEAN SetCustomCertificatePolicy()
{
	HKEY hKey;
	LSTATUS lStatus;
	DWORD ValueType, ValueSize;
	PBYTE pData = NULL;
	PDATA_HEADER pDataHeader;
	WCHAR wszValueName[MAX_PATH];
	WORD DataType;
	DWORD dwCustomSign = CUSTOM_SIGN_ENABLE;
	BOOLEAN bSuccess = FALSE;

	lStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
		NULL,
		KEY_READ | KEY_WRITE,
		&hKey);

	if (ERROR_SUCCESS != lStatus)
	{
		goto CleanUp;
	}

	lStatus = RegQueryValueExW(hKey, L"ProductPolicy", NULL, &ValueType, NULL, &ValueSize);
	if (ERROR_SUCCESS != lStatus || REG_BINARY != ValueType)
	{
		goto CleanUp;
	}

	pData = (PBYTE)malloc(ValueSize);
	if (NULL == pData)
	{
		goto CleanUp;
	}

	lStatus = RegQueryValueExW(hKey, L"ProductPolicy", NULL, &ValueType, pData, &ValueSize);
	if (ERROR_SUCCESS != lStatus || REG_BINARY != ValueType)
	{
		goto CleanUp;
	}

	while (TRUE)
	{
		pDataHeader = GetNextBlock((PPOLICY_HEADER)pData);
		if (NULL == pDataHeader)
		{
			break;
		}

		if (FALSE == GetValueName(pDataHeader, wszValueName, MAX_PATH, &DataType))
		{
			goto CleanUp;
		}

		if (0 == _wcsicmp(wszValueName, CUSTOM_KERENL_SIGNER) && REG_DWORD == DataType)
		{
			if (FALSE == SetValueData(pDataHeader, (PBYTE)&dwCustomSign, 4, REG_DWORD))
			{
				goto CleanUp;
			}

			lStatus = RegSetValueExW(hKey, L"ProductPolicy", NULL, REG_BINARY, pData, ValueSize);
			if (ERROR_SUCCESS != lStatus)
			{
				goto CleanUp;
			}

			bSuccess = TRUE;
			break;
		}
	}

CleanUp:
	if (NULL != pData)
	{
		free(pData);
	}
	if (NULL != hKey)
	{
		RegCloseKey(hKey);
	}

	return bSuccess;
}


BOOLEAN SetShutDownPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return FALSE;
	}

	if (FALSE == LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &TokenPrivileges.Privileges[0].Luid))
	{
		return FALSE;
	}

	if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, NULL, 0, NULL))
	{
		return FALSE;
	}

	return TRUE;
}


int wmain(int argc, PWSTR argv[])
{
	CHAR Buf[MAX_PATH];

	if (FALSE == SetShutDownPrivilege())
	{
		wprintf(L"set shutdown fail");
		goto CleanUp;
	}

	if (1 == argc)
	{
		if (FALSE == RegisterSetupMode())
		{
			wprintf(L"register setup mode fail\n");
			goto CleanUp;
		}
		else
		{
			wprintf(L"register setup mode success\n");
		}

		wprintf(L"reboot? [y/n] ");
		scanf_s("%s", Buf, MAX_PATH);
		if ('y' == Buf[0] || 'Y' == Buf[0])
		{
			if (FALSE == ExitWindowsEx(EWX_REBOOT, 0))
			{
				wprintf(L"reboot fail\n");
				goto CleanUp;
			}

			return 0;
		}
	}
	else if (0 == wcscmp(argv[1], L"boot"))
	{
		if (FALSE == SetCustomCertificatePolicy())
		{
			wprintf(L"set custom certivicate policy fail\n");
			goto CleanUp;
		}
		else
		{
			wprintf(L"set custom certivicate policy success\n");
			UnRegisterSetupMode();

			wprintf(L"rebooting ...\n");
			InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, TRUE, 0);
			Sleep(INFINITE);
		}
	}
	else
	{
		wprintf(L"command-line argument is wrong\n");
		goto CleanUp;
	}

CleanUp:
	system("PAUSE");
	return 0;
}
