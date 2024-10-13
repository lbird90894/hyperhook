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

#include "lwstr.h"


#define MAX_NUMERIC_CCH 32

/****************************************************************
						Type Definition
****************************************************************/
typedef enum _FORMAT_TYPE
{
	FORMAT_NONE,
	FORMAT_C,
	FORMAT_S,
	FORMAT_D,
	FORMAT_LLD,
	FORMAT_X_LOWER,
	FORMAT_X_UPPER,
	FORMAT_LLX_LOWER,
	FORMAT_LLX_UPPER,
} FORMAT_TYPE;

typedef struct _SINGLE_FORMAT_INFO
{
	FORMAT_TYPE FormatType;
	ULONG FormatData;
	BOOLEAN bSpace;
} SINGLE_FORMAT_INFO, *PSINGLE_FORMAT_INFO;


/****************************************************************
					   Function Definition
****************************************************************/
ULONG LightWcslen(IN PCWSTR pwszBuf)
{
	ULONG i = 0;

	if (NULL == pwszBuf)
	{
		return 0;
	}

	while (TRUE)
	{
		if (0 == pwszBuf[i])
		{
			break;
		}

		++i;
	}

	return i;
}


BOOLEAN LightWcscpy(IN PWSTR Des, IN ULONG cchDes, IN PCWSTR Src)
{
	ULONG SrcLen;

	SrcLen = LightWcslen(Src);
	if (cchDes < SrcLen + 1)
	{
		return FALSE;
	}

	Des[SrcLen] = 0;
	for (ULONG i = 0; i < SrcLen; ++i)
	{
		Des[i] = Src[i];
	}

	return TRUE;
}


static
BOOLEAN IsPrefixString(IN PCWSTR FullStr, IN PCWSTR PrefixStr)
{
	ULONG FullStrLen, PrefixStrLen;

	if (NULL == FullStr || NULL == PrefixStr)
	{
		return FALSE;
	}

	FullStrLen = LightWcslen(FullStr);
	PrefixStrLen = LightWcslen(PrefixStr);

	if (FullStrLen < PrefixStrLen)
	{
		return FALSE;
	}

	for (ULONG i = 0; i < PrefixStrLen; ++i)
	{
		if (FullStr[i] != PrefixStr[i])
		{
			return FALSE;
		}
	}

	return TRUE;
}


static
BOOLEAN NumericToString(
	IN ULONG Base,
	IN UINT64 Numeric,
	OUT PWSTR pwszData,
	IN ULONG cchData,
	IN BOOLEAN bUpperCase
)
{
	WCHAR HexLowerTable[16] = { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9',
							L'a', L'b', L'c', L'd', L'e', L'f' };
	WCHAR HexUpperTable[16] = { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9',
							L'A', L'B', L'C', L'D', L'E', L'F' };

	PWCHAR HexTable = bUpperCase ? HexUpperTable : HexLowerTable;

	int ReverseDigit[MAX_NUMERIC_CCH];
	int FowardIndex = 0, ReverseIndex = 0;

	if (0 == Base || NULL == pwszData)
	{
		return FALSE;
	}

	do
	{
		ReverseDigit[ReverseIndex] = Numeric % Base;
		Numeric /= Base;
		++ReverseIndex;
	} while (0 != Numeric);

	if (cchData < ReverseIndex + 1)// size including NULL terminate
	{
		return FALSE;
	}

	pwszData[ReverseIndex] = 0;

	for (LONG i = ReverseIndex - 1; i >= 0; --i)
	{
		pwszData[FowardIndex] = HexTable[ReverseDigit[i]];
		++FowardIndex;
	}

	return TRUE;
}


static
BOOLEAN NumericPrintfW(IN FORMAT_TYPE Format, IN UINT64 ullNumeric, OUT PWSTR pwszData, IN ULONG cchData)
{
	BOOLEAN bSuccess = FALSE;
	ULONG ulNumeric = ullNumeric;

	if (NULL == pwszData)
	{
		return FALSE;
	}

	if (FORMAT_D == Format)
	{
		if ((1UL << 31) <= ulNumeric)// negative number
		{
			pwszData[0] = L'-';
			bSuccess = NumericToString(10, ~ulNumeric + 1, pwszData + 1, cchData - 1, FALSE);
		}
		else
		{
			bSuccess = NumericToString(10, ulNumeric, pwszData, cchData, FALSE);
		}
	}
	else if (FORMAT_LLD == Format)
	{
		if ((1LL << 63) <= ullNumeric)// negative number
		{
			pwszData[0] = L'-';
			bSuccess = NumericToString(10, ~ullNumeric + 1, pwszData + 1, cchData - 1, FALSE);
		}
		else
		{
			bSuccess = NumericToString(10, ullNumeric, pwszData, cchData, FALSE);
		}
	}
	else if (FORMAT_X_LOWER == Format)
	{
		if ((1UL << 31) <= ulNumeric)// negative number
		{
			pwszData[0] = L'-';
			bSuccess = NumericToString(16, ~ulNumeric + 1, pwszData + 1, cchData - 1, FALSE);
		}
		else
		{
			bSuccess = NumericToString(16, ulNumeric, pwszData, cchData, FALSE);
		}
	}
	else if (FORMAT_X_UPPER == Format)
	{
		if ((1UL << 31) <= ulNumeric)// negative number
		{
			pwszData[0] = L'-';
			bSuccess = NumericToString(16, ~ulNumeric + 1, pwszData + 1, cchData - 1, TRUE);
		}
		else
		{
			bSuccess = NumericToString(16, ulNumeric, pwszData, cchData, TRUE);
		}
	}
	else if (FORMAT_LLX_LOWER == Format)
	{
		bSuccess = NumericToString(16, ullNumeric, pwszData, cchData, FALSE);
	}
	else if (FORMAT_LLX_UPPER == Format)
	{
		bSuccess = NumericToString(16, ullNumeric, pwszData, cchData, TRUE);
	}

	return bSuccess;
}


static
BOOLEAN IsNumericFormat(IN FORMAT_TYPE FormatType)
{
	if (FORMAT_D == FormatType || FORMAT_LLD == FormatType ||
		FORMAT_X_LOWER == FormatType || FORMAT_X_UPPER == FormatType ||
		FORMAT_LLX_LOWER == FormatType || FORMAT_LLX_UPPER == FormatType)
	{
		return TRUE;
	}

	return FALSE;
}


static
BOOLEAN GetNumericData(IN PCWSTR pwszFormat, OUT FORMAT_TYPE* pFormatType, OUT PULONG pFormatLength)
{
	BOOLEAN bNumericData = FALSE;

	if (NULL == pwszFormat || NULL == pFormatType || NULL == pFormatLength)
	{
		return FALSE;
	}

	if (IsPrefixString(pwszFormat, L"d"))
	{
		*pFormatType = FORMAT_D;
		*pFormatLength = 1;
		bNumericData = TRUE;
	}
	else if (IsPrefixString(pwszFormat, L"lld"))
	{
		*pFormatType = FORMAT_LLD;
		*pFormatLength = 3;
		bNumericData = TRUE;
	}
	else if (IsPrefixString(pwszFormat, L"x"))
	{
		*pFormatType = FORMAT_X_LOWER;
		*pFormatLength = 1;
		bNumericData = TRUE;
	}
	else if (IsPrefixString(pwszFormat, L"X"))
	{
		*pFormatType = FORMAT_X_UPPER;
		*pFormatLength = 1;
		bNumericData = TRUE;
	}
	else if (IsPrefixString(pwszFormat, L"llx"))
	{
		*pFormatType = FORMAT_LLX_LOWER;
		*pFormatLength = 3;
		bNumericData = TRUE;
	}
	else if (IsPrefixString(pwszFormat, L"llX"))
	{
		*pFormatType = FORMAT_LLX_UPPER;
		*pFormatLength = 3;
		bNumericData = TRUE;
	}

	return bNumericData;
}


static
BOOLEAN GetFormatData(
	IN PCWSTR pwszFormat,
	IN ULONG FormatLen,
	IN PSINGLE_FORMAT_INFO pSingleFormatInfo,
	IN OUT PULONG pCurrentFormatPos
)
{
	ULONG ulCurrentPos;
	ULONG AlignSize = 0;
	ULONG FormatLength;
	FORMAT_TYPE FormatType;

	if (NULL == pwszFormat || NULL == pSingleFormatInfo || NULL == pCurrentFormatPos)
	{
		return FALSE;
	}

	ulCurrentPos = *pCurrentFormatPos;
	if (ulCurrentPos >= FormatLen)
	{
		return FALSE;
	}

	if (L'%' == pwszFormat[ulCurrentPos])
	{
		++ulCurrentPos;// None overflow since ulCurrnetPos is not NULL Terminator
		if (L'%' == pwszFormat[ulCurrentPos])
		{
			pSingleFormatInfo->FormatType = FORMAT_NONE;
			pSingleFormatInfo->FormatData = pwszFormat[ulCurrentPos];
			++ulCurrentPos;
		}
		else if (L'c' == pwszFormat[ulCurrentPos])
		{
			pSingleFormatInfo->FormatType = FORMAT_C;
			++ulCurrentPos;
		}
		else if (L's' == pwszFormat[ulCurrentPos])
		{
			pSingleFormatInfo->FormatType = FORMAT_S;
			++ulCurrentPos;
		}
		else if (GetNumericData(&pwszFormat[ulCurrentPos], &FormatType, &FormatLength))
		{
			pSingleFormatInfo->FormatType = FormatType;
			pSingleFormatInfo->FormatData = 0;// case not alignment format like %03d, %3d
			ulCurrentPos += FormatLength;
		}
		else if (L'0' <= pwszFormat[ulCurrentPos] && pwszFormat[ulCurrentPos] <= L'9')
		{
			if (L'0' == pwszFormat[ulCurrentPos])
			{
				pSingleFormatInfo->bSpace = FALSE;
				++ulCurrentPos;
			}
			else
			{
				pSingleFormatInfo->bSpace = TRUE;
			}

			while (L'0' <= pwszFormat[ulCurrentPos] && pwszFormat[ulCurrentPos] <= L'9')
			{
				AlignSize = AlignSize * 10 + (pwszFormat[ulCurrentPos] - L'0');
				++ulCurrentPos;
			}

			if (FALSE == GetNumericData(&pwszFormat[ulCurrentPos], &FormatType, &FormatLength))
			{
				return FALSE;
			}

			pSingleFormatInfo->FormatType = FormatType;
			pSingleFormatInfo->FormatData = AlignSize;
			ulCurrentPos += FormatLength;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		pSingleFormatInfo->FormatType = FORMAT_NONE;
		pSingleFormatInfo->FormatData = pwszFormat[ulCurrentPos];
		++ulCurrentPos;
	}

	*pCurrentFormatPos = ulCurrentPos;

	return TRUE;
}


BOOLEAN LightStringVPrintfW(OUT PWSTR pwszBuf, IN ULONG cchBuf, IN PCWSTR pwszFormat, IN va_list ArgList)
{
	va_list CurrentArg;
	SINGLE_FORMAT_INFO SingleFormatInfo;
	ULONG CurrentBufLen, cchRemainBuf, FormatData, FormatLen, CurrentFormatPos;
	FORMAT_TYPE FormatType;

	if (NULL == pwszBuf || NULL == pwszFormat || NULL == ArgList)
	{
		return FALSE;
	}

	CurrentArg = ArgList;
	FormatLen = LightWcslen(pwszFormat);
	pwszBuf[0] = 0;// LightWcslen(pwszBuf) = 0 
	CurrentFormatPos = 0;

	while (TRUE == GetFormatData(pwszFormat, FormatLen, &SingleFormatInfo, &CurrentFormatPos))
	{
		CurrentBufLen = LightWcslen(pwszBuf);
		cchRemainBuf = cchBuf - CurrentBufLen;

		FormatType = SingleFormatInfo.FormatType;
		FormatData = SingleFormatInfo.FormatData;

		if (FORMAT_NONE == FormatType)
		{
			WCHAR wszData[2] = { 0, };
			wszData[0] = FormatData;
			if (FALSE == LightWcscpy(pwszBuf + CurrentBufLen, cchRemainBuf, wszData))
			{
				return FALSE;
			}
		}
		else if (FORMAT_C == FormatType)
		{
			WCHAR wszData[2] = { 0, };
			wszData[0] = *(PCHAR*)CurrentArg;
			if (FALSE == LightWcscpy(pwszBuf + CurrentBufLen, cchRemainBuf, wszData))
			{
				return FALSE;
			}

			CurrentArg += 8;
		}
		else if (FORMAT_S == FormatType)
		{
			if (FALSE == LightWcscpy(pwszBuf + CurrentBufLen, cchRemainBuf, *(PCWSTR*)CurrentArg))
			{
				return FALSE;
			}

			CurrentArg += 8;
		}
		else if (IsNumericFormat(FormatType))
		{
			if (0 == FormatData)// case not alignment format like %03d, %3d
			{
				if (FALSE == NumericPrintfW(FormatType, *(UINT64*)CurrentArg, pwszBuf + CurrentBufLen, cchRemainBuf))
				{
					return FALSE;
				}
			}
			else
			{
				WCHAR AlignChar;
				ULONG NumericDataLen;
				WCHAR wszNumericBuf[MAX_NUMERIC_CCH];

				AlignChar = SingleFormatInfo.bSpace ? L' ' : L'0';
				if (FALSE == NumericPrintfW(FormatType, *(UINT64*)CurrentArg, wszNumericBuf, MAX_NUMERIC_CCH))
				{
					return FALSE;
				}

				NumericDataLen = LightWcslen(wszNumericBuf);
				if (cchRemainBuf < (FormatData + 1) || cchRemainBuf < (NumericDataLen + 1))
				{
					return FALSE;
				}

				for (ULONG i = 0; i < FormatData; ++i)
				{
					pwszBuf[CurrentBufLen + i] = AlignChar;
				}

				if (FormatData < NumericDataLen)
				{
					if (FALSE == LightWcscpy(pwszBuf + CurrentBufLen, cchRemainBuf, wszNumericBuf))
					{
						return FALSE;
					}
				}
				else
				{
					if (FALSE == LightWcscpy(pwszBuf + CurrentBufLen + FormatData - NumericDataLen, cchRemainBuf, wszNumericBuf))
					{
						return FALSE;
					}
				}
			}

			CurrentArg += 8;
		}
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}


BOOLEAN LightStringPrintfW(OUT PWSTR pwszBuf, IN ULONG cchBuf, IN PCWSTR pwszFormat, ...)
{
	BOOLEAN bSuccess;
	va_list ArgList;

	va_start(ArgList, pwszFormat);
	bSuccess = LightStringVPrintfW(pwszBuf, cchBuf, pwszFormat, ArgList);
	va_end(ArgList);

	return bSuccess;
}