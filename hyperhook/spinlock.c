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

#include "spinlock.h"
#include "vminit.h"


#define MAX_WAIT 0x10000

inline BOOLEAN SpinlockTryLock(volatile LONG* Lock)
{
	return (!(*Lock) && !_interlockedbittestandset(Lock, 0));
}


VOID InitializeHostLock(volatile LONG* Lock)
{
	*Lock = 0;
}


VOID AcquireHostLock(volatile LONG* Lock)
{
	ULONG wait = 1;

	while (!SpinlockTryLock(Lock))
	{
		for (ULONG i = 0; i < wait; ++i)
		{
			_mm_pause();
		}

		if (wait * 2 > MAX_WAIT)
		{
			wait = MAX_WAIT;
		}
		else
		{
			wait = wait * 2;
		}
	}
}


VOID ReleaseHostLock(volatile LONG* Lock)
{
	*Lock = 0;
}
