#pragma once

#define RUNDOWN_INIT_VALUE 0x80000000
#define RUNDOWN_COMPLETE_VALUE 0
#define ObpBeginRundown(p) _interlockedbittestandreset(p, 31)
#define ObpUnlock _InterlockedDecrement

__inline BOOL ObpLock(PLONG pLock)
{
	LONG Value, NewValue;

	if (Value = *pLock)
	{
		do 
		{
			NewValue = _InterlockedCompareExchange(pLock, Value + 1, Value);

			if (NewValue == Value) return TRUE;

		} while (Value = NewValue);
	}

	return FALSE;
}

__inline BOOL ObpAcquireRundownProtection(PLONG pLock)
{
	LONG Value, NewValue;

	if (0 > (Value = *pLock))
	{
		do 
		{
			NewValue = _InterlockedCompareExchange(pLock, Value + 1, Value);

			if (NewValue == Value) return TRUE;

		} while (0 > (Value = NewValue));
	}

	return FALSE;
}
