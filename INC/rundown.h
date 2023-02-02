#pragma once

#include "mini_yvals.h"

class RundownProtection
{
	LONG _Value;

public:

	enum {
		v_complete = 0, v_init = 0x80000000
	};

	_NODISCARD BOOL IsRundownBegin()
	{
		return 0 <= _Value;
	}

	_NODISCARD BOOL Acquire()
	{
		LONG Value, NewValue;

		if (0 > (Value = _Value))
		{
			do 
			{
				NewValue = InterlockedCompareExchangeNoFence(&_Value, Value + 1, Value);

				if (NewValue == Value) return TRUE;

			} while (0 > (Value = NewValue));
		}

		return FALSE;
	}

	_NODISCARD BOOL Release()
	{
		return InterlockedDecrement(&_Value) == v_complete;
	}

	// if (Acquire()) { Rundown_l(); Release(); }
	void Rundown_l()
	{
		InterlockedBitTestAndReset(&_Value, 31);
	}

	RundownProtection(LONG Value = v_complete) : _Value(Value)
	{
	}

	BOOL Init()
	{
		return InterlockedCompareExchange(&_Value, v_init, v_complete) == v_complete;
	}
};

class __declspec(novtable) RUNDOWN_REF : public RundownProtection
{
protected:

	virtual void RundownCompleted() = 0;

public:

	void BeginRundown()
	{
		if (Acquire())
		{
			Rundown_l();
			Release();
		}
	}

	void Release()
	{
		if (RundownProtection::Release())
		{
			RundownCompleted();
		}
	}

	RUNDOWN_REF(LONG Value = RundownProtection::v_init) : RundownProtection(Value) {}
};

//  */<memory>*/ bool _Ref_count_base::_Incref_nz()
// increment (*pLock) if not zero, return true if successful
inline _NODISCARD BOOL ObpLock(PLONG pLock)
{
	LONG Value, NewValue;

	if (Value = *pLock)
	{
		do 
		{
			NewValue = InterlockedCompareExchangeNoFence(pLock, Value + 1, Value);

			if (NewValue == Value) return TRUE;

		} while (Value = NewValue);
	}

	return FALSE;
}
