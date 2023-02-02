#pragma once

struct _RTL_FRAME : TEB_ACTIVE_FRAME 
{
	_RTL_FRAME(const TEB_ACTIVE_FRAME_CONTEXT* ctx)
	{
		Context = ctx;
		Flags = 0;
		RtlPushFrame(this);
	}

	~_RTL_FRAME()
	{
		RtlPopFrame(this);
	}

	static TEB_ACTIVE_FRAME* get(const TEB_ACTIVE_FRAME_CONTEXT* ctx)
	{
		if (TEB_ACTIVE_FRAME* prf = RtlGetFrame())
		{
			do 
			{
				if (prf->Context == ctx) return prf;
			} while (prf = prf->Previous);
		}

		return 0;
	}
};

template<typename C> struct RTL_FRAME : public _RTL_FRAME, public C 
{
	static const TEB_ACTIVE_FRAME_CONTEXT* getContext()
	{
		static const TEB_ACTIVE_FRAME_CONTEXT s = { 0, __FUNCDNAME__ };
		return &s;
	}

	RTL_FRAME() : _RTL_FRAME(getContext())
	{
	}

	static C* get()
	{
		return static_cast<RTL_FRAME*>(_RTL_FRAME::get(getContext()));
	}
};
