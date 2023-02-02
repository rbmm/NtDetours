#pragma once

class __declspec(dllimport) __declspec(novtable) DIS
{
public:
	enum DIST{ arm, cee, ia64, mips, mips16, ppc, ppc2, shcompact, arm2, ia32, ia16, amd64, invalid };
	enum REGA{ eax,ecx,edx,ebx,esp,ebp,esi,edi };
	enum MEMREFT{  };
	enum TRMT{  };
	enum TRMTA {
		a_gen = 1,
		a_int = 2,
		a_div = 3,
		a_jmp_u_2 = 4,
		a_jmp_u_5 = 5,
		a_jmp_rm = 7,
		a_ret = 8,
		a_iret = 9,
		a_jmp_c_2=10,
		a_jmp_c_6=11,
		a_loop=12,
		a_jcx=13,
		a_call=15,
		a_call_rm=17 
	};
	enum OPA{  };
	enum OPREFT{  };

	virtual ~DIS() = 0;
	virtual unsigned __int64 AddrAddress(UINT_PTR) = 0;
	virtual unsigned __int64 AddrInstruction()const = 0;
	virtual unsigned __int64 AddrJumpTable() = 0;
	virtual unsigned __int64 AddrOperand(UINT_PTR) = 0;
	virtual unsigned __int64 AddrTarget(UINT_PTR) = 0;
	virtual UINT Cb()const = 0;
	virtual UINT CbAssemble(void *,size_t) = 0;
	virtual UINT CbDisassemble(unsigned __int64,void const *,size_t) = 0;
	virtual UINT CbJumpEntry() = 0;
	virtual UINT CbOperand(size_t) = 0;
	virtual UINT CcchFormatInstrStops(UINT_PTR *,size_t) = 0;
	virtual UINT CchFormatBytes(wchar_t *,size_t)const = 0;
	virtual UINT CchFormatBytesMax() = 0;
	virtual UINT Cinstruction()const = 0;
	virtual UINT Coperand()const = 0;
	virtual unsigned long DwModifiers() = 0;
	virtual bool FDecode(struct INSTRUCTION *,struct OPERAND *,UINT_PTR) = 0;
	virtual bool FEncode(unsigned __int64,struct INSTRUCTION const *,struct OPERAND const *,UINT_PTR,UINT_PTR) = 0;
	virtual void FormatAddr(void*,size_t) = 0;
	virtual void FormatInstr(void*) = 0;
	virtual bool FSelectInstruction(UINT_PTR) = 0;
	virtual bool FSetFormatInstrStops(UINT_PTR const *,UINT_PTR) = 0;
	virtual OPA Opa()const = 0;
	virtual OPREFT Opreft(UINT_PTR)const = 0;
	virtual TRMT Trmt()const = 0;
	virtual TRMTA Trmta()const = 0;

	static DIS * __stdcall PdisNew(DIST);
	DIST Dist()const; 
	void SetAddr64(bool);
	void * PvClientSet(void *);
	void * PvClient()const; 
	unsigned __int64 Addr()const; 

	size_t  CchFormatInstr(wchar_t *,size_t)const;
	size_t  CchFormatAddr(unsigned __int64,wchar_t *,size_t)const;

	unsigned __int64 (__stdcall* PfndwgetregSet(unsigned __int64 (__stdcall*)(DIS const *,REGA)))(DIS const *,REGA);
	size_t (__stdcall* PfncchregrelSet(size_t (__stdcall*)(DIS const *,REGA,unsigned long,wchar_t *,size_t,unsigned long *)))(DIS const *,REGA,unsigned long,wchar_t *,size_t,unsigned long *);
	size_t (__stdcall* PfncchregSet(size_t (__stdcall*)(DIS const *,REGA,wchar_t *,size_t)))(DIS const *,REGA,wchar_t *,size_t);
	size_t (__stdcall* PfncchfixupSet(size_t (__stdcall*)(DIS const *,unsigned __int64,size_t,wchar_t *,size_t,unsigned __int64 *)))(DIS const *,unsigned __int64,size_t,wchar_t *,size_t,unsigned __int64 *);
	size_t (__stdcall* PfncchaddrSet(size_t (__stdcall*)(DIS const *,unsigned __int64,wchar_t *,size_t,unsigned __int64 *)))(DIS const *,unsigned __int64,wchar_t *,size_t,unsigned __int64 *);
};
