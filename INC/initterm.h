typedef void (__cdecl *_PVFV)(void);

#ifdef _PAGE_
#pragma comment(linker, "/merge:.CRT=PAGER")
#else
#pragma comment(linker, "/merge:.CRT=.rdata")
#endif

extern "C"
{
#pragma const_seg(".CRT$XCA")
	const _PVFV __xc_a = 0;
#pragma const_seg(".CRT$XCZ")
	const _PVFV __xc_z = 0;

#pragma const_seg(".CRT$XIA")
  const _PVFV __xi_a = 0;
#pragma const_seg(".CRT$XIZ")
  const _PVFV __xi_z = 0;

#pragma const_seg()

  void _initterm(const _PVFV *ppfn, const _PVFV *end)
  {
	  do 
	  {
		  if (_PVFV pfn = *ppfn++)
		  {
			  pfn();
		  }
	  } while (ppfn < end);
  }

  void initterm()
  {
	  _initterm(&__xi_a, &__xi_z);
	  _initterm(&__xc_a, &__xc_z);
  }

  SLIST_HEADER g__onexit;

  struct ONEXIT : SLIST_ENTRY 
  {
	   _PVFV func;
#ifdef _KERNEL_MODE
	   void operator delete(void* p)
	   {
		   ExFreePool(p);
	   }

	   void* operator new(size_t cb)
	   {
		   return ExAllocatePool(PagedPool, cb);
	   }
#endif
  };

  int __cdecl atexit(_PVFV func)
  {
	  if (ONEXIT* p = new ONEXIT)
	  {
		  p->func = func;
		  InterlockedPushEntrySList(&g__onexit, p);
		  return 0;
	  }
      
	  __debugbreak();
	  return -1;
  }

  void destroyterm()
  {
	  while (ONEXIT* p = static_cast<ONEXIT*>(InterlockedPopEntrySList(&g__onexit)))
	  {
		  p->func();
		  delete p;
	  }
  }
};
