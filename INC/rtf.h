typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,  
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR, 
	UWOP_SAVE_XMM, 
	UWOP_SAVE_XMM_FAR, 
	UWOP_SAVE_XMM128, 
	UWOP_SAVE_XMM128_FAR, 
	UWOP_PUSH_MACHFRAME   
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo   : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

//#define UNW_FLAG_EHANDLER  0x01
//#define UNW_FLAG_UHANDLER  0x02
//#define UNW_FLAG_CHAININFO 0x04

typedef struct _UNWIND_INFO {
	BYTE Version       : 3;
	BYTE Flags         : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset   : 4;
	UNWIND_CODE UnwindCode[1];
	/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
	*   union {
	*       OPTIONAL ULONG ExceptionHandler;
	*       OPTIONAL ULONG FunctionEntry;
	*   };
	*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#define GetUnwindCodeEntry(info, index) ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetChainedFunctionEntry(info) ((PRUNTIME_FUNCTION)GetLanguageSpecificDataPtr(info))

#define GetExceptionHandler(base, info) ((PEXCEPTION_HANDLER)((ULONG_PTR)(base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) ((PSCOPE_TABLE_AMD64)((PULONG)GetLanguageSpecificDataPtr(info) + 1))

#define UNWIND_HISTORY_TABLE_SIZE 12

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct DISPATCHER_CONTEXT *PDISPATCHER_CONTEXT;

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_HANDLER) (
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PVOID EstablisherFrame,
	IN OUT PCONTEXT ContextRecord,
	IN OUT PDISPATCHER_CONTEXT DispatcherContext
	);

typedef struct SCOPE_RECORD
{
	DWORD BeginAddress;
	DWORD EndAddress;
	DWORD HandlerAddress;
	DWORD JumpTarget;
} * PSCOPE_RECORD;