
using DWORD = unsigned long;
using ULONG_PTR = unsigned long;
using LONG = long;
using TCHAR = wchar_t;

#define MAX_PATH 260

typedef struct tagPROCESSENTRY32 {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	TCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32, *PPROCESSENTRY32;

