
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