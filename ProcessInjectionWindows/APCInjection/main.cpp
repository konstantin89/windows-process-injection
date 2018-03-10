#include <iostream>
#include "apc_injection.h"

/**
* @brief:  Example of findProcessByName() usage.
* @param:  procName - Process name. (for example: L"calc.exe")
* @return: void
*/
void findProcessByNameExample(PCWSTR  procName)
{
	std::vector<DWORD> tidVector;
	DWORD pid;

	findProcessByName(procName, pid, tidVector);

	std::wcout << procName << " contains " << tidVector.size() << " threads" << std::endl;
	for (auto tid : tidVector)
	{
		std::wcout << procName << " tid: " << tid << std::endl;
	}
}

/**
* @brief:  Run process from executable.
* @param:  aExecToRun - Full path of exe file.
* @return: true on succes, false otherwise.
*/
bool runExec(LPWSTR aExecToRun)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	int retVal = CreateProcess(NULL, aExecToRun, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!retVal)
	{
		std::wcout << L"[-] Failed to run exec: " << aExecToRun << std::endl;
		return false;
	}
	return true;
}

int main()
{
	//findProcessByNameExample(L"explorer.exe");

	wchar_t dllToInject[MAX_PATH] = { L"c:\\temp\\InjectedDll.dll" };
	wchar_t targetProcessExecFullPath[MAX_PATH] = { L"c:\\temp\\SleepingProc.exe"};
	wchar_t targetProcessName[MAX_PATH] = { L"SleepingProc.exe" };

	// Run process that will be injected with DLL.
	if (!runExec(targetProcessExecFullPath))
	{
		return -1;
	}

	injectDll(targetProcessName, dllToInject);

	return 0;
}