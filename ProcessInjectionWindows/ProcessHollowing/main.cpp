#include <Windows.h>
#include <iostream>
#include "process_hollowing.h"


int main()
{
	wchar_t injectedFileFullPath[MAX_PATH] = { L"C:\\temp\\InjectedProc.exe" };
	wchar_t calculatorExecFullPath[MAX_PATH] = { L"C:\\windows\\system32\\calc.exe" };

	/*
	* Example of process hollowing technique.
	* Injection our executable in to windows calculator.
	*/
	return injectProc(injectedFileFullPath, calculatorExecFullPath);
}