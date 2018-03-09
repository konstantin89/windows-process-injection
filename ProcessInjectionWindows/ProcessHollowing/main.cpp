#include "process_hollowing.h"

int main()
{
	std::wstring calculatorExec(L"C:\\windows\\system32\\calc.exe");
	std::wstring enjectedProc(L"C:\\temp\\InjectedProc.exe");

	return injectProc(enjectedProc, calculatorExec);
}