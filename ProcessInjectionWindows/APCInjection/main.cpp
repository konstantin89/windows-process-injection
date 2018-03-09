#include <iostream>
#include "apc_injection.h"

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

int main()
{
	findProcessByNameExample(L"explorer.exe");


	return 0;
}