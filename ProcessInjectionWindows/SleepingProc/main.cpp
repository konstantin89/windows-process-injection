#include <Windows.h>
#include <iostream>

#define SECONDS_TO_SLEEP 30

int main()
{
	std::cout << "SleepingProc.exe - pid=" << GetCurrentProcessId() << std::endl;
	
	SleepEx(SECONDS_TO_SLEEP * 1000, TRUE);
	
}