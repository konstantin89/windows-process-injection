#ifndef _APC_INJECTION_H
#define _APC_INJECTION_H

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>


/**
* @brief:
*
* @param: exeName - input. Name of process to find.
* @param: pid  - output. Pid of exeName process.
* @param: tids - output. Thread ids of exeName process.
*
* @return: On success - true. 
*          Otherwise - false.
*
*/
bool findProcessByName(PCWSTR exeName, DWORD& pid, std::vector<DWORD>& tids);



#endif