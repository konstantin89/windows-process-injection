#ifndef _APC_INJECTION_H
#define _APC_INJECTION_H

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>

#ifdef _DEBUG
#define DEBUG_PRINT(str) do{std::cout << str << std::endl;}while(0)
#else
#define DEBUG_PRINT(str) do{}while(0);
#endif

/**
* @brief: Find PID and list of TIDs of given process name.
*
* @param input:  exeName - Name of process to find.
* @param output: pid - Pid of exeName process.
* @param output: tids - Thread ids of exeName process.
*
* @return: On success - true. 
*          Otherwise - false.
*
*/
bool findProcessByName(PCWSTR exeName, DWORD& pid, std::vector<DWORD>& tids);


/**
* @brief: Inject DLL in to target process.
*
* @param: aTargetProc - Process to be injected with DLL.
* @param: aDllToInject - DLL to be injected.
*
* @return: true on success, false otherwise.
*
*/
bool injectDll(LPWSTR aTargetProc, LPWSTR aDllToInject);

#endif