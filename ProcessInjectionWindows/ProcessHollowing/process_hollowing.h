#ifndef _PROCESS_HOLLOWING_H
#define _PROCESS_HOLLOWING_H

#include <string>

/**
* @brief: Function that used to demonstrate process injecion 
*         using process hollowing technique.
* 
* @param: aWstrProcToInject - Executable name to be injected
*                             in to victim process.
*
* @param: aWstrTargetProc - Executable of process that will 
*                           run in suspended mode, in order to
*                           be injected with aWstrProcToInject.
*
* @return: On success - 0. 
*          Otherwise - Windows error code.
*
*/
int injectProc(std::wstring aWstrProcToInject, std::wstring aWstrTargetProc);

#endif