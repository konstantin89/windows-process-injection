#ifndef _PROCESS_HOLLOWING_H
#define _PROCESS_HOLLOWING_H

#include <string>

/**
* @brief: Function that used to demonstrate process injecion 
*         using process hollowing technique.
* 
* @param: aProcToInject - Executable name to be injected
*                         in to victim process.
*
* @param: aTargetProc - Executable of process that will 
*                       run in suspended mode, in order to
*                       be injected with aProcToInject.
*
* @return: On success - 0. 
*          Otherwise - Windows error code.
*
*/
int injectProc(LPWSTR aProcToInject, LPWSTR aTargetProc);

#endif