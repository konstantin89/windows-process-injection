#include <windows.h>
#include <stdio.h>

extern "C" __declspec(dllexport) void message();

void message()
{
	MessageBox(0, L"InjectedDLL", L"DLL_PROCESS_ATTACH", MB_OK);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, // handle to DLL module
	                DWORD fdwReason,    // reason for calling function
	                LPVOID lpReserved)  // reserved
{

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			printf("InjectedDLL DLL_PROCESS_ATTACH\n");
			message();
			break;
		}

		case DLL_THREAD_ATTACH:
		{
			break;
		}

		case DLL_THREAD_DETACH:
		{
			break;
		}

		case DLL_PROCESS_DETACH:
		{
			break;
		}
	}
	return TRUE;

}