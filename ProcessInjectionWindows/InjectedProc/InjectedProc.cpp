
#include "stdafx.h"
#include "InjectedProc.h"

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	MessageBox(0, L"InjectedProcess", L"InjectedProcess", MB_OK);

	return 0;
}
