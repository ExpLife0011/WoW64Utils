/*
*/
#pragma once

#include <Windows.h>

#pragma comment(lib, "WoW64Utils.lib")

extern "C" {
	DWORD64 __cdecl x64Call(_In_ DWORD64 pfnProc64, _In_ int nArgs, ...);
	DWORD64 __cdecl GetModuleHandle64(_In_ LPWSTR lpModuleName);
	DWORD64 __cdecl GetProcAddress64(_In_ DWORD64 hModule, _In_ LPSTR lpProcName);
	void    __cdecl memcpy64(_In_ DWORD64 Dest, _In_ DWORD64 Src, _In_ DWORD Size);
	DWORD64 __cdecl GetTeb64();
	DWORD64 __cdecl GetPeb64();
}