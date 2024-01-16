#pragma once
#include <Windows.h>
#include <winternl.h>
#include "../XorStr.h"
#include <TlHelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#include <fstream>
#include <signal.h>
#include <thread>
#include "driver.h"
#include "lazy.h"
#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <tchar.h>
#include <winternl.h>
#include <winnt.h>

__forceinline bool HideThread(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);

	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandleA(_xor("ntdll.dll")), _xor("NtSetInformationThread"));
	if (NtSIT == NULL)
		return false;

	if (hThread == NULL)
		Status = NtSIT(GetCurrentThread(),
			0x11,
			0, 0);
	else
		Status = NtSIT(hThread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

BOOL CheckRemoteDebuggerPresentAPI(VOID)
{
	BOOL m_bIsDebugging = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &m_bIsDebugging);
	return m_bIsDebugging;
}

BOOL IsDebuggerPresentPEB(VOID)
{
	PPEB m_pPeb = (PPEB)__readgsdword(0x30);
	return m_pPeb->BeingDebugged == 1;
}

bool IsDebugging()
{
	if (IsDebuggerPresent()  || CheckRemoteDebuggerPresentAPI())
		return true;
	return false;
}

__forceinline BOOL IsRemoteSession(void)
{
	return GetSystemMetrics(SM_REMOTESESSION);
}

void ProcessN(const char* filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = LI_FN(OpenProcess)(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				LI_FN(CloseHandle)(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	LI_FN(CloseHandle)(hSnapShot);
}

typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);
typedef VOID(_stdcall* RtlSetProcessIsCritical) (IN BOOLEAN NewValue, OUT PBOOLEAN OldValue, IN BOOLEAN IsWinlogon);

BOOL EnablePriv(LPCSTR lpszPriv)
{
	
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkprivs;
	ZeroMemory(&tkprivs, sizeof(tkprivs));

	if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
		CloseHandle(hToken); return FALSE;
	}

	tkprivs.PrivilegeCount = 1;
	tkprivs.Privileges[0].Luid = luid;
	tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
	CloseHandle(hToken);
	return bRet;
	
}

BOOL MakeCritical()
{
	HANDLE hDLL;
	RtlSetProcessIsCritical fSetCritical;

	hDLL = LoadLibraryA(_xor("ntdll.dll"));
	if (hDLL != NULL)
	{
		EnablePriv(SE_DEBUG_NAME);
		(fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, (_xor("RtlSetProcessIsCritical")));
		if (!fSetCritical) return 0;
		fSetCritical(1, 0, 0);
		return 1;
	}
	else
		return 0;
}

DWORD GetProcIDFromName(LPCTSTR szProcessName)
{
	
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		LI_FN(CloseHandle)(hSnapshot);
		return 0;
	}

	if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		LI_FN(CloseHandle)(hSnapshot);
		return pe32.th32ProcessID;
	}

	while (Process32Next(hSnapshot, &pe32))
	{
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			LI_FN(CloseHandle)(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

bool IsUserEbanat()
{
	return IsRemoteSession() || DriverCheck();
}

void CheckUserActivity()
{
	if (IsDebugging() || DriverCheck())
	{
		// raise(11);
	}
}

bool Start()
{
	HideThread(GetCurrentThread);
	while (true)
	{
		if (IsUserEbanat())
		{
			// raise(11);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

void Protection()
{
	HideThread(GetCurrentThread);

	while (true)
	{
		CheckUserActivity();
		IsUserEbanat();
		Sleep(1000);
	}
}
