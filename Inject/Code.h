HANDLE hProc;

using namespace KeyAuth;

auto name = _("meta");
auto ownerid = _("c5upeL7z3A");
auto secret = _("39db528da590942fe2ea524d5723b7ab03efb41b03ff90a387a1e55b19b65858");
auto version = _("5.0");
auto url = _("https://keyauth.win/api/1.2/");

api KeyAuthApp(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt(), url.decrypt());

bool IsLicenseRU_PVP = NULL;
bool zhopu_ya_prisunul = 0;

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

inline void crash() {
	KeyAuthApp.log(KeyAuthApp.data.hwid);
	KeyAuthApp.ban(_xor("crash"));
	raise(11);
}

namespace ul {
	bool VDXZ1 = false;
	bool VDXZ2 = false;
	bool VDXZ3 = false;
	bool VDXZmega = false;
}

void ERYGDFGEHTRH()
{
	KeyAuthApp.check();

	if (KeyAuthApp.checkblack()) {
		abort();
	}
}

void YUJTYJSGHSDGH()
{
	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(3));
		ERYGDFGEHTRH();
	}
}

void PLASTIK()
{
	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(2));
		ERYGDFGEHTRH();
	}
}

void Patch_DbgBreakPoint()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

struct DbgUiRemoteBreakinPatch
{
	WORD  push_0;
	BYTE  push;
	DWORD CurrentPorcessHandle;
	BYTE  mov_eax;
	DWORD TerminateProcess;
	WORD  call_eax;
};

void Patch_DbgUiRemoteBreakin()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
	if (!pDbgUiRemoteBreakin)
		return;

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return;

	FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
	if (!pTerminateProcess)
		return;

	DbgUiRemoteBreakinPatch patch = { 0 };
	patch.push_0 = '\x6A\x00';
	patch.push = '\x68';
	patch.CurrentPorcessHandle = 0xFFFFFFFF;
	patch.mov_eax = '\xB8';
	patch.TerminateProcess = (DWORD)pTerminateProcess;
	patch.call_eax = '\xFF\xD0';

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
		return;

	::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
		&patch, sizeof(DbgUiRemoteBreakinPatch));
	VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}

bool IsDebuggerPresent1()
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return false;

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
	if (!pIsDebuggerPresent)
		return false;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return false;

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
		return false;

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				break;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);
	return bDebuggerPresent;
}

bool proverki2()
{
	int argc;
	char argv;

	Patch_DbgBreakPoint();
	Patch_DbgUiRemoteBreakin();

	if (IsDebuggerPresent())
		LI_FN(exit)(3);

	IsDebuggerPresent1();

	BOOL bDebuggerPresent;
	if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
		TRUE == bDebuggerPresent)
		LI_FN(exit)(3);

	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
		IN HANDLE           ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID           ProcessInformation,
		IN ULONG            ProcessInformationLength,
		OUT PULONG          ReturnLength
		);

	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugPort,
				&dwProcessDebugPort,
				sizeof(DWORD),
				&dwReturned);

			if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
				LI_FN(exit)(3);
		}
	}

	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);

	__try
	{
		RaiseException(DBG_CONTROL_C, 0, 0, NULL);
		return true;
	}
	__except (DBG_CONTROL_C == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH)
	{
		return false;
	}

	PVOID pRetAddress = _ReturnAddress();
	if (*(PBYTE)pRetAddress == 0xCC) // int 3
	{
		DWORD dwOldProtect;
		if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			*(PBYTE)pRetAddress = 0x90; // nop
			VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
		}
	}
}

int UYYFDUGHR7YGH6F()
{
	int debugger_present = false;

	LI_FN(CheckRemoteDebuggerPresent).safe()(LI_FN(GetCurrentProcess).safe()(), &debugger_present);

	return debugger_present;
}

bool codeExecuted = false;

BOOL CALLBACK FDJKFUNSYDFYDBF(HWND hwnd, LPARAM lParam) {
	char windowText[256];
	GetWindowTextA(hwnd, windowText, sizeof(windowText));

	std::string windowTitle = windowText;
	std::string keywords[] = {
		_xor("[Elevated]"),
		_xor("Hacker 2"),
		_xor("Process Hacker"),
		_xor("HTTP D"),
		_xor("OllyDbg"),
		_xor("IDA"),
		_xor("Window Renamer"),
		_xor("snapshot_2023")
	};

	for (const auto& keyword : keywords) {

		if (windowTitle.find(keyword) != std::string::npos) {
			KeyAuthApp.ban(_xor("EnumWindows"));
			exit(0);

			break;
		}
	}

	return TRUE;
}

void KDFGUDFYDFT()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;

}

void HSDFYASYFGTWFY()
{
	const std::string DFGHGFHERTHRETWSHRSGH = _xor("C:\\TitanHide.log");

	std::ifstream file(DFGHGFHERTHRETWSHRSGH);
	if (file.good()) {
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("TitanHide.log"));
		raise(11);
	}
}

void VASDVDR()
{
	const TCHAR* devices[] = {
_xor("\\\\.\\NiGgEr"),
_xor("\\\\.\\KsDumper")
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("drivers"));
			raise(11);
		}
	}
}

void YFGF6GFFDG(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	hProcess = GetCurrentProcess();
	CheckRemoteDebuggerPresent(hProcess, &found);

	if (found)
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("CheckRemoteDebuggerPresent"));
		raise(11);
	}
}

void DFHB6DEFGD6F34FGFG(void)
{
	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(hThread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = TRUE;
		}
	}

	if (found)
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("DFHB6DEFGD6F34FGFG"));
		raise(11);
	}
}

int DNFBYBF6DGF6()
{
	unsigned int NumBps = 0;

	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	HANDLE hThread = GetCurrentThread();

	if (GetThreadContext(hThread, &ctx) == 0)
		return -1;

	if (ctx.Dr0 != 0)
		++NumBps;
	if (ctx.Dr1 != 0)
		++NumBps;
	if (ctx.Dr2 != 0)
		++NumBps;
	if (ctx.Dr3 != 0)
		++NumBps;

	return NumBps;
}

bool ND7F6GDF5V(LPCTSTR String)
{
	OutputDebugString(String);
	if (GetLastError() == 0)
		return true;
	else
		return false;
}

void DGHF6DGF5TDGF()
{
	HANDLE hProcess = NULL;
	DEBUG_EVENT de;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&de, sizeof(DEBUG_EVENT));

	GetStartupInfo(&si);

	CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE,
		DEBUG_PROCESS, NULL, NULL, &si, &pi);

	ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);

	WaitForDebugEvent(&de, INFINITE);
}

bool NDY6G6FGDST5FG()
{
	typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	HANDLE hDebugObject = NULL;
	NTSTATUS Status;

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
		0x1e,
		&hDebugObject, 4, NULL);

	if (Status != 0x00000000)
		return false;

	if (hDebugObject)
		return true;
	else
		return false;
}

#define SERIAL_THRESHOLD 0x10000

int MJSFDNDHFBDGF(TCHAR* pName)
{
	DWORD LocalSerial = 0;

	DWORD Counter = GetTickCount();

	Counter = GetTickCount() - Counter;
	if (Counter >= SERIAL_THRESHOLD)
		ExitProcess(0);

	return LocalSerial;
}

bool VFDVCRTDVFF(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)
		(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtSetInformationThread");

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

bool DFGHSDFGDFSG() {
	DWORD bufferSize = GetSystemFirmwareTable('DSDT', 0, NULL, 0);

	if (bufferSize == 0) {
		return false;
	}

	std::vector<BYTE> buffer(bufferSize, 0);

	if (GetSystemFirmwareTable('DSDT', 0, buffer.data(), bufferSize) == 0) {
		return false;
	}

	const char* testSignSignature = "TESTSIGN";
	for (size_t i = 0; i < buffer.size() - strlen(testSignSignature); ++i) {
		if (memcmp(buffer.data() + i, testSignSignature, strlen(testSignSignature)) == 0) {
			return true;
		}
	}

	return false;
}

bool CMSDCNBDTA()
{
	BOOL bFirstResult = FALSE, bSecondResult = FALSE;
	__try
	{
		bFirstResult = BlockInput(TRUE);
		bSecondResult = BlockInput(TRUE);
	}
	__finally
	{
		BlockInput(FALSE);
	}
	return bFirstResult && bSecondResult;
}

__forceinline BOOL IEHRYDFDYFHB(void)
{
	return GetSystemMetrics(SM_REMOTESESSION);
}

bool LRGFIRFGJYHFBGHGBG()
{
	return IEHRYDFDYFHB();
}

enum { SystemKernelDebuggerInformation = 0x23 };

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

bool Check()
{
	NTSTATUS status;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;

	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
		&SystemInfo,
		sizeof(SystemInfo),
		NULL);

	return SUCCEEDED(status)
		? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
		: false;
}

//inline DWORD anti_suspend()
//{
//	static DWORD TimeTest1 = 0, TimeTest2 = 0;
//	TimeTest1 = TimeTest2;
//	TimeTest2 = LI_FN(GetTickCount).forwarded_safe_cached()();
//	if (TimeTest1 != 0)
//	{
//		if (TimeTest2 - TimeTest1 > 6000) {
//			KeyAuthApp.log(KeyAuthApp.data.hwid);
//			KeyAuthApp.ban(_xor("Suspend"));
//			raise(11);
//		}
//	}
//	return 0;
//}

bool find(const char* name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	auto snapshot = LI_FN(CreateToolhelp32Snapshot).forwarded_safe_cached()(TH32CS_SNAPPROCESS, NULL);

	if (LI_FN(Process32First).forwarded_safe_cached()(snapshot, &entry) == TRUE)
	{
		while (LI_FN(Process32Next).forwarded_safe_cached()(snapshot, &entry) == TRUE)
		{
			if (!strcmp((const char*)entry.szExeFile, name))
			{
				return true;
			}
		}
	}

	LI_FN(CloseHandle).forwarded_safe_cached()(snapshot);
	return false;

}

inline bool hide_thread(HANDLE thread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	pNtSetInformationThread NtSIT = (pNtSetInformationThread)LI_FN(GetProcAddress).forwarded_safe_cached()((LI_FN(GetModuleHandleA).forwarded_safe_cached())(_("ntdll.dll")), _("NtSetInformationThread"));

	if (NtSIT == NULL) return false;
	if (thread == NULL)
		Status = NtSIT(LI_FN(GetCurrentThread).forwarded_safe_cached(), 0x11, 0, 0);
	else
		Status = NtSIT(thread, 0x11, 0, 0);

	if (Status != 0x00000000)
		return false;
	else
		return true;
}

inline bool thread_hide_debugger()
{
	typedef NTSTATUS(WINAPI* pNtSetInformationThread)(IN HANDLE, IN UINT, IN PVOID, IN ULONG);

	const int ThreadHideFromDebugger = 0x11;
	pNtSetInformationThread NtSetInformationThread = NULL;

	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("ntdll.dll"));
	NtSetInformationThread = (pNtSetInformationThread)LI_FN(GetProcAddress).forwarded_safe_cached()(hNtDll, _("NtSetInformationThread"));
	Status = NtSetInformationThread(LI_FN(GetCurrentThread).forwarded_safe_cached()(), ThreadHideFromDebugger, NULL, 0);

	if (Status)
		//raise(11);
		LI_FN(exit)(3);

	return IsBeingDebug;
}

inline void window_check()
{
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("PROCEXPL"), NULL)) *(uintptr_t*)(0) = 0;
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("dbgviewClass"), NULL)) *(uintptr_t*)(0) = 0;
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("XTPMainFrame"), NULL)) *(uintptr_t*)(0) = 0;
	if (LI_FN(FindWindowA).forwarded_safe_cached()(_("WdcWindow"), _("Resource Monitor"))) *(uintptr_t*)(0) = 0;
}

inline int ollydbg_exploit() {
	__try {
		LI_FN(OutputDebugStringA).forwarded_safe_cached()(_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }

	return 0;
}

inline int hardware_breakpoints()
{
	unsigned int NumBps = 0;

	CONTEXT ctx;
	RtlSecureZeroMemory(&ctx, sizeof(CONTEXT));

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	HANDLE hThread = LI_FN(GetCurrentThread).forwarded_safe_cached()();

	if (LI_FN(GetThreadContext).forwarded_safe_cached()(hThread, &ctx) == 0)
		crash();

	if (ctx.Dr0 != 0)
		++NumBps;
	if (ctx.Dr1 != 0)
		++NumBps;
	if (ctx.Dr2 != 0)
		++NumBps;
	if (ctx.Dr3 != 0)
		++NumBps;

	return NumBps;
}

inline void hardware_register()
{
	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = LI_FN(GetCurrentThread).forwarded_safe_cached()();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext).forwarded_safe_cached()(hThread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = TRUE;
		}
	}

	if (found)
	{
		crash();
	}
}

void vmware_check()
{
	if (find(_("vmtoolsd.exe")))  exit(0);
	if (find(_("vmwaretray.exe")))  exit(0);
	if (find(_("vmwareuser.exe"))) exit(0);
	if (find(_("VGAuthService.exe"))) exit(0);
	if (find(_("vmacthlp.exe"))) exit(0);
}

inline bool check1()
{
	UCHAR* pMem = NULL;
	SYSTEM_INFO SystemInfo = { 0 };
	DWORD OldProtect = 0;
	PVOID pAllocation = NULL;

	LI_FN(GetSystemInfo).forwarded_safe_cached()(&SystemInfo);

	pAllocation = LI_FN(VirtualAlloc).forwarded_safe_cached()(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocation == NULL)
		return FALSE;

	RtlFillMemory(pAllocation, 1, 0xC3);

	if (LI_FN(VirtualProtect).forwarded_safe_cached()(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
		return FALSE;

	__try
	{
		((void(*)())pAllocation)();
	}
	__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		LI_FN(VirtualFree).forwarded_safe_cached()(pAllocation, NULL, MEM_RELEASE);
		return FALSE;
	}

	LI_FN(VirtualFree).forwarded_safe_cached()(pAllocation, NULL, MEM_RELEASE);
	return TRUE;
}

inline bool check2()
{
	PCONTEXT ctx = PCONTEXT(LI_FN(VirtualAlloc).forwarded_safe_cached()(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE));
	RtlSecureZeroMemory(ctx, sizeof(CONTEXT));

	ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (LI_FN(GetThreadContext).forwarded_safe_cached()(LI_FN(GetCurrentThread).forwarded_safe_cached()(), ctx) == 0)
		return -1;


	if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
		return TRUE;
	else
		return FALSE;
}

inline int last_error()
{
	LI_FN(SetLastError).forwarded_safe_cached()(0);
	const auto last_error = LI_FN(GetLastError).forwarded_safe_cached()();

	return last_error != 0;
}

inline bool close_handle()
{
	__try {
		LI_FN(CloseHandle).forwarded_safe_cached()((HANDLE)0x13333337);
	}
	__except (STATUS_INVALID_HANDLE) {
		return TRUE;
	}
}

inline int thread_context()
{
	int found = false;
	CONTEXT ctx = { 0 };
	void* h_thread = LI_FN(GetCurrentThread).forwarded_safe_cached();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (LI_FN(GetThreadContext).forwarded_safe_cached()(h_thread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = true;
		}
	}

	return found;
}

inline int remote_is_present()
{
	int debugger_present = false;

	LI_FN(CheckRemoteDebuggerPresent).forwarded_safe_cached()(LI_FN(GetCurrentProcess).forwarded_safe_cached()(), &debugger_present);

	return debugger_present;
}

int is_debugger_present()
{
	return LI_FN(IsDebuggerPresent).forwarded_safe_cached()();
}

inline DWORD anti_suspend()
{
	static DWORD TimeTest1 = 0, TimeTest2 = 0;
	TimeTest1 = TimeTest2;
	TimeTest2 = LI_FN(GetTickCount).forwarded_safe_cached()();
	if (TimeTest1 != 0)
		if (TimeTest2 - TimeTest1 > 6000) {
			crash();
		}
	return 0;
}

inline int hide_loader_thread()
{
	unsigned long thread_hide_from_debugger = 0x11;

	const auto ntdll = LI_FN(LoadLibraryA).forwarded_safe_cached()(_("ntdll.dll"));

	if (ntdll == INVALID_HANDLE_VALUE || ntdll == NULL) { return false; }

	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)LI_FN(GetProcAddress).forwarded_safe_cached()(ntdll, _("NtQueryInformationProcess"));

	if (NtQueryInformationProcess == NULL) { return false; }

	(_NtSetInformationThread)(LI_FN(GetCurrentThread).forwarded_safe_cached(), thread_hide_from_debugger, 0, 0, 0);

	return true;
}

void FHTHFGSH() {
	hide_thread(LI_FN(GetCurrentThread).forwarded_safe_cached()());
	thread_hide_debugger();
	//hide_loader_thread();

	while (true)
	{
		if (Check()) {
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("Check"));
			raise(11);
		}

		if (check1()) exit(0);
		if (check2()) exit(0);
		if (last_error()) exit(0);
		if (close_handle()) exit(0);
		if (thread_context()) exit(0);
		if (remote_is_present()) exit(0);
		if (is_debugger_present()) exit(0);
		EnumWindows(FDJKFUNSYDFYDBF, 0);
		LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(window_check), nullptr, 0, &threadId);
		//LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(ollydbg_exploit), nullptr, 0, &threadId);
		LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(UYYFDUGHR7YGH6F), nullptr, 0, &threadId);
		LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(proverki2), nullptr, 0, &threadId);
		LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(hardware_breakpoints), nullptr, 0, &threadId);
		LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(hardware_register), nullptr, 0, &threadId);
		//LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(vmware_check), nullptr, 0, &threadId);
		KDFGUDFYDFT();
		HSDFYASYFGTWFY();
		VASDVDR();
		YFGF6GFFDG();
		DFHB6DEFGD6F34FGFG();
		DNFBYBF6DGF6();
		ND7F6GDF5V((_xor("FYDETFGFDG")));
		DGHF6DGF5TDGF();
		NDY6G6FGDST5FG();
		MJSFDNDHFBDGF((TCHAR*)(_xor("WGDRSDFSDFJN")));
		VFDVCRTDVFF(hProc);

		if (DFGHSDFGDFSG()) {
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("TestSign"));
			raise(11);
		}

		BOOL isDebuggerPresent = IsDebuggerPresent();
		if (isDebuggerPresent)
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("MFY7DHGF65DSFG"));
			raise(11);
		}

		BOOL IsDebuggerPresent = FALSE;
		HANDLE hProcess = GetCurrentProcess();
		CheckRemoteDebuggerPresent(hProcess, &IsDebuggerPresent);
		if (IsDebuggerPresent)
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("MFY7DHGF65DSFG"));
			raise(11);
		}

		PROCESS_BASIC_INFORMATION pbi;
		ULONG ReturnLength;
		NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);
		if (NT_SUCCESS(status) && pbi.PebBaseAddress->BeingDebugged)
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("MFY7DHGF65DSFG"));
			raise(11);
		}

		if (CMSDCNBDTA())
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("MFY7DHGF65DSFG"));
			raise(11);
		}

		if (LRGFIRFGJYHFBGHGBG())
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("MFY7DHGF65DSFG"));
			raise(11);
		}
	}
}

void mayz()
{
	while (true)
    {
	   SetCursorPos(0, 0);
    }
}

void GERUIGYHDFNBKVKNFDBN() {

	const wchar_t szProc[] = L"RustClient.exe";

	PROCESSENTRY32W PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	DWORD_PTR PID = 0;
	BOOL bRet = Process32FirstW(hSnap, &PE32);
	while (bRet) {
		if (!wcscmp(szProc, PE32.szExeFile)) {
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32NextW(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	// sec

	anti_suspend();
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(FHTHFGSH), nullptr, 0, &threadId);

	if (!ul::VDXZ1 && !ul::VDXZ2 && !ul::VDXZ3 && !ul::VDXZmega && !KeyAuthApp.data.success) {
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("ne doshel do eichek"));
		raise(11);
	}
	else {

		HANDLE handle_mutex = OpenMutexA(MUTEX_ALL_ACCESS, 0, _("galaxy.bundle"));
		if (!handle_mutex)
		{
			handle_mutex = CreateMutexA(0, 0, _("galaxy.bundle"));
		}

		std::vector<std::uint8_t> beta = KeyAuthApp.download(_xor("385530"));
		std::vector<std::uint8_t> release = KeyAuthApp.download(_xor("385530"));

		beta.clear();
		release.clear();

		if (items[selected_item] == "meta (Beta)")
		{
			if (!GREGRTEHRTHGFH(hProc, &beta[0])) {
				CloseHandle(hProc);
			}
		}

		if (items[selected_item] == "meta (Release)")
		{
			if (!GREGRTEHRTHGFH(hProc, &release[0])) {
				CloseHandle(hProc);
			}
		}

	}
	CloseHandle(hProc);

	LI_FN(exit)(3);
}

void FGHRTJGHKGJFDGH()
{
	printf(_("\ninjecting"));

	if (ul::VDXZ3 == true)
	{
	    GERUIGYHDFNBKVKNFDBN();
	}
}

void HSDOFSDFROBS() {
	if (ul::VDXZmega == true)
	{
		ul::VDXZ3 = true;
		Sleep(100);
		Sleep(3000);
		FGHRTJGHKGJFDGH();
	}
}

void GUKRAINTOPNATO() {
	if (IsDebuggerPresent()) {
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggerPresent"));
		raise(11);
	}
	else {
		ul::VDXZmega = true;
		HSDOFSDFROBS();
	}
}

void OBSFIASDGDF() {
	if (ul::VDXZ1 == true) {
		GUKRAINTOPNATO();
	}
	else
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor(""));
		raise(11);
	}
}