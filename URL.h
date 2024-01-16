#pragma once
#include <windows.h>
#include <Urlmon.h>
#pragma comment (lib, "urlmon.lib")
#include <vector>

DWORD threadId;

namespace AntiDebug
{

    std::vector<HANDLE> tHandles;

    bool IsHooked()
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
    bool IsDebuggedHardwareBreakpoints()
    {
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(CONTEXT));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(GetCurrentThread(), &ctx))
            return false;

        return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
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

        *(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret

    }
    bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
    {
        PBYTE pBytes = (PBYTE)pMemory;
        for (SIZE_T i = 0; ; i++)
        {
            // Break on RET (0xC3) if we don't know the function's size
            if (((nMemorySize > 0) && (i >= nMemorySize)) ||
                ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
                break;

            if (pBytes[i] == cByte)
                return true;
        }
        return false;
    }

    bool EraseSpecificByte(PVOID pMemory, SIZE_T nMemorySize = 0)
    {
        PBYTE pBytes = (PBYTE)pMemory;
        for (SIZE_T i = 0; ; i++)
        {
            // Break on RET (0xC3) if we don't know the function's size

            if (i <= nMemorySize)
            {
                if (pBytes[i])
                {
                    uintptr_t addr = (uintptr_t)pMemory + i;

                    *(PBYTE)addr = 0x90;
                    return true;
                }
            }
        }
        return false;
    }

    bool IsDebugged()
    {
        PVOID functionsToCheck[] = {
            &GetProcAddress,
            &ExitProcess,
            &AntiDebug::IsDebuggedHardwareBreakpoints,
            &AntiDebug::IsHooked,
        };
        for (auto funcAddr : functionsToCheck)
        {
            if (CheckForSpecificByte(0xCC, funcAddr))
            {
                //EraseSpecificByte(funcAddr,100);
                return true;
            }
        }
        return false;
    }


    bool IsDebuggerCloseHandle() 
    {
        __try
        {
            CloseHandle((HANDLE)0xDEADBEEF);
            return false;
        }
        __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH)
        {
            return true;
        }
    }

    bool IsDebuggedRaiseException()
    {
        __try
        {
            RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
        }
        __except (GetExceptionCode() == DBG_PRINTEXCEPTION_C)
        {
            return false;
        }

        return true;
    }
    void CreateThreadForDebug(void* func) 
    {
        HANDLE handle = LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(func), nullptr, 0, &threadId);
        tHandles.push_back(handle);
    }


    bool IsDebuggedSuspendThread()
    {
        for (HANDLE thread : tHandles)
        {
            if (GetThreadId(thread))
            {
                if(ResumeThread(thread) > -1)
                    return true;
            }
            else {
                return true;
            }
        }
        return false;
    }
};



HRESULT DownloadFileFromURL(const char* url, const char* file, const char* path)
{
    //VMP_ULTRA(_xor("DownloadFileFromURL"));

    GetISocket* socket = new GetISocket;
    GetIMain* main = new GetIMain;

    std::string hwid = main->GetSerialKey(WF_RU_HWID);

    std::string b64_filename = socket->base64_encode(file, strlen(file)).c_str();

    std::string request_url = url;
    request_url.append(_xor("?file="));
    request_url.append(b64_filename.c_str());

    UrlMkSetSessionOption(URLMON_OPTION_USERAGENT, (LPVOID)hwid.data(), hwid.length(), NULL);

    if (URLDownloadToFileA(NULL, request_url.c_str(), path, 0, 0) == S_OK)
        return S_OK;
    else
        return S_FALSE;
    //VMP_END;
}