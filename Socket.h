    using namespace std;
    #define _CRT_SECURE_NO_WARNINGS

    #include "Config.h"
    #include <conio.h>
    #include <windows.h>
    #include <string>
    #include <WinInet.h>
    #include <iostream>
    #include <sstream>
    #include <fstream>
    #include <vector>
    #include <filesystem>
    #include <tchar.h>
    #include <stdio.h> 
    #include <thread>
    #include "XorStr.h"
    #include "Protect/lazy.h"
 
    #pragma comment (lib, "Wininet.lib")
    #pragma comment(lib, "ntdll.lib")
    #include <Urlmon.h>
    #pragma comment (lib, "urlmon.lib")
    //#include "VMP/VMProtectSDK.h"
    #include "Tools.h"

    #define HOST   _xor("blume.host")
    #define VERSION _xor("1.0")
    #define DOWNLOAD_LINK _xor("https://blume.host/")
    #include <TlHelp32.h>

    static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
    class GetIMain;
    class GetIUnicalHWID
    {
    public:
        std::string GetHWID(string VerSoft)
        {
            //VMP_ULTRA(_xor("GetHWID"));
            std::string SerialKey = "";
            std::string CompName = GetCompUserName(false);
            std::string UserName = GetCompUserName(true);
            SerialKey.append(StringToHex(GetHwUID()));
            SerialKey.append("");
            SerialKey.append(GetHwUID());
            SerialKey.append("");
            SerialKey.append(StringToHex(CompName));
            SerialKey.append("");
            SerialKey.append(StringToHex(UserName));
            std::string Serial2 = VerSoft + SerialKey.substr(15, 15);
            return Serial2;
            //VMP_END;
        }
    private:
        std::string GetHwUID()
        {
            HW_PROFILE_INFO hwProfileInfo;
            std::string szHwProfileGuid = "";

            if (GetCurrentHwProfileA(&hwProfileInfo) != NULL)
                szHwProfileGuid = hwProfileInfo.szHwProfileGuid;

            return szHwProfileGuid;
        }
        std::string GetCompUserName(bool User)
        {
            std::string CompUserName = "";
            char szCompName[MAX_COMPUTERNAME_LENGTH + 1];
            char szUserName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD dwCompSize = sizeof(szCompName);
            DWORD dwUserSize = sizeof(szUserName);

            if (GetComputerNameA(szCompName, &dwCompSize))
            {
                CompUserName = szCompName;

                if (User && GetUserNameA(szUserName, &dwUserSize))
                {
                    CompUserName = szUserName;
                }
            }
            return CompUserName;
        }
        std::string StringToHex(const std::string input)
        {
            const char* lut = _xor("0123456789ABCDEF");
            size_t len = input.length();
            std::string output = "";

            output.reserve(2 * len);

            for (size_t i = 0; i < len; i++)
            {
                const unsigned char c = input[i];
                output.push_back(lut[c >> 4]);
                output.push_back(lut[c & 15]);
            }

            return output;
        }
        DWORD GetVolumeID()
        {
            DWORD VolumeSerialNumber;

            BOOL GetVolumeInformationFlag = GetVolumeInformationA(
                _xor("c:\\"),
                0,
                0,
                &VolumeSerialNumber,
                0,
                0,
                0,
                0
            );

            if (GetVolumeInformationFlag)
                return VolumeSerialNumber;

            return 0;
        }
    };
    class GetISocket
    {
    public:
        std::string GetUrlData(std::string url)
        {
            //VMP_ULTRA(_xor("GetUrlData"));
            std::string request_data = "";

            HINTERNET hIntSession = InternetOpenA("", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

            if (!hIntSession)
            {
                return request_data;
            }

            HINTERNET hHttpSession = InternetConnectA(hIntSession, HOST, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, NULL);

            if (!hHttpSession)
            {
                return request_data;
            }

            HINTERNET hHttpRequest = HttpOpenRequestA(hHttpSession, "GET", url.c_str()
                , 0, 0, 0, INTERNET_FLAG_RELOAD, 0);

            if (!hHttpSession)
            {
                return request_data;
            }

            const char* szHeaders = ("Content-Type: text/html\r\nUser-Agent: License");
            char szRequest[1024] = { 0 };

            if (!HttpSendRequestA(hHttpRequest, szHeaders, strlen(szHeaders), szRequest, strlen(szRequest)))
            {
                return request_data;
            }

            CHAR szBuffer[1024] = { 0 };
            DWORD dwRead = 0;

            while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
            {
                request_data.append(szBuffer, dwRead);
            }

            LI_FN(InternetCloseHandle)(hHttpRequest);
            LI_FN(InternetCloseHandle)(hHttpSession);
            LI_FN(InternetCloseHandle)(hIntSession);

            return request_data;
            //VMP_END;
        }
        std::string base64_encode(char const* bytes_to_encode, unsigned int in_len)
        {
            //VMP_ULTRA(_xor("base64_encode"));
            std::string ret;
            int i = 0;
            int j = 0;
            unsigned char char_array_3[3];
            unsigned char char_array_4[4];

            while (in_len--)
            {
                char_array_3[i++] = *(bytes_to_encode++);
                if (i == 3)
                {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;

                    for (i = 0; (i < 4); i++)
                        ret += base64_chars[char_array_4[i]];
                    i = 0;
                }
            }

            if (i)
            {
                for (j = i; j < 3; j++)
                    char_array_3[j] = '\0';

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (j = 0; (j < i + 1); j++)
                    ret += base64_chars[char_array_4[j]];

                while ((i++ < 3))
                    ret += '=';

            }

            return ret;
            //VMP_END;
        }
        std::string GetHashText(const void* data, const size_t data_size)
        {
            //VMP_ULTRA(_xor("GetHashText"));
            HCRYPTPROV hProv = NULL;

            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            {
                return "";
            }

            BOOL hash_ok = FALSE;
            HCRYPTPROV hHash = NULL;

            hash_ok = LI_FN(CryptCreateHash)(hProv, CALG_MD5, 0, 0, &hHash);

            if (!hash_ok)
            {
                LI_FN(CryptReleaseContext)(hProv, 0);
                return "";
            }

            if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0))
            {
                LI_FN(CryptDestroyHash)(hHash);
                LI_FN(CryptReleaseContext)(hProv, 0);
                return "";
            }

            DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
            if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0))
            {
                LI_FN(CryptDestroyHash)(hHash);
                LI_FN(CryptReleaseContext)(hProv, 0);
                return "";
            }

            std::vector<BYTE> buffer(cbHashSize);

            if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0))
            {
                LI_FN(CryptDestroyHash)(hHash);
                LI_FN(CryptReleaseContext)(hProv, 0);
                return "";
            }

            std::ostringstream oss;

            for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter)
            {
                oss.fill('0');
                oss.width(2);
                oss << std::hex << static_cast<const int>(*iter);
            }

            LI_FN(CryptDestroyHash)(hHash);
            LI_FN(CryptReleaseContext)(hProv, 0);
            return oss.str();
            //VMP_END;
        }
    };

    namespace Tools
    {
        string randomName(int length) {

            char consonents[] = { 'b','c','d','f','g','h','j','k','l','m','n','p','q','r','s','t','v','w','x','z' };
            char vowels[] = { 'a','e','i','o','u','y' };
            string name = "";
            int random = rand() % 2;
            int count = 0;

            for (int i = 0; i < length; i++) {

                if (random < 2 && count < 2) {
                    name = name + consonents[rand() % 19];
                    count++;
                }
                else {
                    name = name + vowels[rand() % 5];
                    count = 0;
                }

                random = rand() % 2;

            }

            return name;

        }

    }

    class GetIInject
    {
    public:
        bool Inject = false;
        bool Error1 = false;
        bool Error2 = false;
        bool Error3 = false;
        bool Error4 = false;
    public:
        DWORD get_proc_id(const char* proc_name)
        {
            DWORD proc_id = 0;
            auto* const h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (h_snap != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32 proc_entry;
                proc_entry.dwSize = sizeof(proc_entry);

                if (Process32First(h_snap, &proc_entry))
                {
                    do
                    {
                        if (!_stricmp(proc_entry.szExeFile, proc_name))
                        {
                            proc_id = proc_entry.th32ProcessID;
                            break;
                        }
                    } while (Process32Next(h_snap, &proc_entry));
                }
            }

            LI_FN(CloseHandle)(h_snap);
            return proc_id;
        }
        string RandomString()
        {
            srand((unsigned int)time(0));
            string str = _xor("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
            string newstr;
            int pos;
            while (newstr.size() != 32)
            {
                pos = ((rand() % (str.size() + 1)));
                newstr += str.substr(pos, 1);
            }
            return newstr;
        }

        wstring RandomStringW()
        {
            srand((unsigned int)time(0));
            wstring str = _xorw(L"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
            wstring newstr;
            int pos;
            while (newstr.size() != 5)
            {
                pos = ((rand() % (str.size() + 1)));
                newstr += str.substr(pos, 1);
            }
            return newstr;
        }





        void RunWithAdminPermissions(string sz_exe, string sz_params, bool show)
        {
            ShellExecuteA(NULL, _xor("runas"), sz_exe.c_str(), sz_params.c_str(), NULL, show);
        }
        DWORD GetProcessID(const char* proc_name)
        {
            DWORD proc_id = 0;
            auto* const h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (h_snap != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32 proc_entry;
                proc_entry.dwSize = sizeof(proc_entry);

                if (Process32First(h_snap, &proc_entry))
                {
                    do
                    {
                        if (!_stricmp(proc_entry.szExeFile, proc_name))
                        {
                            proc_id = proc_entry.th32ProcessID;
                            break;
                        }
                    } while (Process32Next(h_snap, &proc_entry));
                }
            }

            LI_FN(CloseHandle)(h_snap);
            return proc_id;
        }
        bool CreateMessageBoxWithAnswers(LPCSTR caption, LPCSTR text)
        {
            int id = MessageBoxA(NULL, text, caption, MB_YESNO);
            if (id == IDYES)
                return true;
            else
                return false;

        }
     




        
      

     


        void LdLibrary_Inject(LPCSTR iName, string VerSoft, string Name, string Serial) 
        {
            //VMP_ULTRA(_xor("LdLibrary_Inject"));
            string appdata = _xor("C:\\Windows\\SoftwareDistribution\\Download\\");
            appdata += _strdup(Tools::randomName(8 + rand() % 64).c_str());
            appdata += _xor(".exe");
            string downlink = DOWNLOAD_LINK;
            downlink.append(_xor("panel/server/engine/download.php?serial=") + Serial + _xor("&version=") + Name);
            //downlink += iName;
            HRESULT hr = URLDownloadToFileA(NULL, downlink.c_str(), appdata.c_str(), 0, 0);

            if (hr == S_OK)
            {
                GlobalAddAtomA( Name.c_str() );
   		        ShellExecuteA(0, 0, appdata.c_str(), 0, 0, SW_SHOW);
            }
            else {
                MessageBoxA(0, _xor("Loading error! You have not entered a key for this game."), "", MB_OK);
                ExitProcess(0);
            }

            //VMP_END;

        }



    };

    class GetIMain
    {
    public:


        GetIUnicalHWID* iGetHWID = new GetIUnicalHWID;
        GetIInject* iGetIInject = new GetIInject;
        std::string GetSerialKey(string VerSoft)
        {
            //VMP_ULTRA(_xor("GetSerialKey"));
            return iGetHWID->GetHWID(VerSoft);
            //VMP_END;
        }
        std::string GetSerial64(string VerSoft)
        {
            //VMP_ULTRA(_xor("GetSerial64"));
            std::string Serial = GetSerialKey(VerSoft);
            Serial = iGetISocket->base64_encode(Serial.c_str(), Serial.size());
            return Serial;
            //VMP_END;
        }
        std::string GetDayLicense(std::string VerSoft)
        {
            //VMP_ULTRA(_xor("GetDayLicense"));
            std::string Serial = GetSerial64(VerSoft);
            std::string UrlRequest = _xor("panel/server/engine/");
            UrlRequest.append((_xor("sub.php?serial=")) + Serial);
            std::string ReciveHash = iGetISocket->GetUrlData(UrlRequest);
            if (ReciveHash.size())
            {
                return ReciveHash;
            }
            //VMP_END;
        }


        bool CheckLicense(string VerSoft)
        {
            //VMP_ULTRA(_xor("CheckLicense"));
            std::string Serial = GetSerial64(VerSoft);
            std::string Version = iGetISocket->base64_encode(VERSION,sizeof(VERSION));
            std::string UrlRequest = _xor("panel/server/engine/");
            UrlRequest.append((_xor("gate.php?serial=")) + Serial + _xor("&ver=") + Version);
            std::string ReciveHash = iGetISocket->GetUrlData(UrlRequest);
            if (ReciveHash.size())
            {
                std::string LicenseOK = _xor("5b602f1dce38fd578ae43f98edb3ada1c2fc019e35f80fffa13ba29803f1797c");
                std::string VersionError = _xor("5b602f1dce38fd578ae43f98edb3ada1c2fc019e35f8014123ba29803f1797c");
                std::string IsDetected = _xor("5b602f1dce38fd578ae43f98edb3ada1c2fc01984736014123ba29803f1797c");
                std::string IsHWIDBanned = _xor("1a602f1dce38fd578ae43f98edb3ada1c2fc01984736014123ba29803f1797c");
                if (ReciveHash == VersionError) 
                {
                    MessageBoxA(0, _xor("LOADER UPDATED. REDOWNLOAD LOADER!"), "", MB_OK);
                    ShellExecuteA(0, 0, _xor("https://blume.host/loader/loader.rar"), 0, 0, SW_SHOW);
                    ExitProcess(0);
                }
                
                if (ReciveHash == LicenseOK)
                {
                    //iGetIInject->Inject = true;
                    return true;
                }

                if (ReciveHash == IsHWIDBanned) 
                {
                    SendDebugInformation(_xor("BSOD")); Sleep(1300);
                    typedef NTSTATUS(NTAPI* TFNRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
                    typedef NTSTATUS(NTAPI* TFNNtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters,
                        ULONG UnicodeStringParameterMask, PULONG_PTR* Parameters, ULONG ValidResponseOption, PULONG Response);
                    NTSTATUS s1, s2;
                    BOOLEAN b;
                    ULONG r;
                    HMODULE hNtdll = GetModuleHandleA(_xor("ntdll.dll"));
                    if (!hNtdll)
                        hNtdll = LoadLibraryA(_xor("ntdll.dll"));
                    TFNRtlAdjustPrivilege pfnRtlAdjustPrivilege = (TFNRtlAdjustPrivilege)GetProcAddress(hNtdll, _xor("RtlAdjustPrivilege"));
                    s1 = pfnRtlAdjustPrivilege(19, true, false, &b);
                    TFNNtRaiseHardError pfnNtRaiseHardError = (TFNNtRaiseHardError)GetProcAddress(hNtdll, _xor("NtRaiseHardError"));
                    s2 = pfnNtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6, &r);

                }
            }   
            return false;
            //VMP_END;
        }
        bool IsCheatOnUpdate(string VerSoft, string Version)
        {
            //VMP_ULTRA(_xor("IsCheatOnUpdate"));
            std::string Serial = GetSerial64(VerSoft);
            std::string UrlRequest = _xor("panel/server/engine/");
            UrlRequest.append((_xor("download.php?serial=")) + Serial + _xor("&version=") + Version + _xor("&status=1"));
            std::string ReciveHash = iGetISocket->GetUrlData(UrlRequest);
            if (ReciveHash.size())
            {
                if (ReciveHash == _xor("b040243a8740acdf647e335f613a7d5a"))
                {
                    return true;
                }
            }
            return false;
            //VMP_END;
        }

        std::string ApplyLicenseForKey(std::string key, string VerSoft)
        {
            //VMP_ULTRA(_xor("ApplyLicenseForKey"));
            std::string Serial = iGetHWID->GetHWID(VerSoft).c_str();
            std::string UrlRequest = "panel/server/engine/";
            UrlRequest.append((_xor("activate.php?serial=")) + Serial + _xor("&hw=") + key);
            static std::string ReciveDay = iGetISocket->GetUrlData(UrlRequest);

            if(ReciveDay == _xor("0b602f1dce38fd578ae43f98edb3ada1c2fc019e35f80fffa13ba29803f1797c"))
                MessageBoxA(0, _xor("The key is already activated!"), "", MB_OK);
            if(ReciveDay == _xor("1b602f1dce38fd578ae43f98edb3ada1c2fc019e35f80fffa13ba29803f1797c"))
                MessageBoxA(0, _xor("This key has expired!"), "", MB_OK);
            if (ReciveDay == _xor("2b602f1dce38fd578ae43f98edb3ada1c2fc019e35f80fffa13ba29803f1797c"))
                MessageBoxA(0, _xor("Key not found!"), "", MB_OK);
            
            if (ReciveDay == _xor("5b602f1dce38fd578ae43f98edb3ada1c2fc019e35f80fffa13ba29803f1797c"))
            {
                MessageBoxA(0, _xor("Successful activation!"), "", MB_OK);
            }

            LI_FN(exit)(3);
            return ReciveDay;
            //VMP_END;
        }
        void SendDebugInformation(std::string information = _xor(""))
        {
            std::string Serial = iGetHWID->GetHWID(WF_RU_HWID).c_str();
            std::string UrlRequest = _xor("panel/server/engine/");
            UrlRequest.append(_xor("telegram.php?serial="));
            UrlRequest.append(Serial);
            UrlRequest.append(_xor("&info="));
            UrlRequest.append(iGetISocket->base64_encode(information.c_str(),information.length()));
            static std::string ReciveDay = iGetISocket->GetUrlData(UrlRequest);

            //KeyAuthApp.webhook("ojEFAhswWO", "", "Debug:");
        }
        std::string GetDayExitingLicense(string VerSoft)
        {
            //VMP_ULTRA(_xor("GetDayExitingLicense"));
            std::string Serial = GetSerialKey(VerSoft).c_str();

            std::string UrlRequest = "panel/server/engine/";
            UrlRequest.append(_xor("getuserday.php?serial=") + Serial);
            static std::string ReciveDay = iGetISocket->GetUrlData(UrlRequest);
            return ReciveDay;
            //VMP_END;
        }
    private:
        GetISocket* iGetISocket = 0;
    };