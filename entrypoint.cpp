#include "Socket.h"

#include <d3d11.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#include <tchar.h>
#include <string>
#include <stdio.h>
#include <direct.h>
#include <fstream>
#include <iostream>
#include "resource.h"
#include <filesystem>
#pragma comment(lib, "d3d11.lib")
#include "URL.h"
#include "cGui/WndProc.h"
#include "Protect/memory.hpp"
#include "Protect/protection.h"
#include "Protect/process.h"
#include "Auth/auth.hpp"
#include "Protect/skCrypt.h"
#include "Inject/MM.H"
#include "Inject/Code.h"
#include "cGui/imgui_internal.h"

#define Create_Thread(x) CreateThread(0, 0, x, 0, 0, 0);
#define j_Sleep(x) Sleep(x*1000);

GetIMain* iGetMain = NULL;
GetIInject* iGetIInject = nullptr;

char buffer[255] = "";

bool IsDebuggerPresentCheck()
{
	return IsDebuggerPresent();
}

bool Checker()
{
	thread_hide_debugger();
	//hide_loader_thread();

	if (check1()) exit(0);
	if (check2()) exit(0);
	if (last_error()) exit(0);
	if (close_handle()) exit(0);
	if (thread_context()) exit(0);
	if (remote_is_present()) exit(0);
	if (is_debugger_present()) exit(0);

	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(window_check), nullptr, 0, &threadId);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(ollydbg_exploit), nullptr, 0, &threadId);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(hardware_breakpoints), nullptr, 0, &threadId);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(hardware_register), nullptr, 0, &threadId);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(vmware_check), nullptr, 0, &threadId);

	if (IsDebuggerPresentCheck())
	{
		ExitProcess(0);
	}

	BOOL bDebuggerPresent;
	if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
		TRUE == bDebuggerPresent)
		ExitProcess(-1);

	std::string debuggers[] = {
		_xor("HTTP Debugger"),
		_xor("IDA: Quick start"),
		_xor("Scylla x64 v0.9.8"),
		_xor("ProcessHacker"),
		_xor("windowrenamer"),
		_xor("ResourceHacker"),
		_xor("Cheat Engine"),
	};

	for (int i = 0; i <= 3; i++)
	{
		if (FindWindowA(NULL, debuggers[i].c_str()) || FindWindowA(debuggers[i].c_str(), NULL))
		{
			KeyAuthApp.log(KeyAuthApp.data.hwid);
			KeyAuthApp.ban(_xor("FindWindowA: debuggers"));
			raise(11);
		}
	}

	if (AntiDebug::IsDebuggedHardwareBreakpoints())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggedHardwareBreakpoints"));
		raise(11);
	}
	if (IsUserEbanat())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsUserEbanat"));
		raise(11);
	}

	if (AntiDebug::IsDebuggerCloseHandle())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggerCloseHandle"));
		raise(11);
	}

	if (AntiDebug::IsDebuggedRaiseException())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggedRaiseException"));
		raise(11);
	}
	if (AntiDebug::IsDebuggedSuspendThread())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggedSuspendThread"));
		raise(11);
	}

	if (Check()) {
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("Check"));
		raise(11);
	}

	EnumWindows(FDJKFUNSYDFYDBF, 0);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(UYYFDUGHR7YGH6F), nullptr, 0, &threadId);
	LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(proverki2), nullptr, 0, &threadId);

	if (DFGHSDFGDFSG()) {
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("TestSign"));
		raise(11);
	}

	BOOL isDebuggerPresent = IsDebuggerPresent();
	if (isDebuggerPresent)
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("IsDebuggerPresent"));
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
		KeyAuthApp.ban(_xor("CMSDCNBDTA"));
		raise(11);
	}

	if (LRGFIRFGJYHFBGHGBG())
	{
		KeyAuthApp.log(KeyAuthApp.data.hwid);
		KeyAuthApp.ban(_xor("LRGFIRFGJYHFBGHGBG"));
		raise(11);
	}

	return TRUE;
}

DWORD WINAPI ThreadProc2(CONST LPVOID lpParam) {
	while (true)
	{
		Sleep(100);
		{
			LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(Checker), nullptr, 0, &threadId);
		}
	}
}

LPCSTR szClassWindow = "b3824d3d3fddf0da";
int         m_iWindowWidth = 600.000;
int         m_iWindowHeight = 400.000;

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	KeyAuthApp.init();

	if (Checker())
	{
		name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();

		char buf[MAX_PATH];
		GetModuleFileNameA(nullptr, buf, MAX_PATH);
		std::filesystem::path fnamef = std::filesystem::path(buf).filename();
		std::string fnames = iGetIInject->RandomString();
		fnames.append(_xor(".exe"));
		rename(fnamef.string().c_str(), fnames.c_str());

		LPCTSTR lpzClass = szClassWindow;
		
		if (!RegMyWindowClass(hInstance, lpzClass))
			return 1;
		std::string days = iGetMain->GetDayLicense(WF_RU_HWID);

		RECT screen_rect;
		GetWindowRect(GetDesktopWindow(), &screen_rect); 
		int x = screen_rect.right / 2 - 150;
		int y = screen_rect.bottom / 2 - 75;

		
		HWND hWnd = CreateWindow(lpzClass, szClassWindow, WS_POPUP, x, y, m_iWindowWidth, m_iWindowHeight, NULL, NULL, hInstance, NULL);

		if (!hWnd) return 2;


		LPDIRECT3D9 pD3D;
		if ((pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
		{
			UnregisterClass(lpzClass, hInstance);
		}

		ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
		g_d3dpp.Windowed = TRUE;
		g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
		g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
		g_d3dpp.EnableAutoDepthStencil = TRUE;
		g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
		g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE; 

		if (pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
		{

			pD3D->Release();
			UnregisterClass(lpzClass, hInstance);
			return 0;

		}
		else
		{
			AntiDebug::CreateThreadForDebug(ThreadProc2);
		}

		ImGui_ImplDX9_Init(hWnd, g_pd3dDevice);

		ImGuiStyle& style = ImGui::GetStyle();

		ImGuiIO& io = ImGui::GetIO();

		io.IniFilename = NULL;

		style.Colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.19f, 0.19f, 0.19f, 0.92f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.19f, 0.19f, 0.19f, 0.29f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.24f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.05f, 0.05f, 0.05f, 0.54f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.19f, 0.19f, 0.19f, 0.54f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.20f, 0.22f, 0.23f, 1.00f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.06f, 0.06f, 0.06f, 1.00f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.05f, 0.05f, 0.05f, 0.54f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.34f, 0.34f, 0.34f, 0.54f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.40f, 0.40f, 0.40f, 0.54f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.56f, 0.56f, 0.56f, 0.54f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.33f, 0.67f, 0.86f, 1.00f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.34f, 0.34f, 0.34f, 0.54f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.56f, 0.56f, 0.56f, 0.54f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.05f, 0.05f, 0.05f, 0.54f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.19f, 0.19f, 0.19f, 0.54f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.20f, 0.22f, 0.23f, 1.00f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.00f, 0.00f, 0.00f, 0.52f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.00f, 0.00f, 0.00f, 0.36f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.20f, 0.22f, 0.23f, 0.33f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.28f, 0.28f, 0.28f, 0.29f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.44f, 0.44f, 0.44f, 0.29f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.40f, 0.44f, 0.47f, 1.00f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(1.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(1.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.20f, 0.22f, 0.23f, 1.00f);

		style.WindowRounding = 0;
		style.FrameRounding = 6;

		FILE* fp; AllocConsole();
		freopen_s(&fp, "CONOUT$", "w", stdout);

		std::string consoleTitle = _("debug").decrypt();
		SetConsoleTitleA(consoleTitle.c_str());

		DownloadFileFromURL(_("https://cdn.discordapp.com/attachments/1145125599443177485/1182315135231082638/opensans.ttf?ex=65843fc6&is=6571cac6&hm=8af7fadfcfb43236c3d8501433e42d91e93a814790a86a8beb1b1a3e5d6d86d8&"), _("font.ttf"), _("C:\\Windows\\SoftwareDistribution\\Download\\font.ttf"));

		printf(_("font downloaded"));

		ImFont* loaderFont = io.Fonts->AddFontFromFileTTF(_("C:\\Windows\\SoftwareDistribution\\Download\\font.ttf"), 18.000f);

		Sleep(1000);

		printf(_("\n\nwelcome to loader"));

		MSG msg;
		ZeroMemory(&msg, sizeof(msg));
		ShowWindow(hWnd, SW_SHOWDEFAULT);
		UpdateWindow(hWnd);
		while (msg.message != WM_QUIT)
		{
			if (AntiDebug::IsDebuggedSuspendThread())
			{
				KeyAuthApp.log(KeyAuthApp.data.hwid);
				KeyAuthApp.ban(_xor("IsDebuggedSuspendThread"));
				raise(11);
			}
			if (AntiDebug::IsDebuggedHardwareBreakpoints()) 
			{
				KeyAuthApp.log(KeyAuthApp.data.hwid);
				KeyAuthApp.ban(_xor("IsDebuggedHardwareBreakpoints"));
				raise(11);
			}
			if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
				continue;
			}

			ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

			ImGui_ImplDX9_NewFrame();

			DWORD dwFlag = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

			static bool open = true;

			if (!open)
				ExitProcess(0);

			string name = _xor("");
			string version = VERSION;
			name = _xor("meta.loader");

			std::string status = _xor("Have a good day");
			ImGui::SetNextWindowSize(ImVec2(m_iWindowWidth, m_iWindowHeight));
			ImGui::PushFont(loaderFont);
			ImGui::Begin(name.c_str(), &open, dwFlag);
			{
				if (IsLicenseRU_PVP == 1)
				{
					std::string gameinfo = _xor("Game: Rust (Non-Steam)");
					std::string launcherinfo = _xor("Launcher: Alkad");
					ImGui::Text(gameinfo.c_str());
					ImGui::Text(launcherinfo.c_str());
					ImGui::PushItemWidth(m_iWindowWidth - 5);
					ImGui::Combo("", &selected_item, items, _ARRAYSIZE(items));
					if (ImGui::Button(_xor("Load")))
					{
						GlobalAddAtomA(items[selected_item]);
						if (items[selected_item] == ("meta (Release)"))
						{
							ul::VDXZ1 = true;

							printf(_("\n\nintializing security"));

							LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(OBSFIASDGDF), nullptr, 0, &threadId);
						}
						
						if (items[selected_item] == ("meta (Beta)"))
						{
							ul::VDXZ1 = true;

							LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(OBSFIASDGDF), nullptr, 0, &threadId);
						}
					}
				}
				else
				{
				ImGui::Text(_xor("Key: "));
				ImGui::InputText(_xor(""), buffer, 255);
				if (ImGui::Button(_xor("Login")))
				{
					KeyAuthApp.license(buffer);

					if (KeyAuthApp.checkblack()) {
						LI_FN(exit)(0);
					}

					if (KeyAuthApp.data.success) {
						LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(YUJTYJSGHSDGH), nullptr, 0, &threadId);
						LI_FN(CreateThread)(nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(FHTHFGSH), nullptr, 0, &threadId);
						IsLicenseRU_PVP = 1;
					}
				}
				}
			}
			ImGui::End();

			g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, false);
			g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, false);
			g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, false);


			if (g_pd3dDevice->BeginScene() >= 0)
			{
				ImGui::Render();
				g_pd3dDevice->EndScene();
			}
			g_pd3dDevice->Present(NULL, NULL, NULL, NULL);
		}

		ImGui_ImplDX9_Shutdown();
		if (g_pd3dDevice) g_pd3dDevice->Release();
		if (pD3D) pD3D->Release();
		ErasePEHeaderFromMemory();
		UnregisterClass(szClassWindow, hInstance);
		return 0;
	}

	//VMP_END;

}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	//VMP_ULTRA(_xor("WndProc"));
	if (ImGui_ImplDX9_WndProcHandler(hWnd, message, wParam, lParam))
		return true;

	switch (message)
	{

	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			ImGui_ImplDX9_InvalidateDeviceObjects();
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
			if (hr == D3DERR_INVALIDCALL)
				IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		return 0;

	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) 
			return 0;
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hWnd, message, wParam, lParam);
	//VMP_END;
}

ATOM RegMyWindowClass(HINSTANCE hInst, LPCTSTR lpzClassName)
{
	
	//VMP_ULTRA(_xor("RegMyWindowClass"));

	WNDCLASS wcWindowClass = { 0 };

	wcWindowClass.lpfnWndProc = (WNDPROC)WndProc;

	wcWindowClass.style = CS_HREDRAW | CS_VREDRAW;
	
	wcWindowClass.hInstance = hInst;

	wcWindowClass.lpszClassName = lpzClassName;

	wcWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);

	wcWindowClass.hbrBackground = (HBRUSH)COLOR_APPWORKSPACE;

	wcWindowClass.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(101));
	return RegisterClass(&wcWindowClass); 
	//VMP_END;
	
}
