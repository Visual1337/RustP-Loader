#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "dwmapi.lib")

#include <d3d9.h>
#include <tchar.h>
#include <dinput.h>
#include "Dwmapi.h"
#include "cGui\imgui.h"
#include "cGui\imgui_impl_dx9.h"

static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp;


extern LRESULT ImGui_ImplDX9_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
ATOM RegMyWindowClass(HINSTANCE, LPCTSTR);

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
