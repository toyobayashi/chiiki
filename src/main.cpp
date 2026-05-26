#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <cwchar>
#include <cstring>

// ── 将 DLL 注入目标进程 ───────────────────────────────────────────────────────

static bool InjectDLL(HANDLE hProcess, const wchar_t* dllFullPath)
{
    // 在目标进程中分配一块内存，用于存放 DLL 路径字符串
    SIZE_T pathBytes = (wcslen(dllFullPath) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    bool ok = false;
    if (WriteProcessMemory(hProcess, remote, dllFullPath, pathBytes, nullptr)) {
        // 在目标进程里启动线程调用 LoadLibraryW(dllFullPath)
        HMODULE k32  = GetModuleHandleW(L"kernel32.dll");
        auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                           GetProcAddress(k32, "LoadLibraryW"));

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                            loadLib, remote, 0, nullptr);
        if (hThread) {
            WaitForSingleObject(hThread, 10'000);   // 最多等 10 秒
            DWORD code = 0;
            GetExitCodeThread(hThread, &code);
            ok = (code != 0);   // LoadLibraryW 成功时返回非零模块句柄
            CloseHandle(hThread);
        }
    }

    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // ── 解析 --cp=XXXX 参数 ──
    UINT targetCP = 932;
    int  argOffset = 1;  // argv[下一个有效参数]的起始索引
    if (argc >= 2 && wcsncmp(argv[1], L"--cp=", 5) == 0) {
        targetCP = (UINT)wcstoul(argv[1] + 5, nullptr, 10);
        argOffset = 2;
    }

    // 通过环境变量传递目标 CP（子进程继承父进程环境）
    wchar_t cpStr[16];
    swprintf_s(cpStr, L"%u", targetCP);
    SetEnvironmentVariableW(L"CPHOOK_ACP", cpStr);

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(nullptr, dllPath, MAX_PATH);
    {
        wchar_t* p = wcsrchr(dllPath, L'\\');
        if (p) p[1] = L'\0';
    }
    wcscat_s(dllPath, L"chiiki.dll");

    // ── 解析游戏 EXE 路径 ──
    wchar_t exePath[MAX_PATH];
    if (argc > argOffset) {
        GetFullPathNameW(argv[argOffset], MAX_PATH, exePath, nullptr);
    } else {
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* p = wcsrchr(exePath, L'\\');
        if (p) p[1] = L'\0';
        wcscat_s(exePath, L"MapleStory.exe");
    }

    // ── 校验文件存在 ──
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(nullptr, dllPath, L"Error: Hook DLL not found", MB_ICONERROR);
        LocalFree(argv);
        return 1;
    }
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(nullptr, exePath, L"Error: Game executable not found", MB_ICONERROR);
        LocalFree(argv);
        return 1;
    }

    // ── 构造命令行（透传额外参数）──
    wchar_t cmdLine[4096];
    swprintf_s(cmdLine, L"\"%s\"", exePath);
    for (int i = argOffset + 1; i < argc; ++i) {
        wcscat_s(cmdLine, L" ");
        wcscat_s(cmdLine, argv[i]);
    }

    // ── 工作目录 = 游戏 EXE 所在目录 ──
    wchar_t workDir[MAX_PATH];
    wcscpy_s(workDir, exePath);
    {
        wchar_t* p = wcsrchr(workDir, L'\\');
        if (p) *p = L'\0';
    }

    // ── 以挂起方式创建游戏进程 ──
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(exePath, cmdLine,
                        nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED,
                        nullptr, workDir,
                        &si, &pi))
    {
        wchar_t msg[256];
        swprintf_s(msg, L"CreateProcess failed (code: %lu)", GetLastError());
        MessageBoxW(nullptr, msg, L"Error", MB_ICONERROR);
        LocalFree(argv);
        return 1;
    }

    // ── 注入 Hook DLL（主线程仍挂起，入口点未执行）──
    if (!InjectDLL(pi.hProcess, dllPath)) {
        wchar_t msg[256];
        swprintf_s(msg, L"DLL injection failed (code: %lu)", GetLastError());
        MessageBoxW(nullptr, msg, L"Error", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        LocalFree(argv);
        return 1;
    }

    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    LocalFree(argv);
    return 0;
}
