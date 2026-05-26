/*
 * chiiki.dll
 *
 * 使用 Microsoft Detours 内联钩子（patch 函数机器码前几字节 + trampoline），
 * 拦截所有调用路径（IAT、GetProcAddress 动态调用、同模块直接调用均有效），
 * 使进程以为系统环境是日语区域（LCID=0x0411，ACP=932）。
 *
 * 钩取的函数：
 *   GetACP / GetOEMCP / GetCPInfo
 *   MultiByteToWideChar / WideCharToMultiByte
 *   IsDBCSLeadByte / IsDBCSLeadByteEx
 *   GetThreadLocale
 *   GetSystemDefaultLCID  / GetUserDefaultLCID
 *   GetSystemDefaultLangID / GetUserDefaultLangID
 *   GetSystemDefaultUILanguage / GetUserDefaultUILanguage
 *   GetSystemDefaultLocaleName / GetUserDefaultLocaleName
 *   GetLocaleInfoA / GetLocaleInfoW
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <imm.h>
#include <detours.h>
#include <cstring>
#include <cwchar>

// ── 目标区域常量（运行时由环境变量 CPHOOK_ACP 覆盖）─────────────────────────
static UINT   TARGET_CP   = 932;
static LCID   TARGET_LCID = 0x0411;   // ja-JP
static LANGID TARGET_LANG = 0x0411;
static wchar_t TARGET_LOCALE_NAME[16] = L"ja-JP";

// 注入时捕获的真实系统 ACP（hooked 之前）
static UINT g_systemACP = CP_ACP;

// ── 原始函数指针（DetourAttach 会将其改写为 trampoline 地址）────────────────────
// 初始化为函数本身，Detours 会将其替换为 trampoline（可安全调用原始实现）
static UINT   (WINAPI* pOrig_GetACP)()                                                              = GetACP;
static UINT   (WINAPI* pOrig_GetOEMCP)()                                                            = GetOEMCP;
static BOOL   (WINAPI* pOrig_GetCPInfo)(UINT, LPCPINFO)                                             = GetCPInfo;
static int    (WINAPI* pOrig_MultiByteToWideChar)(UINT,DWORD,LPCCH,int,LPWSTR,int)                  = MultiByteToWideChar;
static int    (WINAPI* pOrig_WideCharToMultiByte)(UINT,DWORD,LPCWCH,int,LPSTR,int,LPCCH,LPBOOL)     = WideCharToMultiByte;
static BOOL   (WINAPI* pOrig_IsDBCSLeadByte)(BYTE)                                                  = IsDBCSLeadByte;
static BOOL   (WINAPI* pOrig_IsDBCSLeadByteEx)(UINT, BYTE)                                         = IsDBCSLeadByteEx;
static LCID   (WINAPI* pOrig_GetThreadLocale)()                                                     = GetThreadLocale;
static LANGID (WINAPI* pOrig_GetSystemDefaultUILanguage)()                                          = GetSystemDefaultUILanguage;
static LANGID (WINAPI* pOrig_GetUserDefaultUILanguage)()                                            = GetUserDefaultUILanguage;
static LCID   (WINAPI* pOrig_GetSystemDefaultLCID)()                                                = GetSystemDefaultLCID;
static LCID   (WINAPI* pOrig_GetUserDefaultLCID)()                                                  = GetUserDefaultLCID;
static LANGID (WINAPI* pOrig_GetSystemDefaultLangID)()                                              = GetSystemDefaultLangID;
static LANGID (WINAPI* pOrig_GetUserDefaultLangID)()                                                = GetUserDefaultLangID;
static int    (WINAPI* pOrig_GetLocaleInfoA)(LCID, LCTYPE, LPSTR, int)                              = GetLocaleInfoA;
static int    (WINAPI* pOrig_GetLocaleInfoW)(LCID, LCTYPE, LPWSTR, int)                             = GetLocaleInfoW;
static int    (WINAPI* pOrig_GetSystemDefaultLocaleName)(LPWSTR, int)                               = GetSystemDefaultLocaleName;
static int    (WINAPI* pOrig_GetUserDefaultLocaleName)(LPWSTR, int)                                 = GetUserDefaultLocaleName;
// IME
static LONG   (WINAPI* pOrig_ImmGetCompositionStringA)(HIMC, DWORD, LPVOID, DWORD)                  = ImmGetCompositionStringA;
static LONG   (WINAPI* pOrig_ImmGetCompositionStringW)(HIMC, DWORD, LPVOID, DWORD)                  = ImmGetCompositionStringW;
static DWORD  (WINAPI* pOrig_ImmGetCandidateListA)(HIMC, DWORD, LPCANDIDATELIST, DWORD)             = ImmGetCandidateListA;
static DWORD  (WINAPI* pOrig_ImmGetCandidateListW)(HIMC, DWORD, LPCANDIDATELIST, DWORD)             = ImmGetCandidateListW;
// 字体
static HFONT  (WINAPI* pOrig_CreateFontIndirectA)(const LOGFONTA*)                                  = CreateFontIndirectA;
static HFONT  (WINAPI* pOrig_CreateFontIndirectW)(const LOGFONTW*)                                  = CreateFontIndirectW;

// ── 钩子实现 ──────────────────────────────────────────────────────────────────

static UINT WINAPI Hook_GetACP()   { return TARGET_CP; }
static UINT WINAPI Hook_GetOEMCP() { return TARGET_CP; }

static BOOL WINAPI Hook_GetCPInfo(UINT cp, LPCPINFO info)
{
    if (cp == CP_ACP) cp = TARGET_CP;
    return pOrig_GetCPInfo(cp, info);
}

static int WINAPI Hook_MultiByteToWideChar(
    UINT cp, DWORD flags, LPCCH src, int srcLen, LPWSTR dst, int dstLen)
{
    if (cp == CP_ACP || cp == CP_THREAD_ACP) cp = TARGET_CP;
    return pOrig_MultiByteToWideChar(cp, flags, src, srcLen, dst, dstLen);
}

static int WINAPI Hook_WideCharToMultiByte(
    UINT cp, DWORD flags, LPCWCH src, int srcLen,
    LPSTR dst, int dstLen, LPCCH def, LPBOOL used)
{
    if (cp == CP_ACP || cp == CP_THREAD_ACP) cp = TARGET_CP;
    return pOrig_WideCharToMultiByte(cp, flags, src, srcLen, dst, dstLen, def, used);
}

// CP932 双字节前导字节：0x81-0x9F, 0xE0-0xFC
static BOOL WINAPI Hook_IsDBCSLeadByte(BYTE ch)
{
    return (ch >= 0x81 && ch <= 0x9F) || (ch >= 0xE0 && ch <= 0xFC);
}

static BOOL WINAPI Hook_IsDBCSLeadByteEx(UINT cp, BYTE ch)
{
    if (cp == CP_ACP) cp = TARGET_CP;
    return pOrig_IsDBCSLeadByteEx(cp, ch);
}

static LCID   WINAPI Hook_GetThreadLocale()              { return TARGET_LCID; }
static LANGID WINAPI Hook_GetSystemDefaultUILanguage()   { return TARGET_LANG; }
static LANGID WINAPI Hook_GetUserDefaultUILanguage()     { return TARGET_LANG; }
static LCID   WINAPI Hook_GetSystemDefaultLCID()         { return TARGET_LCID; }
static LCID   WINAPI Hook_GetUserDefaultLCID()           { return TARGET_LCID; }
static LANGID WINAPI Hook_GetSystemDefaultLangID()       { return TARGET_LANG; }
static LANGID WINAPI Hook_GetUserDefaultLangID()         { return TARGET_LANG; }

// 无条件将 Locale 替换为日语区域（与 Locale_Remulator 一致）
static int WINAPI Hook_GetLocaleInfoA(LCID, LCTYPE type, LPSTR buf, int cch)
{
    return pOrig_GetLocaleInfoA(TARGET_LCID, type, buf, cch);
}

static int WINAPI Hook_GetLocaleInfoW(LCID, LCTYPE type, LPWSTR buf, int cch)
{
    return pOrig_GetLocaleInfoW(TARGET_LCID, type, buf, cch);
}

static int WINAPI Hook_GetSystemDefaultLocaleName(LPWSTR buf, int cch)
{
    if (buf && cch > 0) {
        int len = (int)wcslen(TARGET_LOCALE_NAME) + 1;
        if (cch < len) return 0;
        wcscpy_s(buf, cch, TARGET_LOCALE_NAME);
        return len;
    }
    return (int)wcslen(TARGET_LOCALE_NAME) + 1;
}

static int WINAPI Hook_GetUserDefaultLocaleName(LPWSTR buf, int cch)
{
    return Hook_GetSystemDefaultLocaleName(buf, cch);
}

// ── IME 钩子 ──────────────────────────────────────────────────────────────────
//
// ImmGetCompositionStringA 在非日语系统下以系统 ACP（如 GBK）返回合成字符串，
// 无法表示日语字符。改为从 W 版本取 Unicode，再转为 CP932 交给游戏。

static LONG WINAPI Hook_ImmGetCompositionStringA(
    HIMC hIMC, DWORD dwIndex, LPVOID lpBuf, DWORD dwBufLen)
{
    // 只处理合成/结果字符串；其他索引直接透传
    if (dwIndex != GCS_RESULTSTR && dwIndex != GCS_COMPSTR &&
        dwIndex != GCS_RESULTREADSTR && dwIndex != GCS_COMPREADSTR)
    {
        return pOrig_ImmGetCompositionStringA(hIMC, dwIndex, lpBuf, dwBufLen);
    }

    // 先查询 Unicode 字节数
    LONG wBytes = pOrig_ImmGetCompositionStringW(hIMC, dwIndex, nullptr, 0);
    if (wBytes <= 0)
        return pOrig_ImmGetCompositionStringA(hIMC, dwIndex, lpBuf, dwBufLen);

    int wChars = wBytes / (int)sizeof(wchar_t);
    auto wBuf = new wchar_t[wChars + 1]();
    pOrig_ImmGetCompositionStringW(hIMC, dwIndex, wBuf, wBytes + (DWORD)sizeof(wchar_t));
    wBuf[wChars] = L'\0';

    LONG result;
    if (lpBuf && dwBufLen > 0) {
        // 将 Unicode 转为 CP932 写入游戏缓冲区
        result = (LONG)pOrig_WideCharToMultiByte(
            TARGET_CP, 0, wBuf, wChars, (LPSTR)lpBuf, (int)dwBufLen, nullptr, nullptr);
        if (result > 0 && (DWORD)result < dwBufLen)
            ((LPSTR)lpBuf)[result] = '\0';
    } else {
        // 仅查询所需字节数
        result = (LONG)pOrig_WideCharToMultiByte(
            TARGET_CP, 0, wBuf, wChars, nullptr, 0, nullptr, nullptr);
    }

    delete[] wBuf;
    return result;
}

// ── IME 候选列表钩子 ─────────────────────────────────────────────────────────
//
// ImmGetCandidateListA 在非日语系统下以系统 ACP（如 GBK）返回候选文字，
// 游戏将其当作 CP932 解析导致乱码。改为从 W 版取 Unicode 逐项转为 CP932 写回。

static DWORD WINAPI Hook_ImmGetCandidateListA(
    HIMC hIMC, DWORD dwIndex, LPCANDIDATELIST lpCandList, DWORD dwBufLen)
{
    DWORD ret = pOrig_ImmGetCandidateListA(hIMC, dwIndex, lpCandList, dwBufLen);
    if (lpCandList && ret > 0)
    {
        // 取 Unicode 版候选列表，用于正确编码转换
        DWORD wBufLen = pOrig_ImmGetCandidateListW(hIMC, dwIndex, nullptr, 0);
        if (wBufLen > 0)
        {
            auto wBuf = new BYTE[wBufLen]();
            auto lpCandListW = reinterpret_cast<LPCANDIDATELIST>(wBuf);
            pOrig_ImmGetCandidateListW(hIMC, dwIndex, lpCandListW, wBufLen);

            for (DWORD i = 0; i < lpCandList->dwCount; i++)
            {
                LPSTR  lstr = (LPSTR) ((LPBYTE)lpCandList  + lpCandList ->dwOffset[i]);
                LPWSTR wstr = (LPWSTR)((LPBYTE)lpCandListW + lpCandListW->dwOffset[i]);
                int wsize = (int)wcslen(wstr);
                int lsize = lstrlenA(lstr);
                if (wsize > 0 && lsize > 0)
                {
                    // 将 Unicode 候选项转为 CP932，写回 A 缓冲区（同字符数时字节数相同）
                    int n = pOrig_WideCharToMultiByte(
                        TARGET_CP, 0, wstr, wsize, lstr, (lsize + 1) * 2, nullptr, nullptr);
                    if (n > 0) lstr[n] = '\0';
                }
            }

            delete[] wBuf;
        }
    }
    return ret;
}

// ── 字体字符集钩子 ────────────────────────────────────────────────────────────
//
// 游戏在日语 Windows 上创建字体时用 DEFAULT_CHARSET，映射到 Shift-JIS。
// 在中文 Windows 上 DEFAULT_CHARSET 会映射为 GB2312，导致 GDI 用错误编码
// 解析字节，文字渲染乱码。钩住字体创建，强制设为 SHIFTJIS_CHARSET。

static inline BYTE FixCharSet(BYTE cs)
{
    return (cs == ANSI_CHARSET || cs == DEFAULT_CHARSET) ? SHIFTJIS_CHARSET : cs;
}

static HFONT WINAPI Hook_CreateFontIndirectA(const LOGFONTA* lf)
{
    if (!lf) return pOrig_CreateFontIndirectA(lf);
    LOGFONTA fixed = *lf;
    fixed.lfCharSet = FixCharSet(lf->lfCharSet);
    return pOrig_CreateFontIndirectA(&fixed);
}

static HFONT WINAPI Hook_CreateFontIndirectW(const LOGFONTW* lf)
{
    if (!lf) return pOrig_CreateFontIndirectW(lf);
    LOGFONTW fixed = *lf;
    fixed.lfCharSet = FixCharSet(lf->lfCharSet);
    return pOrig_CreateFontIndirectW(&fixed);
}

// ── 辅助：Attach / Detach 所有钩子 ───────────────────────────────────────────

static void AttachHooks()
{
    DetourAttach(&(PVOID&)pOrig_GetACP,                     Hook_GetACP);
    DetourAttach(&(PVOID&)pOrig_GetOEMCP,                   Hook_GetOEMCP);
    DetourAttach(&(PVOID&)pOrig_GetCPInfo,                  Hook_GetCPInfo);
    DetourAttach(&(PVOID&)pOrig_MultiByteToWideChar,        Hook_MultiByteToWideChar);
    DetourAttach(&(PVOID&)pOrig_WideCharToMultiByte,        Hook_WideCharToMultiByte);
    DetourAttach(&(PVOID&)pOrig_IsDBCSLeadByte,             Hook_IsDBCSLeadByte);
    DetourAttach(&(PVOID&)pOrig_IsDBCSLeadByteEx,           Hook_IsDBCSLeadByteEx);
    DetourAttach(&(PVOID&)pOrig_GetThreadLocale,            Hook_GetThreadLocale);
    DetourAttach(&(PVOID&)pOrig_GetSystemDefaultUILanguage, Hook_GetSystemDefaultUILanguage);
    DetourAttach(&(PVOID&)pOrig_GetUserDefaultUILanguage,   Hook_GetUserDefaultUILanguage);
    DetourAttach(&(PVOID&)pOrig_GetSystemDefaultLCID,       Hook_GetSystemDefaultLCID);
    DetourAttach(&(PVOID&)pOrig_GetUserDefaultLCID,         Hook_GetUserDefaultLCID);
    DetourAttach(&(PVOID&)pOrig_GetSystemDefaultLangID,     Hook_GetSystemDefaultLangID);
    DetourAttach(&(PVOID&)pOrig_GetUserDefaultLangID,       Hook_GetUserDefaultLangID);
    DetourAttach(&(PVOID&)pOrig_GetLocaleInfoA,             Hook_GetLocaleInfoA);
    DetourAttach(&(PVOID&)pOrig_GetLocaleInfoW,             Hook_GetLocaleInfoW);
    DetourAttach(&(PVOID&)pOrig_GetSystemDefaultLocaleName, Hook_GetSystemDefaultLocaleName);
    DetourAttach(&(PVOID&)pOrig_GetUserDefaultLocaleName,   Hook_GetUserDefaultLocaleName);
    DetourAttach(&(PVOID&)pOrig_ImmGetCompositionStringA,   Hook_ImmGetCompositionStringA);
    DetourAttach(&(PVOID&)pOrig_ImmGetCandidateListA,       Hook_ImmGetCandidateListA);
    DetourAttach(&(PVOID&)pOrig_CreateFontIndirectA,        Hook_CreateFontIndirectA);
    DetourAttach(&(PVOID&)pOrig_CreateFontIndirectW,        Hook_CreateFontIndirectW);
}

static void DetachHooks()
{
    DetourDetach(&(PVOID&)pOrig_GetACP,                     Hook_GetACP);
    DetourDetach(&(PVOID&)pOrig_GetOEMCP,                   Hook_GetOEMCP);
    DetourDetach(&(PVOID&)pOrig_GetCPInfo,                  Hook_GetCPInfo);
    DetourDetach(&(PVOID&)pOrig_MultiByteToWideChar,        Hook_MultiByteToWideChar);
    DetourDetach(&(PVOID&)pOrig_WideCharToMultiByte,        Hook_WideCharToMultiByte);
    DetourDetach(&(PVOID&)pOrig_IsDBCSLeadByte,             Hook_IsDBCSLeadByte);
    DetourDetach(&(PVOID&)pOrig_IsDBCSLeadByteEx,           Hook_IsDBCSLeadByteEx);
    DetourDetach(&(PVOID&)pOrig_GetThreadLocale,            Hook_GetThreadLocale);
    DetourDetach(&(PVOID&)pOrig_GetSystemDefaultUILanguage, Hook_GetSystemDefaultUILanguage);
    DetourDetach(&(PVOID&)pOrig_GetUserDefaultUILanguage,   Hook_GetUserDefaultUILanguage);
    DetourDetach(&(PVOID&)pOrig_GetSystemDefaultLCID,       Hook_GetSystemDefaultLCID);
    DetourDetach(&(PVOID&)pOrig_GetUserDefaultLCID,         Hook_GetUserDefaultLCID);
    DetourDetach(&(PVOID&)pOrig_GetSystemDefaultLangID,     Hook_GetSystemDefaultLangID);
    DetourDetach(&(PVOID&)pOrig_GetUserDefaultLangID,       Hook_GetUserDefaultLangID);
    DetourDetach(&(PVOID&)pOrig_GetLocaleInfoA,             Hook_GetLocaleInfoA);
    DetourDetach(&(PVOID&)pOrig_GetLocaleInfoW,             Hook_GetLocaleInfoW);
    DetourDetach(&(PVOID&)pOrig_GetSystemDefaultLocaleName, Hook_GetSystemDefaultLocaleName);
    DetourDetach(&(PVOID&)pOrig_GetUserDefaultLocaleName,   Hook_GetUserDefaultLocaleName);
    DetourDetach(&(PVOID&)pOrig_ImmGetCompositionStringA,   Hook_ImmGetCompositionStringA);
    DetourDetach(&(PVOID&)pOrig_ImmGetCandidateListA,       Hook_ImmGetCandidateListA);
    DetourDetach(&(PVOID&)pOrig_CreateFontIndirectA,        Hook_CreateFontIndirectA);
    DetourDetach(&(PVOID&)pOrig_CreateFontIndirectW,        Hook_CreateFontIndirectW);
}

// ── DllMain ───────────────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID)
{
    if (DetourIsHelperProcess()) return TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);

        // ── 读取环境变量 CPHOOK_ACP，设置目标区域 ──
        struct LocaleEntry { UINT cp; LCID lcid; LANGID lang; const wchar_t* name; };
        static const LocaleEntry s_table[] = {
            {  932, 0x0411, 0x0411, L"ja-JP" },  // Japanese
            {  950, 0x0404, 0x0404, L"zh-TW" },  // Traditional Chinese
            {  936, 0x0804, 0x0804, L"zh-CN" },  // Simplified Chinese
            {  949, 0x0412, 0x0412, L"ko-KR" },  // Korean
        };
        wchar_t envBuf[16] = {};
        if (GetEnvironmentVariableW(L"CPHOOK_ACP", envBuf, 16) > 0) {
            UINT cp = (UINT)wcstoul(envBuf, nullptr, 10);
            for (auto& e : s_table) {
                if (e.cp == cp) {
                    TARGET_CP   = e.cp;
                    TARGET_LCID = e.lcid;
                    TARGET_LANG = e.lang;
                    wcscpy_s(TARGET_LOCALE_NAME, e.name);
                    break;
                }
            }
        }

        // 在 hook 之前捕获真实系统 ACP
        g_systemACP = GetACP();

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        AttachHooks();
        DetourTransactionCommit();

    } else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetachHooks();
        DetourTransactionCommit();
    }

    return TRUE;
}
