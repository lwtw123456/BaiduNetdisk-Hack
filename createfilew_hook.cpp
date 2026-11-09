#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <new>
#include <utility>

#include <mutex>

#include "createfilew_hook.h"
#include "asar_patch.h"
#include "3rdparty/safetyhook.hpp"

using CreateFileWFn = HANDLE (WINAPI *)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

static const WCHAR kAsarSuffix[] = L"resources\\core.asar";
static const size_t kAsarSuffixLength = sizeof(kAsarSuffix) / sizeof(kAsarSuffix[0]) - 1;

static safetyhook::InlineHook* g_hook = nullptr;
static CreateFileWFn g_original = nullptr;

static thread_local bool g_in_hook = false;
static std::mutex g_patch_mutex;
static bool g_patch_done = false;

static void ensure_patched_once()
{
    if (g_patch_done)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(g_patch_mutex);
    if (g_patch_done)
    {
        return;
    }

    g_in_hook = true;
    asar_ensure_patched();
    g_in_hook = false;

    g_patch_done = true;
}

static HANDLE WINAPI hooked_createfilew(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    LPCWSTR fileName = lpFileName;
    WCHAR redirected[1024];
    if (lpFileName != nullptr && !g_in_hook)
    {
        size_t length = wcslen(lpFileName);
        if (length >= kAsarSuffixLength &&
            length + 9 <= sizeof(redirected) / sizeof(redirected[0]) &&
            CompareStringOrdinal(lpFileName + length - kAsarSuffixLength, -1,
                kAsarSuffix, -1, TRUE) == CSTR_EQUAL)
        {
            ensure_patched_once();
            memcpy(redirected, lpFileName, length * sizeof(WCHAR));
            memcpy(redirected + length, L".patched", 9 * sizeof(WCHAR));
            fileName = redirected;
        }
    }
    return g_original(fileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

extern "C" void InstallCreateFileWHook(void)
{
    if (g_hook != nullptr)
    {
        return;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC target = GetProcAddress(kernel32, "CreateFileW");
    auto created = safetyhook::InlineHook::create(reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(&hooked_createfilew), safetyhook::InlineHook::StartDisabled);
		
    if (!created)
    {
        return;
    }

    g_hook = new (std::nothrow) safetyhook::InlineHook(std::move(*created));
    if (g_hook == nullptr)
    {
        return;
    }
    g_original = g_hook->original<CreateFileWFn>();
    auto enabled = g_hook->enable();
    if (!enabled)
    {
        g_original = nullptr;
    }
}
