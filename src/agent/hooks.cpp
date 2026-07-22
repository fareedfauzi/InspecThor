#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <winhttp.h>
#include <windns.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <shellapi.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <mmsystem.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "hooks.h"
#include "filter.h"
#include <MinHook.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <iostream>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <cwctype>

namespace Inspecthor {

// Callback registration
static TelemetryCallback g_TelemetryCallback = nullptr;
static std::mutex g_CallbackMutex;
static std::mutex g_HookStatusMutex;
static std::vector<HookStatusInfo> g_HookStatuses;
static std::mutex g_AgentPathMutex;
static std::wstring g_AgentModulePath;
static bool g_HookNetwork = true;
static bool g_HookMemoryCopies = false;
static bool g_HookHeap = false;
static bool g_HookAdvancedNative = false;
static std::atomic<bool> g_HooksActivated{ false };
static size_t g_HookAttemptIndex = 0;
static size_t g_HookAttemptLimit = 0;
static void TryInstallOpenSslHooks(HMODULE module);

void RegisterTelemetryCallback(TelemetryCallback cb) {
    std::lock_guard<std::mutex> lock(g_CallbackMutex);
    g_TelemetryCallback = cb;
}

std::vector<HookStatusInfo> GetHookStatuses() {
    std::lock_guard<std::mutex> lock(g_HookStatusMutex);
    return g_HookStatuses;
}

void SetAgentModulePath(const std::wstring& modulePath) {
    std::lock_guard<std::mutex> lock(g_AgentPathMutex);
    g_AgentModulePath = modulePath;
}

// Reentrancy protection
thread_local bool t_insideHook = false;

bool IsInsideHook() { return t_insideHook; }
void SetInsideHook(bool value) { t_insideHook = value; }

// Safe memory copy functions (No C++ object destruction in these frames to avoid C2712)
static bool SafeCopyWString(wchar_t* dest, const wchar_t* src, size_t maxCount) {
    __try {
        size_t i = 0;
        while (src[i] != 0 && i < maxCount - 1) {
            dest[i] = src[i];
            i++;
        }
        dest[i] = 0;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeCopyAString(char* dest, const char* src, size_t maxCount) {
    __try {
        size_t i = 0;
        while (src[i] != 0 && i < maxCount - 1) {
            dest[i] = src[i];
            i++;
        }
        dest[i] = 0;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeCopyBuffer(void* dest, const void* src, size_t count) {
    __try {
        memcpy(dest, src, count);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Safe Memory Reading Helpers
static std::wstring ReadWStringSafe(LPCWSTR ptr, size_t maxLen = 256) {
    if (!ptr) return L"";
    std::vector<wchar_t> temp(maxLen);
    if (SafeCopyWString(temp.data(), ptr, maxLen)) {
        return std::wstring(temp.data());
    }
    return L"<Invalid Pointer>";
}

static std::string ReadAStringSafe(LPCSTR ptr, size_t maxLen = 256) {
    if (!ptr) return "";
    std::vector<char> temp(maxLen);
    if (SafeCopyAString(temp.data(), ptr, maxLen)) {
        return std::string(temp.data());
    }
    return "<Invalid Pointer>";
}

static std::vector<uint8_t> ReadBufferSafe(const void* ptr, size_t len, size_t maxLen = 1024) {
    std::vector<uint8_t> res;
    if (!ptr || len == 0) return res;
    size_t toRead = (len > maxLen) ? maxLen : len;
    res.resize(toRead);
    if (SafeCopyBuffer(res.data(), ptr, toRead)) {
        return res;
    }
    res.clear();
    return res;
}

static constexpr size_t kMaximumFileBufferCapture = 64u * 1024u;
static constexpr size_t kMaximumMemoryBufferCapture = 64u * 1024u;

static DWORD NamedPipePeerProcessId(HANDLE pipe) {
    ULONG pid = 0;
    if (pipe && GetNamedPipeClientProcessId(pipe, &pid) && pid != GetCurrentProcessId()) return pid;
    pid = 0;
    if (pipe && GetNamedPipeServerProcessId(pipe, &pid) && pid != GetCurrentProcessId()) return pid;
    return 0;
}

static uint64_t OverlappedOffset(const OVERLAPPED* overlapped) {
    if (!overlapped) return UINT64_MAX;
    OVERLAPPED copy{};
    if (!SafeCopyBuffer(&copy, overlapped, sizeof(copy))) return UINT64_MAX;
    return (static_cast<uint64_t>(copy.OffsetHigh) << 32) | copy.Offset;
}

static uint64_t LargeIntegerOffset(const LARGE_INTEGER* offset) {
    if (!offset) return UINT64_MAX;
    LARGE_INTEGER copy{};
    return SafeCopyBuffer(&copy, offset, sizeof(copy)) ? static_cast<uint64_t>(copy.QuadPart) : UINT64_MAX;
}

static std::string WideToUtf8(const std::wstring& wstr);

static std::string ReadHandleArrayPreviewSafe(const HANDLE* handles, DWORD count) {
    if (!handles || count == 0) return "";
    DWORD limit = count > 8 ? 8 : count;
    std::vector<HANDLE> temp(limit);
    if (!SafeCopyBuffer(temp.data(), handles, sizeof(HANDLE) * limit)) {
        return "<Invalid Pointer>";
    }
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (DWORD i = 0; i < limit; ++i) {
        if (i > 0) oss << ", ";
        oss << "0x" << (uintptr_t)temp[i];
    }
    if (count > limit) oss << ", +" << (count - limit) << " more";
    return oss.str();
}

static std::string GuidToUtf8(REFGUID guid) {
    wchar_t buf[64] = {};
    if (StringFromGUID2(guid, buf, (int)(sizeof(buf) / sizeof(buf[0]))) <= 0) {
        return "";
    }
    return WideToUtf8(std::wstring(buf));
}

static std::string GuidPtrToUtf8(const GUID* guid) {
    if (!guid) return "";
    GUID copy = {};
    if (!SafeCopyBuffer(&copy, guid, sizeof(copy))) {
        return "<Invalid GUID>";
    }
    return GuidToUtf8(copy);
}

static std::string DecodeSockaddr(const struct sockaddr* name) {
    if (!name) return "";
    ADDRESS_FAMILY family = AF_UNSPEC;
    if (!SafeCopyBuffer(&family, &name->sa_family, sizeof(family))) return "";
    char address[INET6_ADDRSTRLEN] = {};
    std::ostringstream result;
    if (family == AF_INET) {
        sockaddr_in copy{};
        if (!SafeCopyBuffer(&copy, name, sizeof(copy)) || !InetNtopA(AF_INET, &copy.sin_addr, address, sizeof(address))) return "";
        result << address << ':' << ntohs(copy.sin_port);
        return result.str();
    }
    if (family == AF_INET6) {
        sockaddr_in6 copy{};
        if (!SafeCopyBuffer(&copy, name, sizeof(copy)) || !InetNtopA(AF_INET6, &copy.sin6_addr, address, sizeof(address))) return "";
        result << '[' << address << "]:" << ntohs(copy.sin6_port);
        return result.str();
    }
    return "";
}

static std::string WideToUtf8(const std::wstring& wstr);

static std::string ModuleNameToUtf8(LPCWSTR moduleName) {
    return WideToUtf8(moduleName ? std::wstring(moduleName) : L"");
}

static void RecordHookStatus(LPCWSTR moduleName, LPCSTR apiName, const char* status, const std::string& reason) {
    std::lock_guard<std::mutex> lock(g_HookStatusMutex);
    g_HookStatuses.push_back({
        apiName ? apiName : "",
        ModuleNameToUtf8(moduleName),
        status ? status : "",
        reason
    });
}

static void ClearHookStatuses() {
    std::lock_guard<std::mutex> lock(g_HookStatusMutex);
    g_HookStatuses.clear();
}

static bool InstallHookApiTracked(LPCWSTR moduleName, LPCSTR apiName, LPVOID detour, LPVOID* original) {
    ++g_HookAttemptIndex;
    if (g_HookAttemptLimit != 0 && g_HookAttemptIndex > g_HookAttemptLimit) {
        RecordHookStatus(moduleName, apiName, "Skipped", "disabled by INSPECTHOR_HOOK_LIMIT diagnostic setting");
        return false;
    }
    LPVOID target = nullptr;
    MH_STATUS status = MH_CreateHookApiEx(moduleName, apiName, detour, original, &target);
    if (status == MH_OK) {
        RecordHookStatus(moduleName, apiName, "Hooked", "");
        return true;
    }

    // Kernel32/kernelbase and Nt/Zw exports frequently resolve to the same
    // implementation. The first alias owns the hook; the others are covered.
    if (status == MH_ERROR_ALREADY_CREATED && target != nullptr) {
        RecordHookStatus(moduleName, apiName, "Hooked", "shared implementation already hooked");
        return true;
    }

    const char* reason = MH_StatusToString(status);
    if (status == MH_ERROR_MODULE_NOT_FOUND) {
        RecordHookStatus(moduleName, apiName, "Module Not Loaded", reason ? reason : "module not loaded");
    } else if (status == MH_ERROR_FUNCTION_NOT_FOUND) {
        RecordHookStatus(moduleName, apiName, "Skipped", reason ? reason : "function not exported");
    } else {
        RecordHookStatus(moduleName, apiName, "Failed", reason ? reason : "hook creation failed");
    }
    return false;
}

static std::wstring GetAgentModulePath() {
    std::lock_guard<std::mutex> lock(g_AgentPathMutex);
    return g_AgentModulePath;
}

static bool IsSameArchitectureProcess(HANDLE hProcess) {
    typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto pIsWow64Process2 = kernel32 ? (IsWow64Process2_t)GetProcAddress(kernel32, "IsWow64Process2") : nullptr;

    if (pIsWow64Process2) {
        USHORT currentMachine = 0;
        USHORT currentNative = 0;
        USHORT targetMachine = 0;
        USHORT targetNative = 0;
        if (pIsWow64Process2(GetCurrentProcess(), &currentMachine, &currentNative) &&
            pIsWow64Process2(hProcess, &targetMachine, &targetNative)) {
            return currentMachine == targetMachine;
        }
    }

    BOOL currentWow64 = FALSE;
    BOOL targetWow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &currentWow64) &&
        IsWow64Process(hProcess, &targetWow64)) {
        return currentWow64 == targetWow64;
    }

    return true;
}

static bool InjectAgentIntoProcess(HANDLE hProcess) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid == 0 || targetPid == GetCurrentProcessId()) {
        return false;
    }

    std::wstring dllPath = GetAgentModulePath();
    if (dllPath.empty() || !IsSameArchitectureProcess(hProcess)) {
        return false;
    }

    size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), bytes, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    LPVOID loadLibraryWAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryWAddr, remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return true;
}

static bool InjectAgentIntoThreadOwner(HANDLE hThread) {
    if (!hThread || hThread == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD pid = GetProcessIdOfThread(hThread);
    if (pid == 0 || pid == GetCurrentProcessId()) {
        return false;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProcess) {
        return false;
    }

    bool injected = InjectAgentIntoProcess(hProcess);
    CloseHandle(hProcess);
    return injected;
}

static uint64_t ResolveModuleBase(void* address) {
    HMODULE hMod = NULL;
    BOOL success = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)address,
        &hMod
    );
    return success && hMod ? reinterpret_cast<uint64_t>(hMod) : 0;
}

// Helper to convert wstring to string
static std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Global Filter Instance
static CallerFilter g_CallerFilter;

void ConfigureFilter(const TraceConfig& config) {
    g_CallerFilter.Configure(config);
    g_HookNetwork = (config.flags & TraceConfigHookNetwork) != 0;
    g_HookMemoryCopies = (config.flags & TraceConfigHookMemoryCopies) != 0;
    if (GetEnvironmentVariableW(L"INSPECTHOR_FORCE_MEMORY_COPY_HOOKS", nullptr, 0) > 0) g_HookMemoryCopies = true;
    g_HookHeap = (config.flags & TraceConfigHookHeap) != 0;
    g_HookAdvancedNative = (config.flags & TraceConfigHookAdvancedNative) != 0;
}

// Logs the event and notifies the telemetry queue
static void LogTelemetry(
    const std::string& apiName,
    const std::string& dllName,
    void* callerAddress,
    uint64_t returnValue,
    const std::vector<ParameterCapture>& params
) {
    std::string callerModule;
    void* tracedCallerAddress = callerAddress;

    void* stackFrames[32] = {};
    USHORT frames = CaptureStackBackTrace(1, 32, stackFrames, nullptr);
    if (!g_CallerFilter.ShouldTrace(callerAddress, callerModule)) {
        bool foundTraceableFrame = false;
        for (USHORT i = 0; i < frames; ++i) {
            std::string stackModule;
            if (g_CallerFilter.ShouldTrace(stackFrames[i], stackModule)) {
                callerModule = stackModule;
                tracedCallerAddress = stackFrames[i];
                foundTraceableFrame = true;
                break;
            }
        }
        if (!foundTraceableFrame) {
            return; // Suppress trace based on caller filtering rules
        }
    }

    TelemetryEvent ev;
    ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    ev.processId = GetCurrentProcessId();
    ev.threadId = GetCurrentThreadId();
    ev.apiName = apiName;
    ev.dllName = dllName;
    ev.callerAddress = (uint64_t)tracedCallerAddress;
    ev.callerModule = callerModule;
    ev.callerModuleBase = ResolveModuleBase(tracedCallerAddress);
    ev.returnValue = returnValue;
    ev.parameters = params;

    for (USHORT i = 0; i < frames; ++i) {
        ev.callStack.push_back((uint64_t)stackFrames[i]);
    }

    std::lock_guard<std::mutex> lock(g_CallbackMutex);
    if (g_TelemetryCallback) {
        g_TelemetryCallback(ev);
    }
}

// ----------------------------------------------------
// HOOK SIGNATURES & Detour Functions
// ----------------------------------------------------

// 1. CreateProcessW
typedef BOOL(WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static CreateProcessW_t pfnCreateProcessW = nullptr;
static BOOL WINAPI Detour_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    HookGuard guard;
    BOOL res = pfnCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if (res && lpProcessInformation && lpProcessInformation->hProcess) {
        InjectAgentIntoProcess(lpProcessInformation->hProcess);
    }
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpApplicationName", "LPCWSTR", (uint64_t)lpApplicationName, {}, WideToUtf8(ReadWStringSafe(lpApplicationName, 2048))},
            {"lpCommandLine", "LPWSTR", (uint64_t)lpCommandLine, {}, WideToUtf8(ReadWStringSafe(lpCommandLine, 8192))},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"hProcess", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hProcess : nullptr), {}, ""},
            {"hThread", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hThread : nullptr), {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwProcessId : 0), {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwThreadId : 0), {}, ""}
        };
        LogTelemetry("CreateProcessW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
static CreateProcessA_t pfnCreateProcessA = nullptr;
static BOOL WINAPI Detour_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    HookGuard guard;
    BOOL res = pfnCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if (res && lpProcessInformation && lpProcessInformation->hProcess) {
        InjectAgentIntoProcess(lpProcessInformation->hProcess);
    }
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpApplicationName", "LPCSTR", (uint64_t)lpApplicationName, {}, ReadAStringSafe(lpApplicationName, 2048)},
            {"lpCommandLine", "LPSTR", (uint64_t)lpCommandLine, {}, ReadAStringSafe(lpCommandLine, 8192)},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"hProcess", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hProcess : nullptr), {}, ""},
            {"hThread", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hThread : nullptr), {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwProcessId : 0), {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwThreadId : 0), {}, ""}
        };
        LogTelemetry("CreateProcessA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreateProcessAsUserW_t)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static CreateProcessAsUserW_t pfnCreateProcessAsUserW = nullptr;
static BOOL WINAPI Detour_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    HookGuard guard;
    BOOL res = pfnCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if (res && lpProcessInformation && lpProcessInformation->hProcess) {
        InjectAgentIntoProcess(lpProcessInformation->hProcess);
    }
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hToken", "HANDLE", (uint64_t)hToken, {}, ""},
            {"lpApplicationName", "LPCWSTR", (uint64_t)lpApplicationName, {}, WideToUtf8(ReadWStringSafe(lpApplicationName, 2048))},
            {"lpCommandLine", "LPWSTR", (uint64_t)lpCommandLine, {}, WideToUtf8(ReadWStringSafe(lpCommandLine, 8192))},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"hProcess", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hProcess : nullptr), {}, ""},
            {"hThread", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hThread : nullptr), {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwProcessId : 0), {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwThreadId : 0), {}, ""}
        };
        LogTelemetry("CreateProcessAsUserW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreateProcessAsUserA_t)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
static CreateProcessAsUserA_t pfnCreateProcessAsUserA = nullptr;
static BOOL WINAPI Detour_CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    HookGuard guard;
    BOOL res = pfnCreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if (res && lpProcessInformation && lpProcessInformation->hProcess) {
        InjectAgentIntoProcess(lpProcessInformation->hProcess);
    }
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hToken", "HANDLE", (uint64_t)hToken, {}, ""},
            {"lpApplicationName", "LPCSTR", (uint64_t)lpApplicationName, {}, ReadAStringSafe(lpApplicationName, 2048)},
            {"lpCommandLine", "LPSTR", (uint64_t)lpCommandLine, {}, ReadAStringSafe(lpCommandLine, 8192)},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"hProcess", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hProcess : nullptr), {}, ""},
            {"hThread", "HANDLE", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->hThread : nullptr), {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwProcessId : 0), {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)((res && lpProcessInformation) ? lpProcessInformation->dwThreadId : 0), {}, ""}
        };
        LogTelemetry("CreateProcessAsUserA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef UINT(WINAPI* WinExec_t)(LPCSTR, UINT);
static WinExec_t pfnWinExec = nullptr;
static UINT WINAPI Detour_WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {
    HookGuard guard;
    UINT res = pfnWinExec(lpCmdLine, uCmdShow);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpCmdLine", "LPCSTR", (uint64_t)lpCmdLine, {}, ReadAStringSafe(lpCmdLine)},
            {"uCmdShow", "UINT", (uint64_t)uCmdShow, {}, ""}
        };
        LogTelemetry("WinExec", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINSTANCE(WINAPI* ShellExecuteW_t)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
static ShellExecuteW_t pfnShellExecuteW = nullptr;
static HINSTANCE WINAPI Detour_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd) {
    HookGuard guard;
    HINSTANCE res = pfnShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpOperation", "LPCWSTR", (uint64_t)lpOperation, {}, WideToUtf8(ReadWStringSafe(lpOperation))},
            {"lpFile", "LPCWSTR", (uint64_t)lpFile, {}, WideToUtf8(ReadWStringSafe(lpFile, 2048))},
            {"lpParameters", "LPCWSTR", (uint64_t)lpParameters, {}, WideToUtf8(ReadWStringSafe(lpParameters, 8192))},
            {"lpDirectory", "LPCWSTR", (uint64_t)lpDirectory, {}, WideToUtf8(ReadWStringSafe(lpDirectory))},
            {"nShowCmd", "INT", (uint64_t)nShowCmd, {}, ""}
        };
        LogTelemetry("ShellExecuteW", "shell32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINSTANCE(WINAPI* ShellExecuteA_t)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
static ShellExecuteA_t pfnShellExecuteA = nullptr;
static HINSTANCE WINAPI Detour_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) {
    HookGuard guard;
    HINSTANCE res = pfnShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpOperation", "LPCSTR", (uint64_t)lpOperation, {}, ReadAStringSafe(lpOperation)},
            {"lpFile", "LPCSTR", (uint64_t)lpFile, {}, ReadAStringSafe(lpFile, 2048)},
            {"lpParameters", "LPCSTR", (uint64_t)lpParameters, {}, ReadAStringSafe(lpParameters, 8192)},
            {"lpDirectory", "LPCSTR", (uint64_t)lpDirectory, {}, ReadAStringSafe(lpDirectory)},
            {"nShowCmd", "INT", (uint64_t)nShowCmd, {}, ""}
        };
        LogTelemetry("ShellExecuteA", "shell32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ShellExecuteExW_t)(SHELLEXECUTEINFOW*);
static ShellExecuteExW_t pfnShellExecuteExW = nullptr;
static BOOL WINAPI Detour_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    HookGuard guard;
    BOOL res = pfnShellExecuteExW(pExecInfo);
    if (!guard.WasInside()) {
        DWORD pid = (res && pExecInfo && pExecInfo->hProcess) ? GetProcessId(pExecInfo->hProcess) : 0;
        if (res && pExecInfo && pExecInfo->hProcess) {
            InjectAgentIntoProcess(pExecInfo->hProcess);
        }
        std::vector<ParameterCapture> params = {
            {"lpVerb", "LPCWSTR", (uint64_t)(pExecInfo ? pExecInfo->lpVerb : nullptr), {}, WideToUtf8(ReadWStringSafe(pExecInfo ? pExecInfo->lpVerb : nullptr))},
            {"lpFile", "LPCWSTR", (uint64_t)(pExecInfo ? pExecInfo->lpFile : nullptr), {}, WideToUtf8(ReadWStringSafe(pExecInfo ? pExecInfo->lpFile : nullptr, 2048))},
            {"lpParameters", "LPCWSTR", (uint64_t)(pExecInfo ? pExecInfo->lpParameters : nullptr), {}, WideToUtf8(ReadWStringSafe(pExecInfo ? pExecInfo->lpParameters : nullptr, 8192))},
            {"lpDirectory", "LPCWSTR", (uint64_t)(pExecInfo ? pExecInfo->lpDirectory : nullptr), {}, WideToUtf8(ReadWStringSafe(pExecInfo ? pExecInfo->lpDirectory : nullptr))},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""}
        };
        LogTelemetry("ShellExecuteExW", "shell32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ShellExecuteExA_t)(SHELLEXECUTEINFOA*);
static ShellExecuteExA_t pfnShellExecuteExA = nullptr;
static BOOL WINAPI Detour_ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo) {
    HookGuard guard;
    BOOL res = pfnShellExecuteExA(pExecInfo);
    if (!guard.WasInside()) {
        DWORD pid = (res && pExecInfo && pExecInfo->hProcess) ? GetProcessId(pExecInfo->hProcess) : 0;
        if (res && pExecInfo && pExecInfo->hProcess) {
            InjectAgentIntoProcess(pExecInfo->hProcess);
        }
        std::vector<ParameterCapture> params = {
            {"lpVerb", "LPCSTR", (uint64_t)(pExecInfo ? pExecInfo->lpVerb : nullptr), {}, ReadAStringSafe(pExecInfo ? pExecInfo->lpVerb : nullptr)},
            {"lpFile", "LPCSTR", (uint64_t)(pExecInfo ? pExecInfo->lpFile : nullptr), {}, ReadAStringSafe(pExecInfo ? pExecInfo->lpFile : nullptr, 2048)},
            {"lpParameters", "LPCSTR", (uint64_t)(pExecInfo ? pExecInfo->lpParameters : nullptr), {}, ReadAStringSafe(pExecInfo ? pExecInfo->lpParameters : nullptr, 8192)},
            {"lpDirectory", "LPCSTR", (uint64_t)(pExecInfo ? pExecInfo->lpDirectory : nullptr), {}, ReadAStringSafe(pExecInfo ? pExecInfo->lpDirectory : nullptr)},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""}
        };
        LogTelemetry("ShellExecuteExA", "shell32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 2. CreateFileW
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileW_t pfnCreateFileW = nullptr;
static HANDLE WINAPI Detour_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HookGuard guard;
    HANDLE res = pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpFileName", "LPCWSTR", (uint64_t)lpFileName, {}, WideToUtf8(ReadWStringSafe(lpFileName))},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwShareMode", "DWORD", (uint64_t)dwShareMode, {}, ""},
            {"dwCreationDisposition", "DWORD", (uint64_t)dwCreationDisposition, {}, ""},
            {"dwFlagsAndAttributes", "DWORD", (uint64_t)dwFlagsAndAttributes, {}, ""}
        };
        LogTelemetry("CreateFileW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileA_t pfnCreateFileA = nullptr;
static HANDLE WINAPI Detour_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HookGuard guard;
    HANDLE res = pfnCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpFileName", "LPCSTR", (uint64_t)lpFileName, {}, ReadAStringSafe(lpFileName)},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwShareMode", "DWORD", (uint64_t)dwShareMode, {}, ""},
            {"dwCreationDisposition", "DWORD", (uint64_t)dwCreationDisposition, {}, ""},
            {"dwFlagsAndAttributes", "DWORD", (uint64_t)dwFlagsAndAttributes, {}, ""}
        };
        LogTelemetry("CreateFileA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
static DeleteFileW_t pfnDeleteFileW = nullptr;
static BOOL WINAPI Detour_DeleteFileW(LPCWSTR lpFileName) {
    HookGuard guard;
    BOOL res = pfnDeleteFileW(lpFileName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpFileName", "LPCWSTR", (uint64_t)lpFileName, {}, WideToUtf8(ReadWStringSafe(lpFileName))}
        };
        LogTelemetry("DeleteFileW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* DeleteFileA_t)(LPCSTR);
static DeleteFileA_t pfnDeleteFileA = nullptr;
static BOOL WINAPI Detour_DeleteFileA(LPCSTR lpFileName) {
    HookGuard guard;
    BOOL res = pfnDeleteFileA(lpFileName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpFileName", "LPCSTR", (uint64_t)lpFileName, {}, ReadAStringSafe(lpFileName)}
        };
        LogTelemetry("DeleteFileA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CopyFileW_t)(LPCWSTR, LPCWSTR, BOOL);
static CopyFileW_t pfnCopyFileW = nullptr;
static BOOL WINAPI Detour_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
    HookGuard guard;
    BOOL res = pfnCopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCWSTR", (uint64_t)lpExistingFileName, {}, WideToUtf8(ReadWStringSafe(lpExistingFileName))},
            {"lpNewFileName", "LPCWSTR", (uint64_t)lpNewFileName, {}, WideToUtf8(ReadWStringSafe(lpNewFileName))},
            {"bFailIfExists", "BOOL", (uint64_t)bFailIfExists, {}, ""}
        };
        LogTelemetry("CopyFileW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CopyFileA_t)(LPCSTR, LPCSTR, BOOL);
static CopyFileA_t pfnCopyFileA = nullptr;
static BOOL WINAPI Detour_CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists) {
    HookGuard guard;
    BOOL res = pfnCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCSTR", (uint64_t)lpExistingFileName, {}, ReadAStringSafe(lpExistingFileName)},
            {"lpNewFileName", "LPCSTR", (uint64_t)lpNewFileName, {}, ReadAStringSafe(lpNewFileName)},
            {"bFailIfExists", "BOOL", (uint64_t)bFailIfExists, {}, ""}
        };
        LogTelemetry("CopyFileA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CopyFileExW_t)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
static CopyFileExW_t pfnCopyFileExW = nullptr;
static BOOL WINAPI Detour_CopyFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags) {
    HookGuard guard;
    BOOL res = pfnCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCWSTR", (uint64_t)lpExistingFileName, {}, WideToUtf8(ReadWStringSafe(lpExistingFileName))},
            {"lpNewFileName", "LPCWSTR", (uint64_t)lpNewFileName, {}, WideToUtf8(ReadWStringSafe(lpNewFileName))},
            {"dwCopyFlags", "DWORD", (uint64_t)dwCopyFlags, {}, ""}
        };
        LogTelemetry("CopyFileExW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CopyFileExA_t)(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
static CopyFileExA_t pfnCopyFileExA = nullptr;
static BOOL WINAPI Detour_CopyFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags) {
    HookGuard guard;
    BOOL res = pfnCopyFileExA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCSTR", (uint64_t)lpExistingFileName, {}, ReadAStringSafe(lpExistingFileName)},
            {"lpNewFileName", "LPCSTR", (uint64_t)lpNewFileName, {}, ReadAStringSafe(lpNewFileName)},
            {"dwCopyFlags", "DWORD", (uint64_t)dwCopyFlags, {}, ""}
        };
        LogTelemetry("CopyFileExA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* MoveFileW_t)(LPCWSTR, LPCWSTR);
static MoveFileW_t pfnMoveFileW = nullptr;
static BOOL WINAPI Detour_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    HookGuard guard;
    BOOL res = pfnMoveFileW(lpExistingFileName, lpNewFileName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCWSTR", (uint64_t)lpExistingFileName, {}, WideToUtf8(ReadWStringSafe(lpExistingFileName))},
            {"lpNewFileName", "LPCWSTR", (uint64_t)lpNewFileName, {}, WideToUtf8(ReadWStringSafe(lpNewFileName))}
        };
        LogTelemetry("MoveFileW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* MoveFileA_t)(LPCSTR, LPCSTR);
static MoveFileA_t pfnMoveFileA = nullptr;
static BOOL WINAPI Detour_MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) {
    HookGuard guard;
    BOOL res = pfnMoveFileA(lpExistingFileName, lpNewFileName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCSTR", (uint64_t)lpExistingFileName, {}, ReadAStringSafe(lpExistingFileName)},
            {"lpNewFileName", "LPCSTR", (uint64_t)lpNewFileName, {}, ReadAStringSafe(lpNewFileName)}
        };
        LogTelemetry("MoveFileA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* MoveFileExW_t)(LPCWSTR, LPCWSTR, DWORD);
static MoveFileExW_t pfnMoveFileExW = nullptr;
static BOOL WINAPI Detour_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags) {
    HookGuard guard;
    BOOL res = pfnMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCWSTR", (uint64_t)lpExistingFileName, {}, WideToUtf8(ReadWStringSafe(lpExistingFileName))},
            {"lpNewFileName", "LPCWSTR", (uint64_t)lpNewFileName, {}, WideToUtf8(ReadWStringSafe(lpNewFileName))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("MoveFileExW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* MoveFileExA_t)(LPCSTR, LPCSTR, DWORD);
static MoveFileExA_t pfnMoveFileExA = nullptr;
static BOOL WINAPI Detour_MoveFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags) {
    HookGuard guard;
    BOOL res = pfnMoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpExistingFileName", "LPCSTR", (uint64_t)lpExistingFileName, {}, ReadAStringSafe(lpExistingFileName)},
            {"lpNewFileName", "LPCSTR", (uint64_t)lpNewFileName, {}, ReadAStringSafe(lpNewFileName)},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("MoveFileExA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreateDirectoryW_t)(LPCWSTR, LPSECURITY_ATTRIBUTES);
static CreateDirectoryW_t pfnCreateDirectoryW = nullptr;
static BOOL WINAPI Detour_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HookGuard guard;
    BOOL res = pfnCreateDirectoryW(lpPathName, lpSecurityAttributes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpPathName", "LPCWSTR", (uint64_t)lpPathName, {}, WideToUtf8(ReadWStringSafe(lpPathName))}
        };
        LogTelemetry("CreateDirectoryW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreateDirectoryA_t)(LPCSTR, LPSECURITY_ATTRIBUTES);
static CreateDirectoryA_t pfnCreateDirectoryA = nullptr;
static BOOL WINAPI Detour_CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HookGuard guard;
    BOOL res = pfnCreateDirectoryA(lpPathName, lpSecurityAttributes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpPathName", "LPCSTR", (uint64_t)lpPathName, {}, ReadAStringSafe(lpPathName)}
        };
        LogTelemetry("CreateDirectoryA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* RemoveDirectoryW_t)(LPCWSTR);
static RemoveDirectoryW_t pfnRemoveDirectoryW = nullptr;
static BOOL WINAPI Detour_RemoveDirectoryW(LPCWSTR lpPathName) {
    HookGuard guard;
    BOOL res = pfnRemoveDirectoryW(lpPathName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpPathName", "LPCWSTR", (uint64_t)lpPathName, {}, WideToUtf8(ReadWStringSafe(lpPathName))}
        };
        LogTelemetry("RemoveDirectoryW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* RemoveDirectoryA_t)(LPCSTR);
static RemoveDirectoryA_t pfnRemoveDirectoryA = nullptr;
static BOOL WINAPI Detour_RemoveDirectoryA(LPCSTR lpPathName) {
    HookGuard guard;
    BOOL res = pfnRemoveDirectoryA(lpPathName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpPathName", "LPCSTR", (uint64_t)lpPathName, {}, ReadAStringSafe(lpPathName)}
        };
        LogTelemetry("RemoveDirectoryA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 3. ReadFile
typedef BOOL(WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_t pfnReadFile = nullptr;
static BOOL WINAPI Detour_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    BOOL res = pfnReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    DWORD lastError = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        DWORD read = 0;
        if (res && lpNumberOfBytesRead) SafeCopyBuffer(&read, lpNumberOfBytesRead, sizeof(read));
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, read, kMaximumFileBufferCapture), ""},
            {"nNumberOfBytesToRead", "DWORD", (uint64_t)nNumberOfBytesToRead, {}, ""},
            {"NumberOfBytesTransferred", "DWORD", (uint64_t)read, {}, ""},
            {"FileOffset", "UINT64", OverlappedOffset(lpOverlapped), {}, ""},
            {"Asynchronous", "BOOL", lpOverlapped ? 1ull : 0ull, {}, ""}
            ,{"LastError", "DWORD", (uint64_t)lastError, {}, ""}, {"PeerProcessId", "DWORD", NamedPipePeerProcessId(hFile), {}, ""}
        };
        LogTelemetry("ReadFile", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(lastError);
    return res;
}

typedef BOOL(WINAPI* ReadFileEx_t)(HANDLE, LPVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
static ReadFileEx_t pfnReadFileEx = nullptr;
static BOOL WINAPI Detour_ReadFileEx(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    BOOL res = pfnReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
    DWORD lastError = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, {}, ""},
            {"nNumberOfBytesToRead", "DWORD", (uint64_t)nNumberOfBytesToRead, {}, ""},
            {"FileOffset", "UINT64", OverlappedOffset(lpOverlapped), {}, ""},
            {"Asynchronous", "BOOL", 1, {}, ""},
            {"LastError", "DWORD", (uint64_t)lastError, {}, ""}
        };
        LogTelemetry("ReadFileEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(lastError);
    return res;
}

// 4. WriteFile
typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static WriteFile_t pfnWriteFile = nullptr;
static BOOL WINAPI Detour_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    BOOL res = pfnWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    DWORD lastError = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        DWORD written = 0;
        if (res && lpNumberOfBytesWritten) SafeCopyBuffer(&written, lpNumberOfBytesWritten, sizeof(written));
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPCVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, nNumberOfBytesToWrite, kMaximumFileBufferCapture), ""},
            {"nNumberOfBytesToWrite", "DWORD", (uint64_t)nNumberOfBytesToWrite, {}, ""},
            {"NumberOfBytesTransferred", "DWORD", (uint64_t)written, {}, ""},
            {"FileOffset", "UINT64", OverlappedOffset(lpOverlapped), {}, ""},
            {"Asynchronous", "BOOL", lpOverlapped ? 1ull : 0ull, {}, ""},
            {"LastError", "DWORD", (uint64_t)lastError, {}, ""}, {"PeerProcessId", "DWORD", NamedPipePeerProcessId(hFile), {}, ""}
        };
        LogTelemetry("WriteFile", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(lastError);
    return res;
}

typedef BOOL(WINAPI* WriteFileEx_t)(HANDLE, LPCVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
static WriteFileEx_t pfnWriteFileEx = nullptr;
static BOOL WINAPI Detour_WriteFileEx(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    BOOL res = pfnWriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
    DWORD lastError = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPCVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, nNumberOfBytesToWrite, kMaximumFileBufferCapture), ""},
            {"nNumberOfBytesToWrite", "DWORD", (uint64_t)nNumberOfBytesToWrite, {}, ""},
            {"FileOffset", "UINT64", OverlappedOffset(lpOverlapped), {}, ""},
            {"Asynchronous", "BOOL", 1, {}, ""},
            {"LastError", "DWORD", (uint64_t)lastError, {}, ""}
        };
        LogTelemetry("WriteFileEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(lastError);
    return res;
}

typedef BOOL(WINAPI* SetFileInformationByHandle_t)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
static SetFileInformationByHandle_t pfnSetFileInformationByHandle = nullptr;
static BOOL WINAPI Detour_SetFileInformationByHandle(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize) {
    HookGuard guard;
    BOOL res = pfnSetFileInformationByHandle(hFile, FileInformationClass, lpFileInformation, dwBufferSize);
    if (!guard.WasInside()) {
        std::vector<uint8_t> information = ReadBufferSafe(lpFileInformation, dwBufferSize, kMaximumFileBufferCapture);
        std::string decoded;
        if (((int)FileInformationClass == 3 || (int)FileInformationClass == 22) &&
            information.size() >= offsetof(FILE_RENAME_INFO, FileName)) {
            FILE_RENAME_INFO header{};
            size_t headerBytes = (std::min)(information.size(), sizeof(header));
            memcpy(&header, information.data(), headerBytes);
            size_t available = information.size() - offsetof(FILE_RENAME_INFO, FileName);
            size_t bytes = (std::min)(available, (size_t)header.FileNameLength);
            if (bytes >= sizeof(wchar_t)) {
                std::wstring name(bytes / sizeof(wchar_t), L'\0');
                memcpy(name.data(), information.data() + offsetof(FILE_RENAME_INFO, FileName), name.size() * sizeof(wchar_t));
                decoded = WideToUtf8(name);
            }
        }
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"FileInformationClass", "FILE_INFO_BY_HANDLE_CLASS", (uint64_t)FileInformationClass, {}, ""},
            {"lpFileInformation", "LPVOID", (uint64_t)lpFileInformation, std::move(information), decoded},
            {"lpNewFileName", "UNICODE_STRING", 0, {}, decoded}
        };
        LogTelemetry("SetFileInformationByHandle", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetFilePointerEx_t)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
static SetFilePointerEx_t pfnSetFilePointerEx = nullptr;
static BOOL WINAPI Detour_SetFilePointerEx(HANDLE hFile, LARGE_INTEGER distance, PLARGE_INTEGER newPointer, DWORD moveMethod) {
    HookGuard guard;
    BOOL result = pfnSetFilePointerEx(hFile, distance, newPointer, moveMethod);
    LARGE_INTEGER position{};
    if (result && newPointer) SafeCopyBuffer(&position, newPointer, sizeof(position));
    if (!guard.WasInside()) LogTelemetry("SetFilePointerEx", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
        {"Distance", "INT64", (uint64_t)distance.QuadPart, {}, ""},
        {"NewFilePointer", "UINT64", (uint64_t)position.QuadPart, {}, ""},
        {"MoveMethod", "DWORD", (uint64_t)moveMethod, {}, ""}
    });
    return result;
}

typedef BOOL(WINAPI* SetEndOfFile_t)(HANDLE);
static SetEndOfFile_t pfnSetEndOfFile = nullptr;
static BOOL WINAPI Detour_SetEndOfFile(HANDLE hFile) {
    HookGuard guard;
    BOOL result = pfnSetEndOfFile(hFile);
    if (!guard.WasInside()) LogTelemetry("SetEndOfFile", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"hFile", "HANDLE", (uint64_t)hFile, {}, ""}});
    return result;
}

typedef BOOL(WINAPI* FlushFileBuffers_t)(HANDLE);
static FlushFileBuffers_t pfnFlushFileBuffers = nullptr;
static BOOL WINAPI Detour_FlushFileBuffers(HANDLE hFile) {
    HookGuard guard;
    BOOL result = pfnFlushFileBuffers(hFile);
    if (!guard.WasInside()) LogTelemetry("FlushFileBuffers", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"hFile", "HANDLE", (uint64_t)hFile, {}, ""}});
    return result;
}

#define DEFINE_FILE_PATH_BOOL_HOOK(Name, ParamName) \
typedef BOOL(WINAPI* Name##W_t)(LPCWSTR); \
static Name##W_t pfn##Name##W = nullptr; \
static BOOL WINAPI Detour_##Name##W(LPCWSTR path) { HookGuard guard; BOOL result = pfn##Name##W(path); if (!guard.WasInside()) LogTelemetry(#Name "W", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {{ParamName, "LPCWSTR", (uint64_t)path, {}, WideToUtf8(ReadWStringSafe(path))}}); return result; } \
typedef BOOL(WINAPI* Name##A_t)(LPCSTR); \
static Name##A_t pfn##Name##A = nullptr; \
static BOOL WINAPI Detour_##Name##A(LPCSTR path) { HookGuard guard; BOOL result = pfn##Name##A(path); if (!guard.WasInside()) LogTelemetry(#Name "A", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {{ParamName, "LPCSTR", (uint64_t)path, {}, ReadAStringSafe(path)}}); return result; }

DEFINE_FILE_PATH_BOOL_HOOK(SetFileAttributes, "lpFileName")

typedef BOOL(WINAPI* CreateHardLinkW_t)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
static CreateHardLinkW_t pfnCreateHardLinkW = nullptr;
static BOOL WINAPI Detour_CreateHardLinkW(LPCWSTR link, LPCWSTR existing, LPSECURITY_ATTRIBUTES attributes) {
    HookGuard guard; BOOL result = pfnCreateHardLinkW(link, existing, attributes);
    if (!guard.WasInside()) LogTelemetry("CreateHardLinkW", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCWSTR", (uint64_t)link, {}, WideToUtf8(ReadWStringSafe(link))}, {"lpNewFileName", "LPCWSTR", (uint64_t)existing, {}, WideToUtf8(ReadWStringSafe(existing))}
    }); return result;
}
typedef BOOL(WINAPI* CreateHardLinkA_t)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
static CreateHardLinkA_t pfnCreateHardLinkA = nullptr;
static BOOL WINAPI Detour_CreateHardLinkA(LPCSTR link, LPCSTR existing, LPSECURITY_ATTRIBUTES attributes) {
    HookGuard guard; BOOL result = pfnCreateHardLinkA(link, existing, attributes);
    if (!guard.WasInside()) LogTelemetry("CreateHardLinkA", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCSTR", (uint64_t)link, {}, ReadAStringSafe(link)}, {"lpNewFileName", "LPCSTR", (uint64_t)existing, {}, ReadAStringSafe(existing)}
    }); return result;
}

typedef BOOL(WINAPI* GetFileAttributesExW_t)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
static GetFileAttributesExW_t pfnGetFileAttributesExW = nullptr;
static BOOL WINAPI Detour_GetFileAttributesExW(LPCWSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID info) {
    HookGuard guard; BOOL result = pfnGetFileAttributesExW(path, level, info);
    if (!guard.WasInside()) LogTelemetry("GetFileAttributesExW", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"lpFileName", "LPCWSTR", (uint64_t)path, {}, WideToUtf8(ReadWStringSafe(path))}});
    return result;
}
typedef BOOL(WINAPI* GetFileAttributesExA_t)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
static GetFileAttributesExA_t pfnGetFileAttributesExA = nullptr;
static BOOL WINAPI Detour_GetFileAttributesExA(LPCSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID info) {
    HookGuard guard; BOOL result = pfnGetFileAttributesExA(path, level, info);
    if (!guard.WasInside()) LogTelemetry("GetFileAttributesExA", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"lpFileName", "LPCSTR", (uint64_t)path, {}, ReadAStringSafe(path)}});
    return result;
}

typedef BOOL(WINAPI* ReplaceFileW_t)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
static ReplaceFileW_t pfnReplaceFileW = nullptr;
static BOOL WINAPI Detour_ReplaceFileW(LPCWSTR replaced, LPCWSTR replacement, LPCWSTR backup, DWORD flags, LPVOID exclude, LPVOID reserved) {
    HookGuard guard; BOOL result = pfnReplaceFileW(replaced, replacement, backup, flags, exclude, reserved);
    if (!guard.WasInside()) LogTelemetry("ReplaceFileW", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCWSTR", (uint64_t)replaced, {}, WideToUtf8(ReadWStringSafe(replaced))},
        {"lpNewFileName", "LPCWSTR", (uint64_t)replacement, {}, WideToUtf8(ReadWStringSafe(replacement))},
        {"lpBackupFileName", "LPCWSTR", (uint64_t)backup, {}, WideToUtf8(ReadWStringSafe(backup))}
    }); return result;
}
typedef BOOL(WINAPI* ReplaceFileA_t)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);
static ReplaceFileA_t pfnReplaceFileA = nullptr;
static BOOL WINAPI Detour_ReplaceFileA(LPCSTR replaced, LPCSTR replacement, LPCSTR backup, DWORD flags, LPVOID exclude, LPVOID reserved) {
    HookGuard guard; BOOL result = pfnReplaceFileA(replaced, replacement, backup, flags, exclude, reserved);
    if (!guard.WasInside()) LogTelemetry("ReplaceFileA", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCSTR", (uint64_t)replaced, {}, ReadAStringSafe(replaced)},
        {"lpNewFileName", "LPCSTR", (uint64_t)replacement, {}, ReadAStringSafe(replacement)},
        {"lpBackupFileName", "LPCSTR", (uint64_t)backup, {}, ReadAStringSafe(backup)}
    }); return result;
}

typedef BOOLEAN(WINAPI* CreateSymbolicLinkW_t)(LPCWSTR, LPCWSTR, DWORD);
static CreateSymbolicLinkW_t pfnCreateSymbolicLinkW = nullptr;
static BOOLEAN WINAPI Detour_CreateSymbolicLinkW(LPCWSTR link, LPCWSTR target, DWORD flags) {
    HookGuard guard; BOOLEAN result = pfnCreateSymbolicLinkW(link, target, flags);
    if (!guard.WasInside()) LogTelemetry("CreateSymbolicLinkW", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCWSTR", (uint64_t)link, {}, WideToUtf8(ReadWStringSafe(link))}, {"lpNewFileName", "LPCWSTR", (uint64_t)target, {}, WideToUtf8(ReadWStringSafe(target))}
    }); return result;
}
typedef BOOLEAN(WINAPI* CreateSymbolicLinkA_t)(LPCSTR, LPCSTR, DWORD);
static CreateSymbolicLinkA_t pfnCreateSymbolicLinkA = nullptr;
static BOOLEAN WINAPI Detour_CreateSymbolicLinkA(LPCSTR link, LPCSTR target, DWORD flags) {
    HookGuard guard; BOOLEAN result = pfnCreateSymbolicLinkA(link, target, flags);
    if (!guard.WasInside()) LogTelemetry("CreateSymbolicLinkA", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpFileName", "LPCSTR", (uint64_t)link, {}, ReadAStringSafe(link)}, {"lpNewFileName", "LPCSTR", (uint64_t)target, {}, ReadAStringSafe(target)}
    }); return result;
}

#undef DEFINE_FILE_PATH_BOOL_HOOK

typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
static CloseHandle_t pfnCloseHandle = nullptr;
static BOOL WINAPI Detour_CloseHandle(HANDLE hObject) {
    HookGuard guard;
    BOOL res = pfnCloseHandle(hObject);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hObject", "HANDLE", (uint64_t)hObject, {}, ""}
        };
        LogTelemetry("CloseHandle", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateMutexW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
static CreateMutexW_t pfnCreateMutexW = nullptr;
static HANDLE WINAPI Detour_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"bInitialOwner", "BOOL", (uint64_t)bInitialOwner, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("CreateMutexW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateMutexA_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
static CreateMutexA_t pfnCreateMutexA = nullptr;
static HANDLE WINAPI Detour_CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"bInitialOwner", "BOOL", (uint64_t)bInitialOwner, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("CreateMutexA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenMutexW_t)(DWORD, BOOL, LPCWSTR);
static OpenMutexW_t pfnOpenMutexW = nullptr;
static HANDLE WINAPI Detour_OpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("OpenMutexW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenMutexA_t)(DWORD, BOOL, LPCSTR);
static OpenMutexA_t pfnOpenMutexA = nullptr;
static HANDLE WINAPI Detour_OpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("OpenMutexA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ReleaseMutex_t)(HANDLE);
static ReleaseMutex_t pfnReleaseMutex = nullptr;
static BOOL WINAPI Detour_ReleaseMutex(HANDLE hMutex) {
    HookGuard guard;
    BOOL res = pfnReleaseMutex(hMutex);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hMutex", "HANDLE", (uint64_t)hMutex, {}, ""}
        };
        LogTelemetry("ReleaseMutex", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateEventW_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
static CreateEventW_t pfnCreateEventW = nullptr;
static HANDLE WINAPI Detour_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"bManualReset", "BOOL", (uint64_t)bManualReset, {}, ""},
            {"bInitialState", "BOOL", (uint64_t)bInitialState, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("CreateEventW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
static CreateEventA_t pfnCreateEventA = nullptr;
static HANDLE WINAPI Detour_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"bManualReset", "BOOL", (uint64_t)bManualReset, {}, ""},
            {"bInitialState", "BOOL", (uint64_t)bInitialState, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("CreateEventA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenEventW_t)(DWORD, BOOL, LPCWSTR);
static OpenEventW_t pfnOpenEventW = nullptr;
static HANDLE WINAPI Detour_OpenEventW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenEventW(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("OpenEventW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenEventA_t)(DWORD, BOOL, LPCSTR);
static OpenEventA_t pfnOpenEventA = nullptr;
static HANDLE WINAPI Detour_OpenEventA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenEventA(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("OpenEventA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetEvent_t)(HANDLE);
static SetEvent_t pfnSetEvent = nullptr;
static BOOL WINAPI Detour_SetEvent(HANDLE hEvent) {
    HookGuard guard;
    BOOL res = pfnSetEvent(hEvent);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hEvent", "HANDLE", (uint64_t)hEvent, {}, ""} };
        LogTelemetry("SetEvent", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ResetEvent_t)(HANDLE);
static ResetEvent_t pfnResetEvent = nullptr;
static BOOL WINAPI Detour_ResetEvent(HANDLE hEvent) {
    HookGuard guard;
    BOOL res = pfnResetEvent(hEvent);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hEvent", "HANDLE", (uint64_t)hEvent, {}, ""} };
        LogTelemetry("ResetEvent", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateSemaphoreW_t)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR);
static CreateSemaphoreW_t pfnCreateSemaphoreW = nullptr;
static HANDLE WINAPI Detour_CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lInitialCount", "LONG", (uint64_t)lInitialCount, {}, ""},
            {"lMaximumCount", "LONG", (uint64_t)lMaximumCount, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("CreateSemaphoreW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateSemaphoreA_t)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR);
static CreateSemaphoreA_t pfnCreateSemaphoreA = nullptr;
static HANDLE WINAPI Detour_CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateSemaphoreA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lInitialCount", "LONG", (uint64_t)lInitialCount, {}, ""},
            {"lMaximumCount", "LONG", (uint64_t)lMaximumCount, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("CreateSemaphoreA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenSemaphoreW_t)(DWORD, BOOL, LPCWSTR);
static OpenSemaphoreW_t pfnOpenSemaphoreW = nullptr;
static HANDLE WINAPI Detour_OpenSemaphoreW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenSemaphoreW(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("OpenSemaphoreW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenSemaphoreA_t)(DWORD, BOOL, LPCSTR);
static OpenSemaphoreA_t pfnOpenSemaphoreA = nullptr;
static HANDLE WINAPI Detour_OpenSemaphoreA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenSemaphoreA(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("OpenSemaphoreA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ReleaseSemaphore_t)(HANDLE, LONG, LPLONG);
static ReleaseSemaphore_t pfnReleaseSemaphore = nullptr;
static BOOL WINAPI Detour_ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount) {
    HookGuard guard;
    BOOL res = pfnReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount);
    if (!guard.WasInside()) {
        LONG previous = (res && lpPreviousCount) ? *lpPreviousCount : 0;
        std::vector<ParameterCapture> params = {
            {"hSemaphore", "HANDLE", (uint64_t)hSemaphore, {}, ""},
            {"lReleaseCount", "LONG", (uint64_t)lReleaseCount, {}, ""},
            {"lpPreviousCount", "LONG", (uint64_t)previous, {}, ""}
        };
        LogTelemetry("ReleaseSemaphore", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef LONG(NTAPI* NtQueryObjectForWait_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct WaitUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

static std::string DescribeWaitHandle(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) return "Invalid handle";
    DWORD processId = GetProcessId(handle);
    if (processId) return "Process PID " + std::to_string(processId);
    DWORD threadId = GetThreadId(handle);
    if (threadId) return "Thread TID " + std::to_string(threadId);

    static NtQueryObjectForWait_t queryObject = reinterpret_cast<NtQueryObjectForWait_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    if (!queryObject) return "Kernel object";

    auto queryUnicode = [&](ULONG informationClass) {
        std::vector<uint8_t> buffer(4096);
        ULONG returned = 0;
        LONG status = queryObject(handle, informationClass, buffer.data(), static_cast<ULONG>(buffer.size()), &returned);
        if (status < 0 || buffer.size() < sizeof(WaitUnicodeString)) return std::string{};
        WaitUnicodeString text = {};
        memcpy(&text, buffer.data(), sizeof(text));
        if (!text.Buffer || text.Length == 0) return std::string{};
        return WideToUtf8(ReadWStringSafe(text.Buffer, text.Length / sizeof(wchar_t) + 1));
    };

    std::string type = queryUnicode(2); // ObjectTypeInformation
    std::string name = queryUnicode(1); // ObjectNameInformation
    if (!type.empty() && !name.empty()) return type + " " + name;
    if (!type.empty()) return type;
    if (!name.empty()) return name;
    return "Kernel object";
}

static WaitForSingleObject_t pfnWaitForSingleObject = nullptr;
static DWORD WINAPI Detour_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    HookGuard guard;
    DWORD res = pfnWaitForSingleObject(hHandle, dwMilliseconds);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hHandle", "HANDLE", (uint64_t)hHandle, {}, DescribeWaitHandle(hHandle)},
            {"ResolvedObjects", "STRING", 0, {}, DescribeWaitHandle(hHandle)},
            {"dwMilliseconds", "DWORD", (uint64_t)dwMilliseconds, {}, ""}
        };
        LogTelemetry("WaitForSingleObject", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* WaitForMultipleObjects_t)(DWORD, const HANDLE*, BOOL, DWORD);
static WaitForMultipleObjects_t pfnWaitForMultipleObjects = nullptr;
static DWORD WINAPI Detour_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
    HookGuard guard;
    DWORD res = pfnWaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
    if (!guard.WasInside()) {
        std::ostringstream resolved;
        DWORD limit = (std::min)(nCount, static_cast<DWORD>(64));
        for (DWORD i = 0; i < limit; ++i) {
            HANDLE handle = nullptr;
            if (!SafeCopyBuffer(&handle, lpHandles + i, sizeof(handle))) break;
            if (i) resolved << "; ";
            resolved << i << ": " << DescribeWaitHandle(handle);
        }
        std::vector<ParameterCapture> params = {
            {"nCount", "DWORD", (uint64_t)nCount, {}, ReadHandleArrayPreviewSafe(lpHandles, nCount)},
            {"ResolvedObjects", "STRING", 0, {}, resolved.str()},
            {"bWaitAll", "BOOL", (uint64_t)bWaitAll, {}, ""},
            {"dwMilliseconds", "DWORD", (uint64_t)dwMilliseconds, {}, ""}
        };
        LogTelemetry("WaitForMultipleObjects", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* WaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
static WaitForSingleObjectEx_t pfnWaitForSingleObjectEx = nullptr;
static DWORD WINAPI Detour_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    HookGuard guard;
    DWORD res = pfnWaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);
    if (!guard.WasInside()) {
        std::string object = DescribeWaitHandle(hHandle);
        std::vector<ParameterCapture> params = {
            {"hHandle", "HANDLE", (uint64_t)hHandle, {}, object},
            {"ResolvedObjects", "STRING", 0, {}, object},
            {"dwMilliseconds", "DWORD", (uint64_t)dwMilliseconds, {}, ""},
            {"bAlertable", "BOOL", (uint64_t)bAlertable, {}, bAlertable ? "true" : "false"}
        };
        LogTelemetry("WaitForSingleObjectEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* WaitForMultipleObjectsEx_t)(DWORD, const HANDLE*, BOOL, DWORD, BOOL);
static WaitForMultipleObjectsEx_t pfnWaitForMultipleObjectsEx = nullptr;
static DWORD WINAPI Detour_WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable) {
    HookGuard guard;
    DWORD res = pfnWaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable);
    if (!guard.WasInside()) {
        std::ostringstream resolved;
        DWORD limit = (std::min)(nCount, static_cast<DWORD>(64));
        for (DWORD i = 0; i < limit; ++i) {
            HANDLE handle = nullptr;
            if (!SafeCopyBuffer(&handle, lpHandles + i, sizeof(handle))) break;
            if (i) resolved << "; ";
            resolved << i << ": " << DescribeWaitHandle(handle);
        }
        std::vector<ParameterCapture> params = {
            {"nCount", "DWORD", (uint64_t)nCount, {}, ReadHandleArrayPreviewSafe(lpHandles, nCount)},
            {"ResolvedObjects", "STRING", 0, {}, resolved.str()},
            {"bWaitAll", "BOOL", (uint64_t)bWaitAll, {}, bWaitAll ? "true" : "false"},
            {"dwMilliseconds", "DWORD", (uint64_t)dwMilliseconds, {}, ""},
            {"bAlertable", "BOOL", (uint64_t)bAlertable, {}, bAlertable ? "true" : "false"}
        };
        LogTelemetry("WaitForMultipleObjectsEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 5. VirtualAlloc
typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
static VirtualAlloc_t pfnVirtualAlloc = nullptr;
static LPVOID WINAPI Detour_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    HookGuard guard;
    LPVOID res = pfnVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpAddress", "LPVOID", (uint64_t)lpAddress, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)dwSize, {}, ""},
            {"flAllocationType", "DWORD", (uint64_t)flAllocationType, {}, ""},
            {"flProtect", "DWORD", (uint64_t)flProtect, {}, ""}
        };
        LogTelemetry("VirtualAlloc", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 6. VirtualProtect
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
static VirtualProtect_t pfnVirtualProtect = nullptr;
static BOOL WINAPI Detour_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    HookGuard guard;
    BOOL res = pfnVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpAddress", "LPVOID", (uint64_t)lpAddress, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)dwSize, {}, ""},
            {"flNewProtect", "DWORD", (uint64_t)flNewProtect, {}, ""}
        };
        LogTelemetry("VirtualProtect", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 7. VirtualFree
typedef BOOL(WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
static VirtualFree_t pfnVirtualFree = nullptr;
static BOOL WINAPI Detour_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    HookGuard guard;
    BOOL res = pfnVirtualFree(lpAddress, dwSize, dwFreeType);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpAddress", "LPVOID", (uint64_t)lpAddress, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)dwSize, {}, ""},
            {"dwFreeType", "DWORD", (uint64_t)dwFreeType, {}, ""}
        };
        LogTelemetry("VirtualFree", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
static VirtualFreeEx_t pfnVirtualFreeEx = nullptr;
static BOOL WINAPI Detour_VirtualFreeEx(HANDLE process, LPVOID address, SIZE_T size, DWORD freeType) {
    HookGuard guard;
    BOOL result = pfnVirtualFreeEx(process, address, size, freeType);
    if (!guard.WasInside()) LogTelemetry("VirtualFreeEx", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpAddress", "LPVOID", (uint64_t)address, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}, {"dwFreeType", "DWORD", (uint64_t)freeType, {}, ""}
    });
    return result;
}

typedef HANDLE(WINAPI* HeapCreate_t)(DWORD, SIZE_T, SIZE_T);
static HeapCreate_t pfnHeapCreate = nullptr;
static HANDLE WINAPI Detour_HeapCreate(DWORD options, SIZE_T initialSize, SIZE_T maximumSize) {
    HookGuard guard; HANDLE result = pfnHeapCreate(options, initialSize, maximumSize);
    if (!guard.WasInside()) LogTelemetry("HeapCreate", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"flOptions", "DWORD", options, {}, ""}, {"dwInitialSize", "SIZE_T", (uint64_t)initialSize, {}, ""}, {"dwMaximumSize", "SIZE_T", (uint64_t)maximumSize, {}, ""}
    }); return result;
}
typedef LPVOID(WINAPI* HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
static HeapAlloc_t pfnHeapAlloc = nullptr;
static LPVOID WINAPI Detour_HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    HookGuard guard; LPVOID result = pfnHeapAlloc(heap, flags, size);
    if (!guard.WasInside()) LogTelemetry("HeapAlloc", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hHeap", "HANDLE", (uint64_t)heap, {}, ""}, {"dwFlags", "DWORD", flags, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}
    }); return result;
}
typedef LPVOID(WINAPI* HeapReAlloc_t)(HANDLE, DWORD, LPVOID, SIZE_T);
static HeapReAlloc_t pfnHeapReAlloc = nullptr;
static LPVOID WINAPI Detour_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID memory, SIZE_T size) {
    HookGuard guard; LPVOID result = pfnHeapReAlloc(heap, flags, memory, size);
    if (!guard.WasInside()) LogTelemetry("HeapReAlloc", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hHeap", "HANDLE", (uint64_t)heap, {}, ""}, {"lpAddress", "LPVOID", (uint64_t)memory, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}
    }); return result;
}
typedef BOOL(WINAPI* HeapFree_t)(HANDLE, DWORD, LPVOID);
static HeapFree_t pfnHeapFree = nullptr;
static BOOL WINAPI Detour_HeapFree(HANDLE heap, DWORD flags, LPVOID memory) {
    HookGuard guard; BOOL result = pfnHeapFree(heap, flags, memory);
    if (!guard.WasInside()) LogTelemetry("HeapFree", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hHeap", "HANDLE", (uint64_t)heap, {}, ""}, {"lpAddress", "LPVOID", (uint64_t)memory, {}, ""}
    }); return result;
}

typedef HLOCAL(WINAPI* LocalAlloc_t)(UINT, SIZE_T);
static LocalAlloc_t pfnLocalAlloc = nullptr;
static HLOCAL WINAPI Detour_LocalAlloc(UINT flags, SIZE_T size) {
    HookGuard guard; HLOCAL result = pfnLocalAlloc(flags, size);
    if (!guard.WasInside()) LogTelemetry("LocalAlloc", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"uFlags", "UINT", flags, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}});
    return result;
}
typedef HLOCAL(WINAPI* LocalFree_t)(HLOCAL);
static LocalFree_t pfnLocalFree = nullptr;
static HLOCAL WINAPI Detour_LocalFree(HLOCAL memory) {
    HookGuard guard; HLOCAL result = pfnLocalFree(memory);
    if (!guard.WasInside()) LogTelemetry("LocalFree", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"lpAddress", "HLOCAL", (uint64_t)memory, {}, ""}});
    return result;
}
typedef HGLOBAL(WINAPI* GlobalAlloc_t)(UINT, SIZE_T);
static GlobalAlloc_t pfnGlobalAlloc = nullptr;
static HGLOBAL WINAPI Detour_GlobalAlloc(UINT flags, SIZE_T size) {
    HookGuard guard; HGLOBAL result = pfnGlobalAlloc(flags, size);
    if (!guard.WasInside()) LogTelemetry("GlobalAlloc", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"uFlags", "UINT", flags, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}});
    return result;
}
typedef HGLOBAL(WINAPI* GlobalFree_t)(HGLOBAL);
static GlobalFree_t pfnGlobalFree = nullptr;
static HGLOBAL WINAPI Detour_GlobalFree(HGLOBAL memory) {
    HookGuard guard; HGLOBAL result = pfnGlobalFree(memory);
    if (!guard.WasInside()) LogTelemetry("GlobalFree", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"lpAddress", "HGLOBAL", (uint64_t)memory, {}, ""}});
    return result;
}

typedef SIZE_T(WINAPI* VirtualQuery_t)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
static VirtualQuery_t pfnVirtualQuery = nullptr;
static SIZE_T WINAPI Detour_VirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION information, SIZE_T length) {
    HookGuard guard; SIZE_T result = pfnVirtualQuery(address, information, length);
    MEMORY_BASIC_INFORMATION copy{}; if (result) SafeCopyBuffer(&copy, information, (std::min<size_t>)(sizeof(copy), (size_t)result));
    if (!guard.WasInside()) LogTelemetry("VirtualQuery", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpAddress", "LPCVOID", (uint64_t)address, {}, ""}, {"BaseAddress", "PVOID", (uint64_t)copy.BaseAddress, {}, ""},
        {"RegionSize", "SIZE_T", (uint64_t)copy.RegionSize, {}, ""}, {"State", "DWORD", copy.State, {}, ""},
        {"Protect", "DWORD", copy.Protect, {}, ""}, {"Type", "DWORD", copy.Type, {}, ""}
    }); return result;
}
typedef SIZE_T(WINAPI* VirtualQueryEx_t)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
static VirtualQueryEx_t pfnVirtualQueryEx = nullptr;
static SIZE_T WINAPI Detour_VirtualQueryEx(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION information, SIZE_T length) {
    HookGuard guard; SIZE_T result = pfnVirtualQueryEx(process, address, information, length);
    MEMORY_BASIC_INFORMATION copy{}; if (result) SafeCopyBuffer(&copy, information, (std::min<size_t>)(sizeof(copy), (size_t)result));
    if (!guard.WasInside()) LogTelemetry("VirtualQueryEx", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpAddress", "LPCVOID", (uint64_t)address, {}, ""}, {"BaseAddress", "PVOID", (uint64_t)copy.BaseAddress, {}, ""},
        {"RegionSize", "SIZE_T", (uint64_t)copy.RegionSize, {}, ""}, {"State", "DWORD", copy.State, {}, ""},
        {"Protect", "DWORD", copy.Protect, {}, ""}, {"Type", "DWORD", copy.Type, {}, ""}
    }); return result;
}

typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);
static UnmapViewOfFile_t pfnUnmapViewOfFile = nullptr;
static BOOL WINAPI Detour_UnmapViewOfFile(LPCVOID base) {
    HookGuard guard; BOOL result = pfnUnmapViewOfFile(base);
    if (!guard.WasInside()) LogTelemetry("UnmapViewOfFile", "kernel32.dll", _ReturnAddress(), (uint64_t)result,
        {{"lpAddress", "LPCVOID", (uint64_t)base, {}, ""}});
    return result;
}

// VirtualProtectEx
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
static VirtualProtectEx_t pfnVirtualProtectEx = nullptr;
static BOOL WINAPI Detour_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    HookGuard guard;
    BOOL res = pfnVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (!guard.WasInside()) {
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpAddress", "LPVOID", (uint64_t)lpAddress, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)dwSize, {}, ""},
            {"flNewProtect", "DWORD", (uint64_t)flNewProtect, {}, ""}
        };
        LogTelemetry("VirtualProtectEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// ReadProcessMemory
typedef BOOL(WINAPI* ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
static ReadProcessMemory_t pfnReadProcessMemory = nullptr;
static BOOL WINAPI Detour_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    HookGuard guard;
    BOOL res = pfnReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if (!guard.WasInside()) {
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        SIZE_T bytesRead = 0;
        if (res && lpNumberOfBytesRead) SafeCopyBuffer(&bytesRead, lpNumberOfBytesRead, sizeof(bytesRead));
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpBaseAddress", "LPCVOID", (uint64_t)lpBaseAddress, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, bytesRead, kMaximumMemoryBufferCapture), ""},
            {"nSize", "SIZE_T", (uint64_t)nSize, {}, ""},
            {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)bytesRead, {}, ""}
        };
        LogTelemetry("ReadProcessMemory", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// MapViewOfFile
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static MapViewOfFile_t pfnMapViewOfFile = nullptr;
static LPVOID WINAPI Detour_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    HookGuard guard;
    LPVOID res = pfnMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hFileMappingObject", "HANDLE", (uint64_t)hFileMappingObject, {}, ""},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwNumberOfBytesToMap", "SIZE_T", (uint64_t)dwNumberOfBytesToMap, {}, ""},
            {"MappedBytes", "PVOID", (uint64_t)res, ReadBufferSafe(res, dwNumberOfBytesToMap ? dwNumberOfBytesToMap : kMaximumMemoryBufferCapture, kMaximumMemoryBufferCapture), ""}
        };
        LogTelemetry("MapViewOfFile", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LPVOID(WINAPI* MapViewOfFileEx_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
static MapViewOfFileEx_t pfnMapViewOfFileEx = nullptr;
static LPVOID WINAPI Detour_MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) {
    HookGuard guard;
    LPVOID res = pfnMapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hFileMappingObject", "HANDLE", (uint64_t)hFileMappingObject, {}, ""},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwNumberOfBytesToMap", "SIZE_T", (uint64_t)dwNumberOfBytesToMap, {}, ""},
            {"lpBaseAddress", "LPVOID", (uint64_t)lpBaseAddress, {}, ""},
            {"MappedBytes", "PVOID", (uint64_t)res, ReadBufferSafe(res, dwNumberOfBytesToMap ? dwNumberOfBytesToMap : kMaximumMemoryBufferCapture, kMaximumMemoryBufferCapture), ""}
        };
        LogTelemetry("MapViewOfFileEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateFileMappingW_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
static CreateFileMappingW_t pfnCreateFileMappingW = nullptr;
static HANDLE WINAPI Detour_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    if (!guard.WasInside()) {
        uint64_t size = ((uint64_t)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"flProtect", "DWORD", (uint64_t)flProtect, {}, ""},
            {"dwMaximumSize", "ULONGLONG", size, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("CreateFileMappingW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
static CreateFileMappingA_t pfnCreateFileMappingA = nullptr;
static HANDLE WINAPI Detour_CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    if (!guard.WasInside()) {
        uint64_t size = ((uint64_t)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)hFile, {}, ""},
            {"flProtect", "DWORD", (uint64_t)flProtect, {}, ""},
            {"dwMaximumSize", "ULONGLONG", size, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("CreateFileMappingA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenFileMappingW_t)(DWORD, BOOL, LPCWSTR);
static OpenFileMappingW_t pfnOpenFileMappingW = nullptr;
static HANDLE WINAPI Detour_OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))}
        };
        LogTelemetry("OpenFileMappingW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenFileMappingA_t)(DWORD, BOOL, LPCSTR);
static OpenFileMappingA_t pfnOpenFileMappingA = nullptr;
static HANDLE WINAPI Detour_OpenFileMappingA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName) {
    HookGuard guard;
    HANDLE res = pfnOpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)}
        };
        LogTelemetry("OpenFileMappingA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateNamedPipeW_t)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
static CreateNamedPipeW_t pfnCreateNamedPipeW = nullptr;
static HANDLE WINAPI Detour_CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HookGuard guard;
    HANDLE res = pfnCreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))},
            {"dwOpenMode", "DWORD", (uint64_t)dwOpenMode, {}, ""},
            {"dwPipeMode", "DWORD", (uint64_t)dwPipeMode, {}, ""},
            {"nMaxInstances", "DWORD", (uint64_t)nMaxInstances, {}, ""},
            {"nOutBufferSize", "DWORD", (uint64_t)nOutBufferSize, {}, ""},
            {"nInBufferSize", "DWORD", (uint64_t)nInBufferSize, {}, ""}
        };
        LogTelemetry("CreateNamedPipeW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateNamedPipeA_t)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
static CreateNamedPipeA_t pfnCreateNamedPipeA = nullptr;
static HANDLE WINAPI Detour_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HookGuard guard;
    HANDLE res = pfnCreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)},
            {"dwOpenMode", "DWORD", (uint64_t)dwOpenMode, {}, ""},
            {"dwPipeMode", "DWORD", (uint64_t)dwPipeMode, {}, ""},
            {"nMaxInstances", "DWORD", (uint64_t)nMaxInstances, {}, ""},
            {"nOutBufferSize", "DWORD", (uint64_t)nOutBufferSize, {}, ""},
            {"nInBufferSize", "DWORD", (uint64_t)nInBufferSize, {}, ""}
        };
        LogTelemetry("CreateNamedPipeA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ConnectNamedPipe_t)(HANDLE, LPOVERLAPPED);
static ConnectNamedPipe_t pfnConnectNamedPipe = nullptr;
static BOOL WINAPI Detour_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    BOOL res = pfnConnectNamedPipe(hNamedPipe, lpOverlapped);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hNamedPipe", "HANDLE", (uint64_t)hNamedPipe, {}, ""},
            {"LastError", "DWORD", error, {}, ""}, {"Asynchronous", "BOOL", lpOverlapped ? 1ull : 0ull, {}, ""},
            {"PeerProcessId", "DWORD", NamedPipePeerProcessId(hNamedPipe), {}, ""} };
        LogTelemetry("ConnectNamedPipe", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(error); return res;
}

typedef BOOL(WINAPI* CallNamedPipeW_t)(LPCWSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD);
static CallNamedPipeW_t pfnCallNamedPipeW = nullptr;
static BOOL WINAPI Detour_CallNamedPipeW(LPCWSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut) {
    HookGuard guard;
    BOOL res = pfnCallNamedPipeW(lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesRead, nTimeOut);
    if (!guard.WasInside()) {
        DWORD read = (res && lpBytesRead) ? *lpBytesRead : 0;
        std::vector<ParameterCapture> params = {
            {"lpNamedPipeName", "LPCWSTR", (uint64_t)lpNamedPipeName, {}, WideToUtf8(ReadWStringSafe(lpNamedPipeName))},
            {"lpInBuffer", "LPVOID", (uint64_t)lpInBuffer, ReadBufferSafe(lpInBuffer, nInBufferSize), ""},
            {"nInBufferSize", "DWORD", (uint64_t)nInBufferSize, {}, ""},
            {"lpOutBuffer", "LPVOID", (uint64_t)lpOutBuffer, ReadBufferSafe(lpOutBuffer, read), ""},
            {"nOutBufferSize", "DWORD", (uint64_t)nOutBufferSize, {}, ""}
        };
        LogTelemetry("CallNamedPipeW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CallNamedPipeA_t)(LPCSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD);
static CallNamedPipeA_t pfnCallNamedPipeA = nullptr;
static BOOL WINAPI Detour_CallNamedPipeA(LPCSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut) {
    HookGuard guard;
    BOOL res = pfnCallNamedPipeA(lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesRead, nTimeOut);
    if (!guard.WasInside()) {
        DWORD read = (res && lpBytesRead) ? *lpBytesRead : 0;
        std::vector<ParameterCapture> params = {
            {"lpNamedPipeName", "LPCSTR", (uint64_t)lpNamedPipeName, {}, ReadAStringSafe(lpNamedPipeName)},
            {"lpInBuffer", "LPVOID", (uint64_t)lpInBuffer, ReadBufferSafe(lpInBuffer, nInBufferSize), ""},
            {"nInBufferSize", "DWORD", (uint64_t)nInBufferSize, {}, ""},
            {"lpOutBuffer", "LPVOID", (uint64_t)lpOutBuffer, ReadBufferSafe(lpOutBuffer, read), ""},
            {"nOutBufferSize", "DWORD", (uint64_t)nOutBufferSize, {}, ""}
        };
        LogTelemetry("CallNamedPipeA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WaitNamedPipeW_t)(LPCWSTR, DWORD);
static WaitNamedPipeW_t pfnWaitNamedPipeW = nullptr;
static BOOL WINAPI Detour_WaitNamedPipeW(LPCWSTR lpNamedPipeName, DWORD nTimeOut) {
    HookGuard guard;
    BOOL res = pfnWaitNamedPipeW(lpNamedPipeName, nTimeOut);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpNamedPipeName", "LPCWSTR", (uint64_t)lpNamedPipeName, {}, WideToUtf8(ReadWStringSafe(lpNamedPipeName))},
            {"nTimeOut", "DWORD", (uint64_t)nTimeOut, {}, ""}
        };
        LogTelemetry("WaitNamedPipeW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WaitNamedPipeA_t)(LPCSTR, DWORD);
static WaitNamedPipeA_t pfnWaitNamedPipeA = nullptr;
static BOOL WINAPI Detour_WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut) {
    HookGuard guard;
    BOOL res = pfnWaitNamedPipeA(lpNamedPipeName, nTimeOut);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpNamedPipeName", "LPCSTR", (uint64_t)lpNamedPipeName, {}, ReadAStringSafe(lpNamedPipeName)},
            {"nTimeOut", "DWORD", (uint64_t)nTimeOut, {}, ""}
        };
        LogTelemetry("WaitNamedPipeA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CreatePipe_t)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
static CreatePipe_t pfnCreatePipe = nullptr;
static BOOL WINAPI Detour_CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize) {
    HookGuard guard;
    BOOL res = pfnCreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
    if (!guard.WasInside()) {
        uint64_t readHandle = (res && hReadPipe) ? (uint64_t)*hReadPipe : 0;
        uint64_t writeHandle = (res && hWritePipe) ? (uint64_t)*hWritePipe : 0;
        std::vector<ParameterCapture> params = {
            {"hReadPipe", "HANDLE", readHandle, {}, ""},
            {"hWritePipe", "HANDLE", writeHandle, {}, ""},
            {"nSize", "DWORD", (uint64_t)nSize, {}, ""}
        };
        LogTelemetry("CreatePipe", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* PeekNamedPipe_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
static PeekNamedPipe_t pfnPeekNamedPipe = nullptr;
static BOOL WINAPI Detour_PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage) {
    HookGuard guard;
    BOOL res = pfnPeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage);
    if (!guard.WasInside()) {
        DWORD read = (res && lpBytesRead) ? *lpBytesRead : 0;
        DWORD available = (res && lpTotalBytesAvail) ? *lpTotalBytesAvail : 0;
        std::vector<ParameterCapture> params = {
            {"hNamedPipe", "HANDLE", (uint64_t)hNamedPipe, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, read), ""},
            {"nBufferSize", "DWORD", (uint64_t)nBufferSize, {}, ""},
            {"lpTotalBytesAvail", "DWORD", (uint64_t)available, {}, ""}
        };
        LogTelemetry("PeekNamedPipe", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* TransactNamedPipe_t)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static TransactNamedPipe_t pfnTransactNamedPipe = nullptr;
static BOOL WINAPI Detour_TransactNamedPipe(HANDLE pipe, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReadOut, LPOVERLAPPED overlapped) {
    HookGuard guard; BOOL result = pfnTransactNamedPipe(pipe, inBuffer, inSize, outBuffer, outSize, bytesReadOut, overlapped);
    DWORD error = result ? ERROR_SUCCESS : GetLastError(); DWORD bytesRead = 0; if (result && bytesReadOut) SafeCopyBuffer(&bytesRead, bytesReadOut, sizeof(bytesRead));
    if (!guard.WasInside()) LogTelemetry("TransactNamedPipe", "kernel32.dll", _ReturnAddress(), result, {
        {"hNamedPipe", "HANDLE", (uint64_t)pipe, {}, ""}, {"lpInBuffer", "LPVOID", (uint64_t)inBuffer, ReadBufferSafe(inBuffer, inSize, kMaximumMemoryBufferCapture), ""},
        {"lpOutBuffer", "LPVOID", (uint64_t)outBuffer, ReadBufferSafe(outBuffer, bytesRead, kMaximumMemoryBufferCapture), ""},
        {"LastError", "DWORD", error, {}, ""}, {"PeerProcessId", "DWORD", NamedPipePeerProcessId(pipe), {}, ""}
    }); if (!result) SetLastError(error); return result;
}
typedef BOOL(WINAPI* DisconnectNamedPipe_t)(HANDLE);
static DisconnectNamedPipe_t pfnDisconnectNamedPipe = nullptr;
static BOOL WINAPI Detour_DisconnectNamedPipe(HANDLE pipe) { HookGuard guard; BOOL result = pfnDisconnectNamedPipe(pipe); if (!guard.WasInside()) LogTelemetry("DisconnectNamedPipe", "kernel32.dll", _ReturnAddress(), result, {{"hNamedPipe", "HANDLE", (uint64_t)pipe, {}, ""}, {"PeerProcessId", "DWORD", NamedPipePeerProcessId(pipe), {}, ""}}); return result; }
typedef BOOL(WINAPI* GetNamedPipeInfo_t)(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD);
static GetNamedPipeInfo_t pfnGetNamedPipeInfo = nullptr;
static BOOL WINAPI Detour_GetNamedPipeInfo(HANDLE pipe, LPDWORD flags, LPDWORD outSize, LPDWORD inSize, LPDWORD maxInstances) { HookGuard guard; BOOL result = pfnGetNamedPipeInfo(pipe, flags, outSize, inSize, maxInstances); if (!guard.WasInside()) LogTelemetry("GetNamedPipeInfo", "kernel32.dll", _ReturnAddress(), result, {{"hNamedPipe", "HANDLE", (uint64_t)pipe, {}, ""}, {"PeerProcessId", "DWORD", NamedPipePeerProcessId(pipe), {}, ""}}); return result; }

// 8. OpenProcess
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
static OpenProcess_t pfnOpenProcess = nullptr;
static HANDLE WINAPI Detour_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HookGuard guard;
    HANDLE res = pfnOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)dwProcessId, {}, ""}
        };
        LogTelemetry("OpenProcess", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 9. LoadLibraryW
static std::string ResolvedModulePath(HMODULE module) {
    if (!module) return "";
    std::vector<wchar_t> path(32768);
    DWORD length = GetModuleFileNameW(module, path.data(), (DWORD)path.size());
    return length ? WideToUtf8(std::wstring(path.data(), length)) : "";
}

typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR);
static LoadLibraryW_t pfnLoadLibraryW = nullptr;
static HMODULE WINAPI Detour_LoadLibraryW(LPCWSTR lpLibFileName) {
    HookGuard guard;
    HMODULE res = pfnLoadLibraryW(lpLibFileName);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpLibFileName", "LPCWSTR", (uint64_t)lpLibFileName, {}, WideToUtf8(ReadWStringSafe(lpLibFileName))},
            {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath(res)}, {"LastError", "DWORD", error, {}, ""}
        };
        LogTelemetry("LoadLibraryW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (res && g_HookNetwork) TryInstallOpenSslHooks(res);
    if (!res) SetLastError(error); return res;
}

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
static LoadLibraryA_t pfnLoadLibraryA = nullptr;
static HMODULE WINAPI Detour_LoadLibraryA(LPCSTR lpLibFileName) {
    HookGuard guard;
    HMODULE res = pfnLoadLibraryA(lpLibFileName);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpLibFileName", "LPCSTR", (uint64_t)lpLibFileName, {}, ReadAStringSafe(lpLibFileName)},
            {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath(res)}, {"LastError", "DWORD", error, {}, ""}
        };
        LogTelemetry("LoadLibraryA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (res && g_HookNetwork) TryInstallOpenSslHooks(res);
    if (!res) SetLastError(error); return res;
}

// 10. LoadLibraryExW
typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
static LoadLibraryExW_t pfnLoadLibraryExW = nullptr;
static HMODULE WINAPI Detour_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HookGuard guard;
    HMODULE res = pfnLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpLibFileName", "LPCWSTR", (uint64_t)lpLibFileName, {}, WideToUtf8(ReadWStringSafe(lpLibFileName))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath(res)},
            {"LastError", "DWORD", error, {}, ""}
        };
        LogTelemetry("LoadLibraryExW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (res && g_HookNetwork) TryInstallOpenSslHooks(res);
    if (!res) SetLastError(error); return res;
}

typedef HMODULE(WINAPI* LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
static LoadLibraryExA_t pfnLoadLibraryExA = nullptr;
static HMODULE WINAPI Detour_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HookGuard guard;
    HMODULE res = pfnLoadLibraryExA(lpLibFileName, hFile, dwFlags);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpLibFileName", "LPCSTR", (uint64_t)lpLibFileName, {}, ReadAStringSafe(lpLibFileName)},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath(res)},
            {"LastError", "DWORD", error, {}, ""}
        };
        LogTelemetry("LoadLibraryExA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (res && g_HookNetwork) TryInstallOpenSslHooks(res);
    if (!res) SetLastError(error); return res;
}

// 11. GetProcAddress
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
static GetProcAddress_t pfnGetProcAddress = nullptr;
static FARPROC WINAPI Detour_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    HookGuard guard;
    FARPROC res = pfnGetProcAddress(hModule, lpProcName);
    if (!guard.WasInside()) {
        std::string procName;
        if (HIWORD(lpProcName) == 0) {
            procName = "#" + std::to_string((LOWORD(lpProcName)));
        } else {
            procName = ReadAStringSafe(lpProcName);
        }
        std::vector<ParameterCapture> params = {
            {"hModule", "HMODULE", (uint64_t)hModule, {}, ""},
            {"lpProcName", "LPCSTR", (uint64_t)lpProcName, {}, procName}
        };
        LogTelemetry("GetProcAddress", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* FreeLibrary_t)(HMODULE);
static FreeLibrary_t pfnFreeLibrary = nullptr;
static BOOL WINAPI Detour_FreeLibrary(HMODULE hLibModule) {
    HookGuard guard;
    std::string resolvedPath = ResolvedModulePath(hLibModule);
    BOOL res = pfnFreeLibrary(hLibModule);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hLibModule", "HMODULE", (uint64_t)hLibModule, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, resolvedPath}
        };
        LogTelemetry("FreeLibrary", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HMODULE(WINAPI* GetModuleHandleW_t)(LPCWSTR);
static GetModuleHandleW_t pfnGetModuleHandleW = nullptr;
static HMODULE WINAPI Detour_GetModuleHandleW(LPCWSTR lpModuleName) {
    HookGuard guard;
    HMODULE res = pfnGetModuleHandleW(lpModuleName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpModuleName", "LPCWSTR", (uint64_t)lpModuleName, {}, WideToUtf8(ReadWStringSafe(lpModuleName))}
        };
        LogTelemetry("GetModuleHandleW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HMODULE(WINAPI* GetModuleHandleA_t)(LPCSTR);
static GetModuleHandleA_t pfnGetModuleHandleA = nullptr;
static HMODULE WINAPI Detour_GetModuleHandleA(LPCSTR lpModuleName) {
    HookGuard guard;
    HMODULE res = pfnGetModuleHandleA(lpModuleName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpModuleName", "LPCSTR", (uint64_t)lpModuleName, {}, ReadAStringSafe(lpModuleName)}
        };
        LogTelemetry("GetModuleHandleA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetModuleHandleExW_t)(DWORD, LPCWSTR, HMODULE*);
static GetModuleHandleExW_t pfnGetModuleHandleExW = nullptr;
static BOOL WINAPI Detour_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
    HookGuard guard;
    BOOL res = pfnGetModuleHandleExW(dwFlags, lpModuleName, phModule);
    if (!guard.WasInside()) {
        uint64_t moduleHandle = (res && phModule) ? (uint64_t)*phModule : 0;
        std::vector<ParameterCapture> params = {
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"lpModuleName", "LPCWSTR", (uint64_t)lpModuleName, {}, WideToUtf8(ReadWStringSafe(lpModuleName))},
            {"phModule", "HMODULE*", moduleHandle, {}, ""}
        };
        LogTelemetry("GetModuleHandleExW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetModuleHandleExA_t)(DWORD, LPCSTR, HMODULE*);
static GetModuleHandleExA_t pfnGetModuleHandleExA = nullptr;
static BOOL WINAPI Detour_GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule) {
    HookGuard guard;
    BOOL res = pfnGetModuleHandleExA(dwFlags, lpModuleName, phModule);
    if (!guard.WasInside()) {
        uint64_t moduleHandle = (res && phModule) ? (uint64_t)*phModule : 0;
        std::vector<ParameterCapture> params = {
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"lpModuleName", "LPCSTR", (uint64_t)lpModuleName, {}, ReadAStringSafe(lpModuleName)},
            {"phModule", "HMODULE*", moduleHandle, {}, ""}
        };
        LogTelemetry("GetModuleHandleExA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HMODULE(WINAPI* LoadPackagedLibrary_t)(LPCWSTR, DWORD);
static LoadPackagedLibrary_t pfnLoadPackagedLibrary = nullptr;
static HMODULE WINAPI Detour_LoadPackagedLibrary(LPCWSTR lpwLibFileName, DWORD Reserved) {
    HookGuard guard;
    HMODULE res = pfnLoadPackagedLibrary(lpwLibFileName, Reserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpwLibFileName", "LPCWSTR", (uint64_t)lpwLibFileName, {}, WideToUtf8(ReadWStringSafe(lpwLibFileName))},
            {"Reserved", "DWORD", (uint64_t)Reserved, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath(res)}
        };
        LogTelemetry("LoadPackagedLibrary", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetDllDirectoryW_t)(LPCWSTR);
static SetDllDirectoryW_t pfnSetDllDirectoryW = nullptr;
static BOOL WINAPI Detour_SetDllDirectoryW(LPCWSTR path) { HookGuard guard; BOOL result = pfnSetDllDirectoryW(path); if (!guard.WasInside()) LogTelemetry("SetDllDirectoryW", "kernel32.dll", _ReturnAddress(), result, {{"lpPathName", "LPCWSTR", (uint64_t)path, {}, WideToUtf8(ReadWStringSafe(path))}}); return result; }
typedef BOOL(WINAPI* SetDllDirectoryA_t)(LPCSTR);
static SetDllDirectoryA_t pfnSetDllDirectoryA = nullptr;
static BOOL WINAPI Detour_SetDllDirectoryA(LPCSTR path) { HookGuard guard; BOOL result = pfnSetDllDirectoryA(path); if (!guard.WasInside()) LogTelemetry("SetDllDirectoryA", "kernel32.dll", _ReturnAddress(), result, {{"lpPathName", "LPCSTR", (uint64_t)path, {}, ReadAStringSafe(path)}}); return result; }
typedef BOOL(WINAPI* SetDefaultDllDirectories_t)(DWORD);
static SetDefaultDllDirectories_t pfnSetDefaultDllDirectories = nullptr;
static BOOL WINAPI Detour_SetDefaultDllDirectories(DWORD flags) { HookGuard guard; BOOL result = pfnSetDefaultDllDirectories(flags); if (!guard.WasInside()) LogTelemetry("SetDefaultDllDirectories", "kernel32.dll", _ReturnAddress(), result, {{"dwFlags", "DWORD", flags, {}, ""}}); return result; }
typedef PVOID(WINAPI* AddDllDirectory_t)(PCWSTR);
static AddDllDirectory_t pfnAddDllDirectory = nullptr;
static PVOID WINAPI Detour_AddDllDirectory(PCWSTR path) { HookGuard guard; PVOID result = pfnAddDllDirectory(path); if (!guard.WasInside()) LogTelemetry("AddDllDirectory", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {{"lpPathName", "PCWSTR", (uint64_t)path, {}, WideToUtf8(ReadWStringSafe(path))}}); return result; }
typedef BOOL(WINAPI* RemoveDllDirectory_t)(PVOID);
static RemoveDllDirectory_t pfnRemoveDllDirectory = nullptr;
static BOOL WINAPI Detour_RemoveDllDirectory(PVOID cookie) { HookGuard guard; BOOL result = pfnRemoveDllDirectory(cookie); if (!guard.WasInside()) LogTelemetry("RemoveDllDirectory", "kernel32.dll", _ReturnAddress(), result, {{"Cookie", "PVOID", (uint64_t)cookie, {}, ""}}); return result; }

typedef LONG NTSTATUS;
struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct NativeAnsiString {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
};

struct NativeObjectAttributes {
    ULONG Length;
    HANDLE RootDirectory;
    NativeUnicodeString* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

static std::string ReadNativeUnicodeStringSafe(const NativeUnicodeString* value) {
    NativeUnicodeString copy{};
    if (!value || !SafeCopyBuffer(&copy, value, sizeof(copy)) || !copy.Buffer || copy.Length == 0) return "";
    return WideToUtf8(ReadWStringSafe(copy.Buffer, (copy.Length / sizeof(wchar_t)) + 1));
}

typedef NTSTATUS(WINAPI* RtlHashUnicodeString_t)(const NativeUnicodeString*, BOOLEAN, ULONG, PULONG);
static RtlHashUnicodeString_t pfnRtlHashUnicodeString = nullptr;
static NTSTATUS WINAPI Detour_RtlHashUnicodeString(const NativeUnicodeString* value, BOOLEAN caseInsensitive, ULONG algorithm, PULONG hashValue) {
    HookGuard guard;
    NTSTATUS result = pfnRtlHashUnicodeString(value, caseInsensitive, algorithm, hashValue);
    ULONG hash = 0; if (hashValue) SafeCopyBuffer(&hash, hashValue, sizeof(hash));
    if (!guard.WasInside()) LogTelemetry("RtlHashUnicodeString", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"String", "UNICODE_STRING", (uint64_t)value, {}, ReadNativeUnicodeStringSafe(value)},
        {"CaseInsensitive", "BOOLEAN", caseInsensitive, {}, ""}, {"HashAlgorithm", "ULONG", algorithm, {}, ""},
        {"HashValue", "ULONG", hash, {}, "Potential API-name hashing when used while resolving exports"}
    });
    return result;
}

static std::string ReadNativeAnsiStringSafe(const NativeAnsiString* value) {
    NativeAnsiString copy{};
    if (!value || !SafeCopyBuffer(&copy, value, sizeof(copy)) || !copy.Buffer || copy.Length == 0) return "";
    return ReadAStringSafe(copy.Buffer, copy.Length + 1);
}

static std::string ReadNativeObjectNameSafe(const NativeObjectAttributes* value) {
    NativeObjectAttributes copy{};
    if (!value || !SafeCopyBuffer(&copy, value, sizeof(copy)) || !copy.ObjectName) return "";
    return ReadNativeUnicodeStringSafe(copy.ObjectName);
}

static uint64_t ReadNativeRootDirectorySafe(const NativeObjectAttributes* value) {
    NativeObjectAttributes copy{};
    return value && SafeCopyBuffer(&copy, value, sizeof(copy)) ? (uint64_t)copy.RootDirectory : 0;
}

static std::mutex g_NativeRegistryHandleMutex;
static std::unordered_set<uint64_t> g_NativeRegistryHandles;

static void RememberNativeRegistryHandle(uint64_t handle) {
    if (!handle) return;
    std::lock_guard<std::mutex> lock(g_NativeRegistryHandleMutex);
    g_NativeRegistryHandles.insert(handle);
}

static bool ForgetNativeRegistryHandle(uint64_t handle) {
    std::lock_guard<std::mutex> lock(g_NativeRegistryHandleMutex);
    return g_NativeRegistryHandles.erase(handle) != 0;
}

template <typename T>
static T ReadScalarSafe(const T* value, T fallback = {}) {
    T copy = fallback;
    if (value) SafeCopyBuffer(&copy, value, sizeof(copy));
    return copy;
}

static std::string DecodeRegistryDataForTelemetry(DWORD type, const void* data, size_t size, bool wideText) {
    if (!data || size == 0) return "";
    if (type == REG_DWORD && size >= sizeof(DWORD)) return std::to_string(ReadScalarSafe(reinterpret_cast<const DWORD*>(data)));
    if (type == REG_QWORD && size >= sizeof(uint64_t)) return std::to_string(ReadScalarSafe(reinterpret_cast<const uint64_t*>(data)));
    if (type == REG_DWORD_BIG_ENDIAN && size >= sizeof(DWORD)) {
        DWORD raw = ReadScalarSafe(reinterpret_cast<const DWORD*>(data));
        DWORD value = ((raw & 0x000000FFu) << 24) | ((raw & 0x0000FF00u) << 8) |
            ((raw & 0x00FF0000u) >> 8) | ((raw & 0xFF000000u) >> 24);
        return std::to_string(value);
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        return wideText ? WideToUtf8(ReadWStringSafe(reinterpret_cast<LPCWSTR>(data), size / sizeof(wchar_t) + 1))
                        : ReadAStringSafe(reinterpret_cast<LPCSTR>(data), size + 1);
    }
    if (type == REG_MULTI_SZ) {
        std::ostringstream decoded;
        if (wideText) {
            std::vector<wchar_t> copy(size / sizeof(wchar_t) + 1, 0);
            if (!SafeCopyBuffer(copy.data(), data, size)) return "";
            for (size_t offset = 0; offset < copy.size() && copy[offset]; ) {
                std::wstring item(&copy[offset]);
                if (decoded.tellp() > 0) decoded << " | ";
                decoded << WideToUtf8(item);
                offset += item.size() + 1;
            }
        } else {
            std::vector<char> copy(size + 1, 0);
            if (!SafeCopyBuffer(copy.data(), data, size)) return "";
            for (size_t offset = 0; offset < copy.size() && copy[offset]; ) {
                std::string item(&copy[offset]);
                if (decoded.tellp() > 0) decoded << " | ";
                decoded << item;
                offset += item.size() + 1;
            }
        }
        return decoded.str();
    }
    return "";
}

typedef NTSTATUS(WINAPI* LdrLoadDll_t)(PWSTR, ULONG, NativeUnicodeString*, PHANDLE);
static LdrLoadDll_t pfnLdrLoadDll = nullptr;
static NTSTATUS WINAPI Detour_LdrLoadDll(PWSTR PathToFile, ULONG Flags, NativeUnicodeString* ModuleFileName, PHANDLE ModuleHandle) {
    HookGuard guard;
    NTSTATUS res = pfnLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
    if (!guard.WasInside()) {
        uint64_t moduleHandle = ((LONG)res >= 0 && ModuleHandle) ? (uint64_t)*ModuleHandle : 0;
        std::vector<ParameterCapture> params = {
            {"PathToFile", "PWSTR", (uint64_t)PathToFile, {}, WideToUtf8(ReadWStringSafe(PathToFile))},
            {"Flags", "ULONG", (uint64_t)Flags, {}, ""},
            {"ModuleFileName", "UNICODE_STRING", (uint64_t)ModuleFileName, {}, ReadNativeUnicodeStringSafe(ModuleFileName)},
            {"hModule", "HANDLE", moduleHandle, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, ResolvedModulePath((HMODULE)moduleHandle)}
        };
        LogTelemetry("LdrLoadDll", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* LdrGetProcedureAddress_t)(PVOID, NativeAnsiString*, WORD, PVOID*);
static LdrGetProcedureAddress_t pfnLdrGetProcedureAddress = nullptr;
static NTSTATUS WINAPI Detour_LdrGetProcedureAddress(PVOID ModuleHandle, NativeAnsiString* FunctionName, WORD Ordinal, PVOID* FunctionAddress) {
    HookGuard guard;
    NTSTATUS res = pfnLdrGetProcedureAddress(ModuleHandle, FunctionName, Ordinal, FunctionAddress);
    if (!guard.WasInside()) {
        std::string procName = ReadNativeAnsiStringSafe(FunctionName);
        if (procName.empty() && Ordinal != 0) {
            procName = "#" + std::to_string(Ordinal);
        }
        uint64_t resolved = ((LONG)res >= 0 && FunctionAddress) ? (uint64_t)*FunctionAddress : 0;
        std::vector<ParameterCapture> params = {
            {"hModule", "PVOID", (uint64_t)ModuleHandle, {}, ""},
            {"lpProcName", "ANSI_STRING", (uint64_t)FunctionName, {}, procName},
            {"Ordinal", "WORD", (uint64_t)Ordinal, {}, ""},
            {"lpProcAddress", "PVOID*", resolved, {}, ""}
        };
        LogTelemetry("LdrGetProcedureAddress", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* LdrUnloadDll_t)(PVOID);
static LdrUnloadDll_t pfnLdrUnloadDll = nullptr;
static NTSTATUS WINAPI Detour_LdrUnloadDll(PVOID moduleHandle) {
    HookGuard guard;
    std::string path = ResolvedModulePath((HMODULE)moduleHandle);
    NTSTATUS result = pfnLdrUnloadDll(moduleHandle);
    if (!guard.WasInside()) LogTelemetry("LdrUnloadDll", "ntdll.dll", _ReturnAddress(), (uint64_t)result,
        {{"hLibModule", "PVOID", (uint64_t)moduleHandle, {}, ""}, {"ResolvedPath", "LPCWSTR", 0, {}, path}});
    return result;
}

typedef NTSTATUS(WINAPI* NtCreateKey_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, ULONG, NativeUnicodeString*, ULONG, PULONG);
static NtCreateKey_t pfnNtCreateKey = nullptr;
static NTSTATUS WINAPI Detour_NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes, ULONG TitleIndex, NativeUnicodeString* Class, ULONG CreateOptions, PULONG Disposition) {
    HookGuard guard;
    NTSTATUS res = pfnNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
    if (!guard.WasInside()) {
        HANDLE resultHandle = nullptr;
        ULONG disposition = 0;
        if (res >= 0 && KeyHandle) SafeCopyBuffer(&resultHandle, KeyHandle, sizeof(resultHandle));
        if (Disposition) SafeCopyBuffer(&disposition, Disposition, sizeof(disposition));
        uint64_t resultKey = (uint64_t)resultHandle;
        RememberNativeRegistryHandle(resultKey);
        std::vector<ParameterCapture> params = {
            {"hKey", "HANDLE", ReadNativeRootDirectorySafe(ObjectAttributes), {}, ""},
            {"ObjectName", "UNICODE_STRING", (uint64_t)ObjectAttributes, {}, ReadNativeObjectNameSafe(ObjectAttributes)},
            {"samDesired", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"phkResult", "PHANDLE", resultKey, {}, ""},
            {"lpdwDisposition", "ULONG", (uint64_t)disposition, {}, ""}
        };
        LogTelemetry("NtCreateKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtOpenKey_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*);
static NtOpenKey_t pfnNtOpenKey = nullptr;
static NTSTATUS WINAPI Detour_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes) {
    HookGuard guard;
    NTSTATUS res = pfnNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    if (!guard.WasInside()) {
        HANDLE resultHandle = nullptr;
        if (res >= 0 && KeyHandle) SafeCopyBuffer(&resultHandle, KeyHandle, sizeof(resultHandle));
        uint64_t resultKey = (uint64_t)resultHandle;
        RememberNativeRegistryHandle(resultKey);
        std::vector<ParameterCapture> params = {
            {"hKey", "HANDLE", ReadNativeRootDirectorySafe(ObjectAttributes), {}, ""},
            {"ObjectName", "UNICODE_STRING", (uint64_t)ObjectAttributes, {}, ReadNativeObjectNameSafe(ObjectAttributes)},
            {"samDesired", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"phkResult", "PHANDLE", resultKey, {}, ""}
        };
        LogTelemetry("NtOpenKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtDeleteKey_t)(HANDLE);
static NtDeleteKey_t pfnNtDeleteKey = nullptr;
static NTSTATUS WINAPI Detour_NtDeleteKey(HANDLE KeyHandle) {
    HookGuard guard;
    NTSTATUS res = pfnNtDeleteKey(KeyHandle);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HANDLE", (uint64_t)KeyHandle, {}, ""} };
        LogTelemetry("NtDeleteKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtSetValueKey_t)(HANDLE, NativeUnicodeString*, ULONG, ULONG, PVOID, ULONG);
static NtSetValueKey_t pfnNtSetValueKey = nullptr;
static NTSTATUS WINAPI Detour_NtSetValueKey(HANDLE KeyHandle, NativeUnicodeString* ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    HookGuard guard;
    NTSTATUS res = pfnNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
    if (!guard.WasInside()) {
        std::string decoded = DecodeRegistryDataForTelemetry(Type, Data, DataSize, true);
        std::vector<ParameterCapture> params = {
            {"hKey", "HANDLE", (uint64_t)KeyHandle, {}, ""},
            {"lpValueName", "UNICODE_STRING", (uint64_t)ValueName, {}, ReadNativeUnicodeStringSafe(ValueName)},
            {"dwType", "ULONG", (uint64_t)Type, {}, ""},
            {"lpData", "PVOID", (uint64_t)Data, ReadBufferSafe(Data, DataSize, 64u * 1024u), decoded}
        };
        LogTelemetry("NtSetValueKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtQueryValueKey_t)(HANDLE, NativeUnicodeString*, ULONG, PVOID, ULONG, PULONG);
static NtQueryValueKey_t pfnNtQueryValueKey = nullptr;
static NTSTATUS WINAPI Detour_NtQueryValueKey(HANDLE KeyHandle, NativeUnicodeString* ValueName, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HANDLE", (uint64_t)KeyHandle, {}, ""},
            {"lpValueName", "UNICODE_STRING", (uint64_t)ValueName, {}, ReadNativeUnicodeStringSafe(ValueName)},
            {"KeyValueInformationClass", "ULONG", (uint64_t)KeyValueInformationClass, {}, ""},
            {"lpData", "PVOID", (uint64_t)KeyValueInformation,
                ReadBufferSafe(KeyValueInformation, res >= 0 ? ReadScalarSafe(ResultLength) : 0, 64u * 1024u), ""}
        };
        LogTelemetry("NtQueryValueKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtDeleteValueKey_t)(HANDLE, NativeUnicodeString*);
static NtDeleteValueKey_t pfnNtDeleteValueKey = nullptr;
static NTSTATUS WINAPI Detour_NtDeleteValueKey(HANDLE KeyHandle, NativeUnicodeString* ValueName) {
    HookGuard guard;
    NTSTATUS res = pfnNtDeleteValueKey(KeyHandle, ValueName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HANDLE", (uint64_t)KeyHandle, {}, ""},
            {"lpValueName", "UNICODE_STRING", (uint64_t)ValueName, {}, ReadNativeUnicodeStringSafe(ValueName)}
        };
        LogTelemetry("NtDeleteValueKey", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtOpenKeyEx_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, ULONG);
static NtOpenKeyEx_t pfnNtOpenKeyEx = nullptr;
static NTSTATUS WINAPI Detour_NtOpenKeyEx(PHANDLE keyHandle, ACCESS_MASK desiredAccess, NativeObjectAttributes* attributes, ULONG openOptions) {
    HookGuard guard;
    NTSTATUS result = pfnNtOpenKeyEx(keyHandle, desiredAccess, attributes, openOptions);
    if (!guard.WasInside()) {
        HANDLE opened = result >= 0 ? ReadScalarSafe(keyHandle) : nullptr;
        RememberNativeRegistryHandle((uint64_t)opened);
        LogTelemetry("NtOpenKeyEx", "ntdll.dll", _ReturnAddress(), (uint64_t)result, {
            {"hKey", "HANDLE", ReadNativeRootDirectorySafe(attributes), {}, ""}, {"ObjectName", "UNICODE_STRING", (uint64_t)attributes, {}, ReadNativeObjectNameSafe(attributes)},
            {"samDesired", "ACCESS_MASK", (uint64_t)desiredAccess, {}, ""}, {"OpenOptions", "ULONG", (uint64_t)openOptions, {}, ""}, {"phkResult", "PHANDLE", (uint64_t)opened, {}, ""}
        });
    }
    return result;
}

typedef NTSTATUS(WINAPI* NtCloseRegistryKey_t)(HANDLE);
static NtCloseRegistryKey_t pfnNtCloseRegistryKey = nullptr;
static NTSTATUS WINAPI Detour_NtCloseRegistryKey(HANDLE handle) {
    HookGuard guard;
    NTSTATUS result = pfnNtCloseRegistryKey(handle);
    if (!guard.WasInside() && result >= 0 && ForgetNativeRegistryHandle((uint64_t)handle)) {
        LogTelemetry("NtCloseKey", "ntdll.dll", _ReturnAddress(), (uint64_t)result,
            { {"hKey", "HANDLE", (uint64_t)handle, {}, ""} });
    }
    return result;
}

typedef NTSTATUS(WINAPI* NtEnumerateKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
static NtEnumerateKey_t pfnNtEnumerateKey = nullptr;
static NTSTATUS WINAPI Detour_NtEnumerateKey(HANDLE keyHandle, ULONG index, ULONG informationClass, PVOID information, ULONG length, PULONG resultLength) {
    HookGuard guard;
    NTSTATUS result = pfnNtEnumerateKey(keyHandle, index, informationClass, information, length, resultLength);
    ULONG capturedLength = result >= 0 ? ReadScalarSafe(resultLength) : 0;
    if (!guard.WasInside()) LogTelemetry("NtEnumerateKey", "ntdll.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HANDLE", (uint64_t)keyHandle, {}, ""}, {"dwIndex", "ULONG", index, {}, ""},
        {"KeyInformationClass", "ULONG", informationClass, {}, ""}, {"lpData", "PVOID", (uint64_t)information, ReadBufferSafe(information, capturedLength, 64u * 1024u), ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* NtEnumerateValueKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
static NtEnumerateValueKey_t pfnNtEnumerateValueKey = nullptr;
static NTSTATUS WINAPI Detour_NtEnumerateValueKey(HANDLE keyHandle, ULONG index, ULONG informationClass, PVOID information, ULONG length, PULONG resultLength) {
    HookGuard guard;
    NTSTATUS result = pfnNtEnumerateValueKey(keyHandle, index, informationClass, information, length, resultLength);
    ULONG capturedLength = result >= 0 ? ReadScalarSafe(resultLength) : 0;
    if (!guard.WasInside()) LogTelemetry("NtEnumerateValueKey", "ntdll.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HANDLE", (uint64_t)keyHandle, {}, ""}, {"dwIndex", "ULONG", index, {}, ""},
        {"KeyValueInformationClass", "ULONG", informationClass, {}, ""}, {"lpData", "PVOID", (uint64_t)information, ReadBufferSafe(information, capturedLength, 64u * 1024u), ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryKey_t pfnNtQueryKey = nullptr;
static NTSTATUS WINAPI Detour_NtQueryKey(HANDLE keyHandle, ULONG informationClass, PVOID information, ULONG length, PULONG resultLength) {
    HookGuard guard;
    NTSTATUS result = pfnNtQueryKey(keyHandle, informationClass, information, length, resultLength);
    ULONG capturedLength = result >= 0 ? ReadScalarSafe(resultLength) : 0;
    if (!guard.WasInside()) LogTelemetry("NtQueryKey", "ntdll.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HANDLE", (uint64_t)keyHandle, {}, ""}, {"KeyInformationClass", "ULONG", informationClass, {}, ""},
        {"lpData", "PVOID", (uint64_t)information, ReadBufferSafe(information, capturedLength, 64u * 1024u), ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* NtRenameKey_t)(HANDLE, NativeUnicodeString*);
static NtRenameKey_t pfnNtRenameKey = nullptr;
static NTSTATUS WINAPI Detour_NtRenameKey(HANDLE keyHandle, NativeUnicodeString* newName) {
    HookGuard guard;
    NTSTATUS result = pfnNtRenameKey(keyHandle, newName);
    if (!guard.WasInside()) LogTelemetry("NtRenameKey", "ntdll.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HANDLE", (uint64_t)keyHandle, {}, ""}, {"lpNewName", "UNICODE_STRING", (uint64_t)newName, {}, ReadNativeUnicodeStringSafe(newName)}
    });
    return result;
}

struct NativeIoStatusBlock {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
};

typedef NTSTATUS(WINAPI* NtCreateFile_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeIoStatusBlock*, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static NtCreateFile_t pfnNtCreateFile = nullptr;
static NTSTATUS WINAPI Detour_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes, NativeIoStatusBlock* IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    if (!guard.WasInside()) {
        uint64_t handle = (res >= 0 && FileHandle) ? (uint64_t)*FileHandle : 0;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", handle, {}, ""},
            {"ObjectName", "UNICODE_STRING", (uint64_t)(ObjectAttributes ? ObjectAttributes->ObjectName : nullptr), {}, ReadNativeObjectNameSafe(ObjectAttributes)},
            {"dwDesiredAccess", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"dwShareMode", "ULONG", (uint64_t)ShareAccess, {}, ""},
            {"dwCreationDisposition", "ULONG", (uint64_t)CreateDisposition, {}, ""},
            {"dwFlagsAndAttributes", "ULONG", (uint64_t)FileAttributes, {}, ""}
        };
        LogTelemetry("NtCreateFile", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtOpenFile_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeIoStatusBlock*, ULONG, ULONG);
static NtOpenFile_t pfnNtOpenFile = nullptr;
static NTSTATUS WINAPI Detour_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes, NativeIoStatusBlock* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    HookGuard guard;
    NTSTATUS res = pfnNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    if (!guard.WasInside()) {
        uint64_t handle = (res >= 0 && FileHandle) ? (uint64_t)*FileHandle : 0;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", handle, {}, ""},
            {"ObjectName", "UNICODE_STRING", (uint64_t)(ObjectAttributes ? ObjectAttributes->ObjectName : nullptr), {}, ReadNativeObjectNameSafe(ObjectAttributes)},
            {"dwDesiredAccess", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"dwShareMode", "ULONG", (uint64_t)ShareAccess, {}, ""}
        };
        LogTelemetry("NtOpenFile", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, NativeIoStatusBlock*, PVOID, ULONG, PLARGE_INTEGER, PULONG);
static NtReadFile_t pfnNtReadFile = nullptr;
static NTSTATUS WINAPI Detour_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, NativeIoStatusBlock* IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    HookGuard guard;
    NTSTATUS res = pfnNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    if (!guard.WasInside()) {
        ULONG bytes = (res >= 0 && IoStatusBlock) ? (ULONG)IoStatusBlock->Information : 0;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)FileHandle, {}, ""},
            {"lpBuffer", "PVOID", (uint64_t)Buffer, ReadBufferSafe(Buffer, bytes, kMaximumFileBufferCapture), ""},
            {"nNumberOfBytesToRead", "ULONG", (uint64_t)Length, {}, ""},
            {"NumberOfBytesTransferred", "ULONG", (uint64_t)bytes, {}, ""},
            {"FileOffset", "UINT64", LargeIntegerOffset(ByteOffset), {}, ""},
            {"Asynchronous", "BOOL", (Event || ApcRoutine) ? 1ull : 0ull, {}, ""}
        };
        LogTelemetry("NtReadFile", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtWriteFile_t)(HANDLE, HANDLE, PVOID, PVOID, NativeIoStatusBlock*, PVOID, ULONG, PLARGE_INTEGER, PULONG);
static NtWriteFile_t pfnNtWriteFile = nullptr;
static NTSTATUS WINAPI Detour_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, NativeIoStatusBlock* IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    HookGuard guard;
    NTSTATUS res = pfnNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    if (!guard.WasInside()) {
        ULONG written = (res >= 0 && IoStatusBlock) ? (ULONG)IoStatusBlock->Information : 0;
        std::vector<ParameterCapture> params = {
            {"hFile", "HANDLE", (uint64_t)FileHandle, {}, ""},
            {"lpBuffer", "PVOID", (uint64_t)Buffer, ReadBufferSafe(Buffer, Length, kMaximumFileBufferCapture), ""},
            {"nNumberOfBytesToWrite", "ULONG", (uint64_t)Length, {}, ""},
            {"NumberOfBytesTransferred", "ULONG", (uint64_t)written, {}, ""},
            {"FileOffset", "UINT64", LargeIntegerOffset(ByteOffset), {}, ""},
            {"Asynchronous", "BOOL", (Event || ApcRoutine) ? 1ull : 0ull, {}, ""}
        };
        LogTelemetry("NtWriteFile", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtDeleteFile_t)(NativeObjectAttributes*);
static NtDeleteFile_t pfnNtDeleteFile = nullptr;
static NTSTATUS WINAPI Detour_NtDeleteFile(NativeObjectAttributes* ObjectAttributes) {
    HookGuard guard;
    NTSTATUS res = pfnNtDeleteFile(ObjectAttributes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ObjectName", "UNICODE_STRING", (uint64_t)(ObjectAttributes ? ObjectAttributes->ObjectName : nullptr), {}, ReadNativeObjectNameSafe(ObjectAttributes)}
        };
        LogTelemetry("NtDeleteFile", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 12. RegOpenKeyExW
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
static RegOpenKeyExW_t pfnRegOpenKeyExW = nullptr;
static LSTATUS WINAPI Detour_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegOpenKeyExW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
static RegOpenKeyExA_t pfnRegOpenKeyExA = nullptr;
static LSTATUS WINAPI Detour_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegOpenKeyExA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegOpenKeyW_t)(HKEY, LPCWSTR, PHKEY);
static RegOpenKeyW_t pfnRegOpenKeyW = nullptr;
static LSTATUS WINAPI Detour_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegOpenKeyW(hKey, lpSubKey, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegOpenKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegOpenKeyA_t)(HKEY, LPCSTR, PHKEY);
static RegOpenKeyA_t pfnRegOpenKeyA = nullptr;
static LSTATUS WINAPI Detour_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegOpenKeyA(hKey, lpSubKey, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegOpenKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 13. RegCreateKeyExW
typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static RegCreateKeyExW_t pfnRegCreateKeyExW = nullptr;
static LSTATUS WINAPI Detour_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    HookGuard guard;
    LSTATUS res = pfnRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        DWORD disposition = lpdwDisposition ? *lpdwDisposition : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""},
            {"phkResult", "PHKEY", resultKey, {}, ""},
            {"lpdwDisposition", "DWORD", (uint64_t)disposition, {}, ""}
        };
        LogTelemetry("RegCreateKeyExW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegCreateKeyExA_t)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static RegCreateKeyExA_t pfnRegCreateKeyExA = nullptr;
static LSTATUS WINAPI Detour_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    HookGuard guard;
    LSTATUS res = pfnRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        DWORD disposition = lpdwDisposition ? *lpdwDisposition : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""},
            {"phkResult", "PHKEY", resultKey, {}, ""},
            {"lpdwDisposition", "DWORD", (uint64_t)disposition, {}, ""}
        };
        LogTelemetry("RegCreateKeyExA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegCreateKeyW_t)(HKEY, LPCWSTR, PHKEY);
static RegCreateKeyW_t pfnRegCreateKeyW = nullptr;
static LSTATUS WINAPI Detour_RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegCreateKeyW(hKey, lpSubKey, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegCreateKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegCreateKeyA_t)(HKEY, LPCSTR, PHKEY);
static RegCreateKeyA_t pfnRegCreateKeyA = nullptr;
static LSTATUS WINAPI Detour_RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
    HookGuard guard;
    LSTATUS res = pfnRegCreateKeyA(hKey, lpSubKey, phkResult);
    if (!guard.WasInside()) {
        uint64_t resultKey = (res == ERROR_SUCCESS && phkResult) ? (uint64_t)*phkResult : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"phkResult", "PHKEY", resultKey, {}, ""}
        };
        LogTelemetry("RegCreateKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// 14. RegSetValueExW
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExW_t pfnRegSetValueExW = nullptr;
static LSTATUS WINAPI Detour_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    HookGuard guard;
    LSTATUS res = pfnRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    if (!guard.WasInside()) {
        std::string decodedData = DecodeRegistryDataForTelemetry(dwType, lpData, cbData, true);
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCWSTR", (uint64_t)lpValueName, {}, WideToUtf8(ReadWStringSafe(lpValueName))},
            {"dwType", "DWORD", (uint64_t)dwType, {}, ""},
            {"lpData", "const BYTE*", (uint64_t)lpData, ReadBufferSafe(lpData, cbData, 64u * 1024u), decodedData}
        };
        LogTelemetry("RegSetValueExW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegSetValueExA_t)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExA_t pfnRegSetValueExA = nullptr;
static LSTATUS WINAPI Detour_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    HookGuard guard;
    LSTATUS res = pfnRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    if (!guard.WasInside()) {
        std::string decodedData = DecodeRegistryDataForTelemetry(dwType, lpData, cbData, false);
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCSTR", (uint64_t)lpValueName, {}, ReadAStringSafe(lpValueName)},
            {"dwType", "DWORD", (uint64_t)dwType, {}, ""},
            {"lpData", "const BYTE*", (uint64_t)lpData, ReadBufferSafe(lpData, cbData, 64u * 1024u), decodedData}
        };
        LogTelemetry("RegSetValueExA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteValueW_t)(HKEY, LPCWSTR);
static RegDeleteValueW_t pfnRegDeleteValueW = nullptr;
static LSTATUS WINAPI Detour_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteValueW(hKey, lpValueName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCWSTR", (uint64_t)lpValueName, {}, WideToUtf8(ReadWStringSafe(lpValueName))}
        };
        LogTelemetry("RegDeleteValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteValueA_t)(HKEY, LPCSTR);
static RegDeleteValueA_t pfnRegDeleteValueA = nullptr;
static LSTATUS WINAPI Detour_RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteValueA(hKey, lpValueName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCSTR", (uint64_t)lpValueName, {}, ReadAStringSafe(lpValueName)}
        };
        LogTelemetry("RegDeleteValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegSetValueW_t)(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD);
static RegSetValueW_t pfnRegSetValueW = nullptr;
static LSTATUS WINAPI Detour_RegSetValueW(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) {
    HookGuard guard;
    LSTATUS res = pfnRegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"dwType", "DWORD", (uint64_t)dwType, {}, ""},
            {"lpData", "LPCWSTR", (uint64_t)lpData, ReadBufferSafe(lpData, cbData, 64u * 1024u), DecodeRegistryDataForTelemetry(dwType, lpData, cbData, true)}
        };
        LogTelemetry("RegSetValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegSetValueA_t)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD);
static RegSetValueA_t pfnRegSetValueA = nullptr;
static LSTATUS WINAPI Detour_RegSetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData) {
    HookGuard guard;
    LSTATUS res = pfnRegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"dwType", "DWORD", (uint64_t)dwType, {}, ""},
            {"lpData", "LPCSTR", (uint64_t)lpData, ReadBufferSafe(lpData, cbData, 64u * 1024u), DecodeRegistryDataForTelemetry(dwType, lpData, cbData, false)}
        };
        LogTelemetry("RegSetValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegQueryValueExW_t pfnRegQueryValueExW = nullptr;
static LSTATUS WINAPI Detour_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    HookGuard guard;
    DWORD beforeSize = lpcbData ? *lpcbData : 0;
    LSTATUS res = pfnRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (!guard.WasInside()) {
        DWORD type = lpType ? *lpType : 0;
        DWORD size = (res == ERROR_SUCCESS && lpcbData) ? *lpcbData : beforeSize;
        std::string decoded = res == ERROR_SUCCESS ? DecodeRegistryDataForTelemetry(type, lpData, size, true) : "";
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCWSTR", (uint64_t)lpValueName, {}, WideToUtf8(ReadWStringSafe(lpValueName))},
            {"dwType", "DWORD", (uint64_t)type, {}, ""},
            {"lpData", "LPBYTE", (uint64_t)lpData, ReadBufferSafe(lpData, (res == ERROR_SUCCESS) ? size : 0, 64u * 1024u), decoded}
        };
        LogTelemetry("RegQueryValueExW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegQueryValueExA_t pfnRegQueryValueExA = nullptr;
static LSTATUS WINAPI Detour_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    HookGuard guard;
    DWORD beforeSize = lpcbData ? *lpcbData : 0;
    LSTATUS res = pfnRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (!guard.WasInside()) {
        DWORD type = lpType ? *lpType : 0;
        DWORD size = (res == ERROR_SUCCESS && lpcbData) ? *lpcbData : beforeSize;
        std::string decoded = res == ERROR_SUCCESS ? DecodeRegistryDataForTelemetry(type, lpData, size, false) : "";
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpValueName", "LPCSTR", (uint64_t)lpValueName, {}, ReadAStringSafe(lpValueName)},
            {"dwType", "DWORD", (uint64_t)type, {}, ""},
            {"lpData", "LPBYTE", (uint64_t)lpData, ReadBufferSafe(lpData, (res == ERROR_SUCCESS) ? size : 0, 64u * 1024u), decoded}
        };
        LogTelemetry("RegQueryValueExA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegQueryValueW_t)(HKEY, LPCWSTR, LPWSTR, PLONG);
static RegQueryValueW_t pfnRegQueryValueW = nullptr;
static LSTATUS WINAPI Detour_RegQueryValueW(HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpData, PLONG lpcbData) {
    HookGuard guard;
    LONG beforeSize = lpcbData ? *lpcbData : 0;
    LSTATUS res = pfnRegQueryValueW(hKey, lpSubKey, lpData, lpcbData);
    if (!guard.WasInside()) {
        DWORD size = (res == ERROR_SUCCESS && lpcbData) ? (DWORD)*lpcbData : (DWORD)beforeSize;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))},
            {"lpData", "LPWSTR", (uint64_t)lpData, ReadBufferSafe(lpData, (res == ERROR_SUCCESS) ? size : 0, 64u * 1024u), WideToUtf8(ReadWStringSafe(lpData, size / 2))}
        };
        LogTelemetry("RegQueryValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegQueryValueA_t)(HKEY, LPCSTR, LPSTR, PLONG);
static RegQueryValueA_t pfnRegQueryValueA = nullptr;
static LSTATUS WINAPI Detour_RegQueryValueA(HKEY hKey, LPCSTR lpSubKey, LPSTR lpData, PLONG lpcbData) {
    HookGuard guard;
    LONG beforeSize = lpcbData ? *lpcbData : 0;
    LSTATUS res = pfnRegQueryValueA(hKey, lpSubKey, lpData, lpcbData);
    if (!guard.WasInside()) {
        DWORD size = (res == ERROR_SUCCESS && lpcbData) ? (DWORD)*lpcbData : (DWORD)beforeSize;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)},
            {"lpData", "LPSTR", (uint64_t)lpData, ReadBufferSafe(lpData, (res == ERROR_SUCCESS) ? size : 0, 64u * 1024u), ReadAStringSafe(lpData, size)}
        };
        LogTelemetry("RegQueryValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteKeyW_t)(HKEY, LPCWSTR);
static RegDeleteKeyW_t pfnRegDeleteKeyW = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteKeyW(hKey, lpSubKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))} };
        LogTelemetry("RegDeleteKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteKeyA_t)(HKEY, LPCSTR);
static RegDeleteKeyA_t pfnRegDeleteKeyA = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteKeyA(hKey, lpSubKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)} };
        LogTelemetry("RegDeleteKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteKeyExW_t)(HKEY, LPCWSTR, REGSAM, DWORD);
static RegDeleteKeyExW_t pfnRegDeleteKeyExW = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))}, {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""} };
        LogTelemetry("RegDeleteKeyExW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteKeyExA_t)(HKEY, LPCSTR, REGSAM, DWORD);
static RegDeleteKeyExA_t pfnRegDeleteKeyExA = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)}, {"samDesired", "REGSAM", (uint64_t)samDesired, {}, ""} };
        LogTelemetry("RegDeleteKeyExA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteTreeW_t)(HKEY, LPCWSTR);
static RegDeleteTreeW_t pfnRegDeleteTreeW = nullptr;
static LSTATUS WINAPI Detour_RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteTreeW(hKey, lpSubKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)lpSubKey, {}, WideToUtf8(ReadWStringSafe(lpSubKey))} };
        LogTelemetry("RegDeleteTreeW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegDeleteTreeA_t)(HKEY, LPCSTR);
static RegDeleteTreeA_t pfnRegDeleteTreeA = nullptr;
static LSTATUS WINAPI Detour_RegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey) {
    HookGuard guard;
    LSTATUS res = pfnRegDeleteTreeA(hKey, lpSubKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)lpSubKey, {}, ReadAStringSafe(lpSubKey)} };
        LogTelemetry("RegDeleteTreeA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegCloseKey_t)(HKEY);
static RegCloseKey_t pfnRegCloseKey = nullptr;
static LSTATUS WINAPI Detour_RegCloseKey(HKEY hKey) {
    HookGuard guard;
    LSTATUS res = pfnRegCloseKey(hKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""} };
        LogTelemetry("RegCloseKey", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LSTATUS(WINAPI* RegGetValueW_t)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static RegGetValueW_t pfnRegGetValueW = nullptr;
static LSTATUS WINAPI Detour_RegGetValueW(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, DWORD flags, LPDWORD type, PVOID data, LPDWORD dataSize) {
    HookGuard guard;
    DWORD requested = ReadScalarSafe(dataSize);
    LSTATUS result = pfnRegGetValueW(hKey, subKey, valueName, flags, type, data, dataSize);
    if (!guard.WasInside()) {
        DWORD capturedType = ReadScalarSafe(type);
        DWORD capturedSize = result == ERROR_SUCCESS ? ReadScalarSafe(dataSize) : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))},
            {"lpValueName", "LPCWSTR", (uint64_t)valueName, {}, WideToUtf8(ReadWStringSafe(valueName))}, {"dwFlags", "DWORD", flags, {}, ""},
            {"dwType", "DWORD", capturedType, {}, ""}, {"requestedSize", "DWORD", requested, {}, ""},
            {"lpData", "PVOID", (uint64_t)data, ReadBufferSafe(data, capturedSize, 64u * 1024u), DecodeRegistryDataForTelemetry(capturedType, data, capturedSize, true)}
        };
        LogTelemetry("RegGetValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegGetValueA_t)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static RegGetValueA_t pfnRegGetValueA = nullptr;
static LSTATUS WINAPI Detour_RegGetValueA(HKEY hKey, LPCSTR subKey, LPCSTR valueName, DWORD flags, LPDWORD type, PVOID data, LPDWORD dataSize) {
    HookGuard guard;
    DWORD requested = ReadScalarSafe(dataSize);
    LSTATUS result = pfnRegGetValueA(hKey, subKey, valueName, flags, type, data, dataSize);
    if (!guard.WasInside()) {
        DWORD capturedType = ReadScalarSafe(type);
        DWORD capturedSize = result == ERROR_SUCCESS ? ReadScalarSafe(dataSize) : 0;
        std::vector<ParameterCapture> params = {
            {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)},
            {"lpValueName", "LPCSTR", (uint64_t)valueName, {}, ReadAStringSafe(valueName)}, {"dwFlags", "DWORD", flags, {}, ""},
            {"dwType", "DWORD", capturedType, {}, ""}, {"requestedSize", "DWORD", requested, {}, ""},
            {"lpData", "PVOID", (uint64_t)data, ReadBufferSafe(data, capturedSize, 64u * 1024u), DecodeRegistryDataForTelemetry(capturedType, data, capturedSize, false)}
        };
        LogTelemetry("RegGetValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegEnumKeyExW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
static RegEnumKeyExW_t pfnRegEnumKeyExW = nullptr;
static LSTATUS WINAPI Detour_RegEnumKeyExW(HKEY hKey, DWORD index, LPWSTR name, LPDWORD nameLength, LPDWORD reserved, LPWSTR className, LPDWORD classLength, PFILETIME lastWrite) {
    HookGuard guard;
    LSTATUS result = pfnRegEnumKeyExW(hKey, index, name, nameLength, reserved, className, classLength, lastWrite);
    if (!guard.WasInside()) {
        DWORD length = result == ERROR_SUCCESS ? ReadScalarSafe(nameLength) : 0;
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"dwIndex", "DWORD", index, {}, ""},
            {"lpSubKey", "LPWSTR", (uint64_t)name, {}, result == ERROR_SUCCESS ? WideToUtf8(ReadWStringSafe(name, length + 1)) : ""} };
        LogTelemetry("RegEnumKeyExW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegEnumKeyExA_t)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
static RegEnumKeyExA_t pfnRegEnumKeyExA = nullptr;
static LSTATUS WINAPI Detour_RegEnumKeyExA(HKEY hKey, DWORD index, LPSTR name, LPDWORD nameLength, LPDWORD reserved, LPSTR className, LPDWORD classLength, PFILETIME lastWrite) {
    HookGuard guard;
    LSTATUS result = pfnRegEnumKeyExA(hKey, index, name, nameLength, reserved, className, classLength, lastWrite);
    if (!guard.WasInside()) {
        DWORD length = result == ERROR_SUCCESS ? ReadScalarSafe(nameLength) : 0;
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"dwIndex", "DWORD", index, {}, ""},
            {"lpSubKey", "LPSTR", (uint64_t)name, {}, result == ERROR_SUCCESS ? ReadAStringSafe(name, length + 1) : ""} };
        LogTelemetry("RegEnumKeyExA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegEnumValueW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegEnumValueW_t pfnRegEnumValueW = nullptr;
static LSTATUS WINAPI Detour_RegEnumValueW(HKEY hKey, DWORD index, LPWSTR valueName, LPDWORD valueNameLength, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    HookGuard guard;
    LSTATUS result = pfnRegEnumValueW(hKey, index, valueName, valueNameLength, reserved, type, data, dataSize);
    if (!guard.WasInside()) {
        DWORD capturedType = ReadScalarSafe(type), capturedSize = result == ERROR_SUCCESS ? ReadScalarSafe(dataSize) : 0;
        DWORD nameLength = result == ERROR_SUCCESS ? ReadScalarSafe(valueNameLength) : 0;
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"dwIndex", "DWORD", index, {}, ""},
            {"lpValueName", "LPWSTR", (uint64_t)valueName, {}, result == ERROR_SUCCESS ? WideToUtf8(ReadWStringSafe(valueName, nameLength + 1)) : ""},
            {"dwType", "DWORD", capturedType, {}, ""}, {"lpData", "LPBYTE", (uint64_t)data, ReadBufferSafe(data, capturedSize, 64u * 1024u), DecodeRegistryDataForTelemetry(capturedType, data, capturedSize, true)} };
        LogTelemetry("RegEnumValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegEnumValueA_t)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegEnumValueA_t pfnRegEnumValueA = nullptr;
static LSTATUS WINAPI Detour_RegEnumValueA(HKEY hKey, DWORD index, LPSTR valueName, LPDWORD valueNameLength, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    HookGuard guard;
    LSTATUS result = pfnRegEnumValueA(hKey, index, valueName, valueNameLength, reserved, type, data, dataSize);
    if (!guard.WasInside()) {
        DWORD capturedType = ReadScalarSafe(type), capturedSize = result == ERROR_SUCCESS ? ReadScalarSafe(dataSize) : 0;
        DWORD nameLength = result == ERROR_SUCCESS ? ReadScalarSafe(valueNameLength) : 0;
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"dwIndex", "DWORD", index, {}, ""},
            {"lpValueName", "LPSTR", (uint64_t)valueName, {}, result == ERROR_SUCCESS ? ReadAStringSafe(valueName, nameLength + 1) : ""},
            {"dwType", "DWORD", capturedType, {}, ""}, {"lpData", "LPBYTE", (uint64_t)data, ReadBufferSafe(data, capturedSize, 64u * 1024u), DecodeRegistryDataForTelemetry(capturedType, data, capturedSize, false)} };
        LogTelemetry("RegEnumValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegRenameKey_t)(HKEY, LPCWSTR, LPCWSTR);
static RegRenameKey_t pfnRegRenameKey = nullptr;
static LSTATUS WINAPI Detour_RegRenameKey(HKEY hKey, LPCWSTR subKey, LPCWSTR newName) {
    HookGuard guard;
    LSTATUS result = pfnRegRenameKey(hKey, subKey, newName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""},
            {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))},
            {"lpNewName", "LPCWSTR", (uint64_t)newName, {}, WideToUtf8(ReadWStringSafe(newName))} };
        LogTelemetry("RegRenameKey", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegNotifyChangeKeyValue_t)(HKEY, BOOL, DWORD, HANDLE, BOOL);
static RegNotifyChangeKeyValue_t pfnRegNotifyChangeKeyValue = nullptr;
static LSTATUS WINAPI Detour_RegNotifyChangeKeyValue(HKEY hKey, BOOL watchSubtree, DWORD filter, HANDLE eventHandle, BOOL asynchronous) {
    HookGuard guard;
    LSTATUS result = pfnRegNotifyChangeKeyValue(hKey, watchSubtree, filter, eventHandle, asynchronous);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"bWatchSubtree", "BOOL", (uint64_t)watchSubtree, {}, ""},
            {"dwNotifyFilter", "DWORD", filter, {}, ""}, {"hEvent", "HANDLE", (uint64_t)eventHandle, {}, ""}, {"fAsynchronous", "BOOL", (uint64_t)asynchronous, {}, ""} };
        LogTelemetry("RegNotifyChangeKeyValue", "advapi32.dll", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

typedef LSTATUS(WINAPI* RegQueryInfoKeyW_t)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
static RegQueryInfoKeyW_t pfnRegQueryInfoKeyW = nullptr;
static LSTATUS WINAPI Detour_RegQueryInfoKeyW(HKEY hKey, LPWSTR className, LPDWORD classLength, LPDWORD reserved, LPDWORD subKeys, LPDWORD maxSubKeyLength, LPDWORD maxClassLength, LPDWORD values, LPDWORD maxValueNameLength, LPDWORD maxValueLength, LPDWORD securityDescriptor, PFILETIME lastWrite) {
    HookGuard guard;
    LSTATUS result = pfnRegQueryInfoKeyW(hKey, className, classLength, reserved, subKeys, maxSubKeyLength, maxClassLength, values, maxValueNameLength, maxValueLength, securityDescriptor, lastWrite);
    if (!guard.WasInside()) LogTelemetry("RegQueryInfoKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"SubKeyCount", "DWORD", ReadScalarSafe(subKeys), {}, ""},
        {"ValueCount", "DWORD", ReadScalarSafe(values), {}, ""}, {"MaxValueLength", "DWORD", ReadScalarSafe(maxValueLength), {}, ""}
    });
    return result;
}

typedef LSTATUS(WINAPI* RegQueryInfoKeyA_t)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
static RegQueryInfoKeyA_t pfnRegQueryInfoKeyA = nullptr;
static LSTATUS WINAPI Detour_RegQueryInfoKeyA(HKEY hKey, LPSTR className, LPDWORD classLength, LPDWORD reserved, LPDWORD subKeys, LPDWORD maxSubKeyLength, LPDWORD maxClassLength, LPDWORD values, LPDWORD maxValueNameLength, LPDWORD maxValueLength, LPDWORD securityDescriptor, PFILETIME lastWrite) {
    HookGuard guard;
    LSTATUS result = pfnRegQueryInfoKeyA(hKey, className, classLength, reserved, subKeys, maxSubKeyLength, maxClassLength, values, maxValueNameLength, maxValueLength, securityDescriptor, lastWrite);
    if (!guard.WasInside()) LogTelemetry("RegQueryInfoKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, {
        {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"SubKeyCount", "DWORD", ReadScalarSafe(subKeys), {}, ""},
        {"ValueCount", "DWORD", ReadScalarSafe(values), {}, ""}, {"MaxValueLength", "DWORD", ReadScalarSafe(maxValueLength), {}, ""}
    });
    return result;
}

typedef LSTATUS(WINAPI* RegLoadKeyW_t)(HKEY, LPCWSTR, LPCWSTR);
static RegLoadKeyW_t pfnRegLoadKeyW = nullptr;
static LSTATUS WINAPI Detour_RegLoadKeyW(HKEY hKey, LPCWSTR subKey, LPCWSTR file) { HookGuard guard; LSTATUS result = pfnRegLoadKeyW(hKey, subKey, file);
    if (!guard.WasInside()) LogTelemetry("RegLoadKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))}, {"lpFile", "LPCWSTR", (uint64_t)file, {}, WideToUtf8(ReadWStringSafe(file, 2048))} }); return result; }
typedef LSTATUS(WINAPI* RegLoadKeyA_t)(HKEY, LPCSTR, LPCSTR);
static RegLoadKeyA_t pfnRegLoadKeyA = nullptr;
static LSTATUS WINAPI Detour_RegLoadKeyA(HKEY hKey, LPCSTR subKey, LPCSTR file) { HookGuard guard; LSTATUS result = pfnRegLoadKeyA(hKey, subKey, file);
    if (!guard.WasInside()) LogTelemetry("RegLoadKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)}, {"lpFile", "LPCSTR", (uint64_t)file, {}, ReadAStringSafe(file, 2048)} }); return result; }

typedef LSTATUS(WINAPI* RegRestoreKeyW_t)(HKEY, LPCWSTR, DWORD);
static RegRestoreKeyW_t pfnRegRestoreKeyW = nullptr;
static LSTATUS WINAPI Detour_RegRestoreKeyW(HKEY hKey, LPCWSTR file, DWORD flags) { HookGuard guard; LSTATUS result = pfnRegRestoreKeyW(hKey, file, flags);
    if (!guard.WasInside()) LogTelemetry("RegRestoreKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpFile", "LPCWSTR", (uint64_t)file, {}, WideToUtf8(ReadWStringSafe(file, 2048))}, {"dwFlags", "DWORD", flags, {}, ""} }); return result; }
typedef LSTATUS(WINAPI* RegRestoreKeyA_t)(HKEY, LPCSTR, DWORD);
static RegRestoreKeyA_t pfnRegRestoreKeyA = nullptr;
static LSTATUS WINAPI Detour_RegRestoreKeyA(HKEY hKey, LPCSTR file, DWORD flags) { HookGuard guard; LSTATUS result = pfnRegRestoreKeyA(hKey, file, flags);
    if (!guard.WasInside()) LogTelemetry("RegRestoreKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpFile", "LPCSTR", (uint64_t)file, {}, ReadAStringSafe(file, 2048)}, {"dwFlags", "DWORD", flags, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegCopyTreeW_t)(HKEY, LPCWSTR, HKEY);
static RegCopyTreeW_t pfnRegCopyTreeW = nullptr;
static LSTATUS WINAPI Detour_RegCopyTreeW(HKEY source, LPCWSTR subKey, HKEY destination) { HookGuard guard; LSTATUS result = pfnRegCopyTreeW(source, subKey, destination);
    if (!guard.WasInside()) LogTelemetry("RegCopyTreeW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)source, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))}, {"hDestinationKey", "HKEY", (uint64_t)destination, {}, ""} }); return result; }
typedef LSTATUS(WINAPI* RegCopyTreeA_t)(HKEY, LPCSTR, HKEY);
static RegCopyTreeA_t pfnRegCopyTreeA = nullptr;
static LSTATUS WINAPI Detour_RegCopyTreeA(HKEY source, LPCSTR subKey, HKEY destination) { HookGuard guard; LSTATUS result = pfnRegCopyTreeA(source, subKey, destination);
    if (!guard.WasInside()) LogTelemetry("RegCopyTreeA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)source, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)}, {"hDestinationKey", "HKEY", (uint64_t)destination, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegSaveKeyExW_t)(HKEY, LPCWSTR, const SECURITY_ATTRIBUTES*, DWORD);
static RegSaveKeyExW_t pfnRegSaveKeyExW = nullptr;
static LSTATUS WINAPI Detour_RegSaveKeyExW(HKEY hKey, LPCWSTR file, const SECURITY_ATTRIBUTES* attributes, DWORD flags) { HookGuard guard; LSTATUS result = pfnRegSaveKeyExW(hKey, file, attributes, flags);
    if (!guard.WasInside()) LogTelemetry("RegSaveKeyExW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpFile", "LPCWSTR", (uint64_t)file, {}, WideToUtf8(ReadWStringSafe(file, 2048))}, {"dwFlags", "DWORD", flags, {}, ""} }); return result; }
typedef LSTATUS(WINAPI* RegSaveKeyExA_t)(HKEY, LPCSTR, const SECURITY_ATTRIBUTES*, DWORD);
static RegSaveKeyExA_t pfnRegSaveKeyExA = nullptr;
static LSTATUS WINAPI Detour_RegSaveKeyExA(HKEY hKey, LPCSTR file, const SECURITY_ATTRIBUTES* attributes, DWORD flags) { HookGuard guard; LSTATUS result = pfnRegSaveKeyExA(hKey, file, attributes, flags);
    if (!guard.WasInside()) LogTelemetry("RegSaveKeyExA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpFile", "LPCSTR", (uint64_t)file, {}, ReadAStringSafe(file, 2048)}, {"dwFlags", "DWORD", flags, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegUnLoadKeyW_t)(HKEY, LPCWSTR);
static RegUnLoadKeyW_t pfnRegUnLoadKeyW = nullptr;
static LSTATUS WINAPI Detour_RegUnLoadKeyW(HKEY hKey, LPCWSTR subKey) { HookGuard guard; LSTATUS result = pfnRegUnLoadKeyW(hKey, subKey);
    if (!guard.WasInside()) LogTelemetry("RegUnLoadKeyW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))} }); return result; }
typedef LSTATUS(WINAPI* RegUnLoadKeyA_t)(HKEY, LPCSTR);
static RegUnLoadKeyA_t pfnRegUnLoadKeyA = nullptr;
static LSTATUS WINAPI Detour_RegUnLoadKeyA(HKEY hKey, LPCSTR subKey) { HookGuard guard; LSTATUS result = pfnRegUnLoadKeyA(hKey, subKey);
    if (!guard.WasInside()) LogTelemetry("RegUnLoadKeyA", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)} }); return result; }

typedef LSTATUS(WINAPI* RegFlushKey_t)(HKEY);
static RegFlushKey_t pfnRegFlushKey = nullptr;
static LSTATUS WINAPI Detour_RegFlushKey(HKEY hKey) { HookGuard guard; LSTATUS result = pfnRegFlushKey(hKey);
    if (!guard.WasInside()) LogTelemetry("RegFlushKey", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegSetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
static RegSetKeySecurity_t pfnRegSetKeySecurity = nullptr;
static LSTATUS WINAPI Detour_RegSetKeySecurity(HKEY hKey, SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor) { HookGuard guard; LSTATUS result = pfnRegSetKeySecurity(hKey, information, descriptor);
    if (!guard.WasInside()) LogTelemetry("RegSetKeySecurity", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"SecurityInformation", "DWORD", information, {}, ""}, {"SecurityDescriptor", "PSECURITY_DESCRIPTOR", (uint64_t)descriptor, {}, ""} }); return result; }
typedef LSTATUS(WINAPI* RegGetKeySecurity_t)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD);
static RegGetKeySecurity_t pfnRegGetKeySecurity = nullptr;
static LSTATUS WINAPI Detour_RegGetKeySecurity(HKEY hKey, SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor, LPDWORD descriptorSize) { HookGuard guard; LSTATUS result = pfnRegGetKeySecurity(hKey, information, descriptor, descriptorSize);
    DWORD size = result == ERROR_SUCCESS ? ReadScalarSafe(descriptorSize) : 0;
    if (!guard.WasInside()) LogTelemetry("RegGetKeySecurity", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"SecurityInformation", "DWORD", information, {}, ""}, {"lpData", "PSECURITY_DESCRIPTOR", (uint64_t)descriptor, ReadBufferSafe(descriptor, size, 64u * 1024u), ""} }); return result; }

typedef LSTATUS(WINAPI* RegCreateKeyTransactedW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD, HANDLE, PVOID);
static RegCreateKeyTransactedW_t pfnRegCreateKeyTransactedW = nullptr;
static LSTATUS WINAPI Detour_RegCreateKeyTransactedW(HKEY hKey, LPCWSTR subKey, DWORD reserved, LPWSTR className, DWORD options, REGSAM desired, const SECURITY_ATTRIBUTES* attributes, PHKEY resultKey, LPDWORD disposition, HANDLE transaction, PVOID extended) { HookGuard guard;
    LSTATUS result = pfnRegCreateKeyTransactedW(hKey, subKey, reserved, className, options, desired, attributes, resultKey, disposition, transaction, extended);
    HKEY opened = result == ERROR_SUCCESS ? ReadScalarSafe(resultKey) : nullptr;
    if (!guard.WasInside()) LogTelemetry("RegCreateKeyTransactedW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))}, {"samDesired", "REGSAM", desired, {}, ""}, {"phkResult", "PHKEY", (uint64_t)opened, {}, ""}, {"lpdwDisposition", "DWORD", ReadScalarSafe(disposition), {}, ""}, {"hTransaction", "HANDLE", (uint64_t)transaction, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegOpenKeyTransactedW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
static RegOpenKeyTransactedW_t pfnRegOpenKeyTransactedW = nullptr;
static LSTATUS WINAPI Detour_RegOpenKeyTransactedW(HKEY hKey, LPCWSTR subKey, DWORD options, REGSAM desired, PHKEY resultKey, HANDLE transaction, PVOID extended) { HookGuard guard;
    LSTATUS result = pfnRegOpenKeyTransactedW(hKey, subKey, options, desired, resultKey, transaction, extended); HKEY opened = result == ERROR_SUCCESS ? ReadScalarSafe(resultKey) : nullptr;
    if (!guard.WasInside()) LogTelemetry("RegOpenKeyTransactedW", "advapi32.dll", _ReturnAddress(), (uint64_t)result, { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))}, {"samDesired", "REGSAM", desired, {}, ""}, {"phkResult", "PHKEY", (uint64_t)opened, {}, ""}, {"hTransaction", "HANDLE", (uint64_t)transaction, {}, ""} }); return result; }

typedef LSTATUS(WINAPI* RegDeleteKeyValueW_t)(HKEY, LPCWSTR, LPCWSTR);
static RegDeleteKeyValueW_t pfnRegDeleteKeyValueW = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyValueW(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName) {
    HookGuard guard; LSTATUS result = pfnRegDeleteKeyValueW(hKey, subKey, valueName);
    if (!guard.WasInside()) LogTelemetry("RegDeleteKeyValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)result,
        { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))}, {"lpValueName", "LPCWSTR", (uint64_t)valueName, {}, WideToUtf8(ReadWStringSafe(valueName))} });
    return result;
}

typedef LSTATUS(WINAPI* RegDeleteKeyValueA_t)(HKEY, LPCSTR, LPCSTR);
static RegDeleteKeyValueA_t pfnRegDeleteKeyValueA = nullptr;
static LSTATUS WINAPI Detour_RegDeleteKeyValueA(HKEY hKey, LPCSTR subKey, LPCSTR valueName) {
    HookGuard guard; LSTATUS result = pfnRegDeleteKeyValueA(hKey, subKey, valueName);
    if (!guard.WasInside()) LogTelemetry("RegDeleteKeyValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)result,
        { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)}, {"lpValueName", "LPCSTR", (uint64_t)valueName, {}, ReadAStringSafe(valueName)} });
    return result;
}

typedef LSTATUS(WINAPI* RegSetKeyValueW_t)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD);
static RegSetKeyValueW_t pfnRegSetKeyValueW = nullptr;
static LSTATUS WINAPI Detour_RegSetKeyValueW(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, DWORD type, LPCVOID data, DWORD dataSize) {
    HookGuard guard; LSTATUS result = pfnRegSetKeyValueW(hKey, subKey, valueName, type, data, dataSize);
    if (!guard.WasInside()) LogTelemetry("RegSetKeyValueW", "advapi32.dll", _ReturnAddress(), (uint64_t)result,
        { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCWSTR", (uint64_t)subKey, {}, WideToUtf8(ReadWStringSafe(subKey))},
          {"lpValueName", "LPCWSTR", (uint64_t)valueName, {}, WideToUtf8(ReadWStringSafe(valueName))}, {"dwType", "DWORD", type, {}, ""},
          {"lpData", "LPCVOID", (uint64_t)data, ReadBufferSafe(data, dataSize, 64u * 1024u), DecodeRegistryDataForTelemetry(type, data, dataSize, true)} });
    return result;
}

typedef LSTATUS(WINAPI* RegSetKeyValueA_t)(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD);
static RegSetKeyValueA_t pfnRegSetKeyValueA = nullptr;
static LSTATUS WINAPI Detour_RegSetKeyValueA(HKEY hKey, LPCSTR subKey, LPCSTR valueName, DWORD type, LPCVOID data, DWORD dataSize) {
    HookGuard guard; LSTATUS result = pfnRegSetKeyValueA(hKey, subKey, valueName, type, data, dataSize);
    if (!guard.WasInside()) LogTelemetry("RegSetKeyValueA", "advapi32.dll", _ReturnAddress(), (uint64_t)result,
        { {"hKey", "HKEY", (uint64_t)hKey, {}, ""}, {"lpSubKey", "LPCSTR", (uint64_t)subKey, {}, ReadAStringSafe(subKey)},
          {"lpValueName", "LPCSTR", (uint64_t)valueName, {}, ReadAStringSafe(valueName)}, {"dwType", "DWORD", type, {}, ""},
          {"lpData", "LPCVOID", (uint64_t)data, ReadBufferSafe(data, dataSize, 64u * 1024u), DecodeRegistryDataForTelemetry(type, data, dataSize, false)} });
    return result;
}

// 15. CreateThread
typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static CreateThread_t pfnCreateThread = nullptr;
static HANDLE WINAPI Detour_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HookGuard guard;
    HANDLE res = pfnCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (!guard.WasInside()) {
        DWORD tid = lpThreadId ? *lpThreadId : (res ? GetThreadId(res) : 0);
        std::vector<ParameterCapture> params = {
            {"lpStartAddress", "LPTHREAD_START_ROUTINE", (uint64_t)lpStartAddress, {}, ""},
            {"lpParameter", "LPVOID", (uint64_t)lpParameter, {}, ""},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("CreateThread", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static CreateRemoteThread_t pfnCreateRemoteThread = nullptr;
static HANDLE WINAPI Detour_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HookGuard guard;
    if (!guard.WasInside()) {
        InjectAgentIntoProcess(hProcess);
    }

    HANDLE res = pfnCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (!guard.WasInside()) {
        DWORD tid = lpThreadId ? *lpThreadId : (res ? GetThreadId(res) : 0);
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpStartAddress", "LPTHREAD_START_ROUTINE", (uint64_t)lpStartAddress, {}, ""},
            {"lpParameter", "LPVOID", (uint64_t)lpParameter, {}, ""},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("CreateRemoteThread", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
static CreateRemoteThreadEx_t pfnCreateRemoteThreadEx = nullptr;
static HANDLE WINAPI Detour_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    HookGuard guard;
    if (!guard.WasInside()) {
        InjectAgentIntoProcess(hProcess);
    }

    HANDLE res = pfnCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
    if (!guard.WasInside()) {
        DWORD tid = lpThreadId ? *lpThreadId : (res ? GetThreadId(res) : 0);
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpStartAddress", "LPTHREAD_START_ROUTINE", (uint64_t)lpStartAddress, {}, ""},
            {"lpParameter", "LPVOID", (uint64_t)lpParameter, {}, ""},
            {"dwCreationFlags", "DWORD", (uint64_t)dwCreationFlags, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("CreateRemoteThreadEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static VirtualAllocEx_t pfnVirtualAllocEx = nullptr;
static LPVOID WINAPI Detour_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    HookGuard guard;
    LPVOID res = pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    if (!guard.WasInside()) {
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpAddress", "LPVOID", (uint64_t)lpAddress, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)dwSize, {}, ""},
            {"flProtect", "DWORD", (uint64_t)flProtect, {}, ""}
        };
        LogTelemetry("VirtualAllocEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
static WriteProcessMemory_t pfnWriteProcessMemory = nullptr;
static BOOL WINAPI Detour_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    HookGuard guard;
    BOOL res = pfnWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if (!guard.WasInside()) {
        DWORD pid = hProcess ? GetProcessId(hProcess) : 0;
        SIZE_T bytesWritten = 0;
        if (res && lpNumberOfBytesWritten) SafeCopyBuffer(&bytesWritten, lpNumberOfBytesWritten, sizeof(bytesWritten));
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpBaseAddress", "LPVOID", (uint64_t)lpBaseAddress, {}, ""},
            {"lpBuffer", "LPCVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, nSize, kMaximumMemoryBufferCapture), ""},
            {"nSize", "SIZE_T", (uint64_t)nSize, {}, ""},
            {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)bytesWritten, {}, ""}
        };
        LogTelemetry("WriteProcessMemory", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* OpenThread_t)(DWORD, BOOL, DWORD);
static OpenThread_t pfnOpenThread = nullptr;
static HANDLE WINAPI Detour_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
    HookGuard guard;
    HANDLE res = pfnOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    if (!guard.WasInside()) {
        DWORD pid = 0;
        if (res) {
            typedef DWORD(WINAPI* GetProcessIdOfThread_t)(HANDLE);
            static GetProcessIdOfThread_t pfnGetProcessIdOfThread = nullptr;
            if (!pfnGetProcessIdOfThread) {
                HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
                if (hKernel32) {
                    pfnGetProcessIdOfThread = (GetProcessIdOfThread_t)GetProcAddress(hKernel32, "GetProcessIdOfThread");
                }
            }
            if (pfnGetProcessIdOfThread) {
                pid = pfnGetProcessIdOfThread(res);
            }
        }
        std::vector<ParameterCapture> params = {
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)dwThreadId, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"ThreadHandle", "HANDLE", (uint64_t)res, {}, ""}
        };
        LogTelemetry("OpenThread", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtOpenThread_t)(PHANDLE, ACCESS_MASK, void*, void*);
static NtOpenThread_t pfnNtOpenThread = nullptr;
static NTSTATUS WINAPI Detour_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, void* ClientId) {
    HookGuard guard;
    NTSTATUS res = pfnNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    if (!guard.WasInside()) {
        DWORD tid = 0;
        DWORD pid = 0;
        HANDLE handle = (res == 0 && ThreadHandle && *ThreadHandle) ? *ThreadHandle : nullptr;
        if (ClientId) {
            void* cidBuf[2] = {};
            if (SafeCopyBuffer(cidBuf, ClientId, sizeof(cidBuf))) {
                pid = (DWORD)(ULONG_PTR)cidBuf[0];
                tid = (DWORD)(ULONG_PTR)cidBuf[1];
            }
        }
        if (!pid && handle) {
            typedef DWORD(WINAPI* GetProcessIdOfThread_t)(HANDLE);
            static GetProcessIdOfThread_t pfnGetProcessIdOfThread = nullptr;
            if (!pfnGetProcessIdOfThread) {
                HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
                if (hKernel32) {
                    pfnGetProcessIdOfThread = (GetProcessIdOfThread_t)GetProcAddress(hKernel32, "GetProcessIdOfThread");
                }
            }
            if (pfnGetProcessIdOfThread) {
                pid = pfnGetProcessIdOfThread(handle);
            }
        }
        std::vector<ParameterCapture> params = {
            {"ThreadHandle", "PHANDLE", (uint64_t)handle, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""}
        };
        LogTelemetry("NtOpenThread", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* DuplicateHandle_t)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
static DuplicateHandle_t pfnDuplicateHandle = nullptr;
static BOOL WINAPI Detour_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    HookGuard guard;
    BOOL res = pfnDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
    if (!guard.WasInside()) {
        HANDLE targetHandle = (res && lpTargetHandle) ? *lpTargetHandle : nullptr;
        std::vector<ParameterCapture> params = {
            {"hSourceProcessHandle", "HANDLE", (uint64_t)hSourceProcessHandle, {}, ""},
            {"hSourceHandle", "HANDLE", (uint64_t)hSourceHandle, {}, ""},
            {"hTargetProcessHandle", "HANDLE", (uint64_t)hTargetProcessHandle, {}, ""},
            {"lpTargetHandle", "LPHANDLE", (uint64_t)targetHandle, {}, ""},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"bInheritHandle", "BOOL", (uint64_t)bInheritHandle, {}, ""},
            {"dwOptions", "DWORD", (uint64_t)dwOptions, {}, ""}
        };
        LogTelemetry("DuplicateHandle", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LONG (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
static NtCreateThreadEx_t pfnNtCreateThreadEx = nullptr;
static LONG NTAPI Detour_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    HookGuard guard;
    if (!guard.WasInside()) {
        InjectAgentIntoProcess(ProcessHandle);
    }

    LONG res = pfnNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    if (!guard.WasInside()) {
        DWORD tid = (res == 0 && ThreadHandle && *ThreadHandle) ? GetThreadId(*ThreadHandle) : 0;
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        uint64_t thread = (res == 0 && ThreadHandle && *ThreadHandle) ? (uint64_t)*ThreadHandle : 0;
        std::vector<ParameterCapture> params = {
            {"ProcessHandle", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"ThreadHandle", "HANDLE", thread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"StartRoutine", "PVOID", (uint64_t)StartRoutine, {}, ""},
            {"Argument", "PVOID", (uint64_t)Argument, {}, ""},
            {"CreateFlags", "ULONG", (uint64_t)CreateFlags, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("NtCreateThreadEx", "ntdll.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);
static QueueUserAPC_t pfnQueueUserAPC = nullptr;
static DWORD WINAPI Detour_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    HookGuard guard;
    if (!guard.WasInside()) {
        InjectAgentIntoThreadOwner(hThread);
    }

    DWORD res = pfnQueueUserAPC(pfnAPC, hThread, dwData);
    if (!guard.WasInside()) {
        DWORD tid = hThread ? GetThreadId(hThread) : 0;
        DWORD pid = hThread ? GetProcessIdOfThread(hThread) : 0;
        std::vector<ParameterCapture> params = {
            {"pfnAPC", "PAPCFUNC", (uint64_t)pfnAPC, {}, ""},
            {"hThread", "HANDLE", (uint64_t)hThread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""},
            {"dwData", "ULONG_PTR", (uint64_t)dwData, {}, ""}
        };
        LogTelemetry("QueueUserAPC", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetThreadContext_t)(HANDLE, const CONTEXT*);
static SetThreadContext_t pfnSetThreadContext = nullptr;
static BOOL WINAPI Detour_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    HookGuard guard;
    if (!guard.WasInside()) {
        InjectAgentIntoThreadOwner(hThread);
    }

    BOOL res = pfnSetThreadContext(hThread, lpContext);
    if (!guard.WasInside()) {
        DWORD tid = hThread ? GetThreadId(hThread) : 0;
        DWORD pid = hThread ? GetProcessIdOfThread(hThread) : 0;
        uint64_t instructionPointer = 0;
        CONTEXT contextCopy{};
        if (lpContext && SafeCopyBuffer(&contextCopy, lpContext, sizeof(contextCopy))) {
#ifdef _WIN64
            instructionPointer = contextCopy.Rip;
#else
            instructionPointer = contextCopy.Eip;
#endif
        }
        std::vector<ParameterCapture> params = {
            {"hThread", "HANDLE", (uint64_t)hThread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""},
            {"lpContext", "const CONTEXT*", (uint64_t)lpContext, ReadBufferSafe(lpContext, sizeof(CONTEXT)), ""},
            {"InstructionPointer", "PVOID", instructionPointer, {}, "Thread instruction pointer"}
        };
        LogTelemetry("SetThreadContext", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

struct NativeClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeClientId*);
static NtOpenProcess_t pfnNtOpenProcess = nullptr;
static NTSTATUS WINAPI Detour_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes, NativeClientId* ClientId) {
    HookGuard guard;
    NTSTATUS res = pfnNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    if (!guard.WasInside()) {
        NativeClientId cid {};
        if (ClientId) SafeCopyBuffer(&cid, ClientId, sizeof(cid));
        uint64_t handle = (res >= 0 && ProcessHandle) ? (uint64_t)*ProcessHandle : 0;
        std::vector<ParameterCapture> params = {
            {"ProcessHandle", "HANDLE", handle, {}, ""},
            {"dwDesiredAccess", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(uintptr_t)cid.UniqueProcess, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)(uintptr_t)cid.UniqueThread, {}, ""}
        };
        LogTelemetry("NtOpenProcess", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static NtAllocateVirtualMemory_t pfnNtAllocateVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    HookGuard guard;
    NTSTATUS res = pfnNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (!guard.WasInside()) {
        PVOID base = nullptr;
        SIZE_T size = 0;
        if (BaseAddress) SafeCopyBuffer(&base, BaseAddress, sizeof(base));
        if (RegionSize) SafeCopyBuffer(&size, RegionSize, sizeof(size));
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpAddress", "PVOID*", (uint64_t)base, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)size, {}, ""},
            {"flAllocationType", "ULONG", (uint64_t)AllocationType, {}, ""},
            {"flProtect", "ULONG", (uint64_t)Protect, {}, ""}
        };
        LogTelemetry("NtAllocateVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
static NtWriteVirtualMemory_t pfnNtWriteVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {
    HookGuard guard;
    NTSTATUS res = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    if (!guard.WasInside()) {
        ULONG written = 0;
        if (NumberOfBytesWritten) SafeCopyBuffer(&written, NumberOfBytesWritten, sizeof(written));
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpBaseAddress", "PVOID", (uint64_t)BaseAddress, {}, ""},
            {"lpBuffer", "PVOID", (uint64_t)Buffer, ReadBufferSafe(Buffer, NumberOfBytesToWrite, kMaximumMemoryBufferCapture), ""},
            {"nSize", "ULONG", (uint64_t)NumberOfBytesToWrite, {}, ""},
            {"lpNumberOfBytesWritten", "ULONG", (uint64_t)written, {}, ""},
            {"NumberOfBytesTransferred", "ULONG", (uint64_t)written, {}, ""}
        };
        LogTelemetry("NtWriteVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static NtProtectVirtualMemory_t pfnNtProtectVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    HookGuard guard;
    NTSTATUS res = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    if (!guard.WasInside()) {
        PVOID base = nullptr;
        SIZE_T size = 0;
        ULONG oldProtect = 0;
        if (BaseAddress) SafeCopyBuffer(&base, BaseAddress, sizeof(base));
        if (RegionSize) SafeCopyBuffer(&size, RegionSize, sizeof(size));
        if (OldProtect) SafeCopyBuffer(&oldProtect, OldProtect, sizeof(oldProtect));
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"lpAddress", "PVOID*", (uint64_t)base, {}, ""},
            {"dwSize", "SIZE_T", (uint64_t)size, {}, ""},
            {"flNewProtect", "ULONG", (uint64_t)NewProtect, {}, ""},
            {"lpflOldProtect", "ULONG", (uint64_t)oldProtect, {}, ""}
        };
        LogTelemetry("NtProtectVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
static NtFreeVirtualMemory_t pfnNtFreeVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtFreeVirtualMemory(HANDLE process, PVOID* baseAddress, PSIZE_T regionSize, ULONG freeType) {
    HookGuard guard; NTSTATUS result = pfnNtFreeVirtualMemory(process, baseAddress, regionSize, freeType);
    PVOID base = nullptr; SIZE_T size = 0;
    if (baseAddress) SafeCopyBuffer(&base, baseAddress, sizeof(base));
    if (regionSize) SafeCopyBuffer(&size, regionSize, sizeof(size));
    if (!guard.WasInside()) LogTelemetry("NtFreeVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpAddress", "PVOID", (uint64_t)base, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}, {"dwFreeType", "ULONG", freeType, {}, ""}
    }); return result;
}

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
static NtReadVirtualMemory_t pfnNtReadVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtReadVirtualMemory(HANDLE process, PVOID baseAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesReadOut) {
    HookGuard guard; NTSTATUS result = pfnNtReadVirtualMemory(process, baseAddress, buffer, size, bytesReadOut);
    SIZE_T bytesRead = 0; if (result >= 0 && bytesReadOut) SafeCopyBuffer(&bytesRead, bytesReadOut, sizeof(bytesRead));
    if (!guard.WasInside()) LogTelemetry("NtReadVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpBaseAddress", "PVOID", (uint64_t)baseAddress, {}, ""},
        {"lpBuffer", "PVOID", (uint64_t)buffer, ReadBufferSafe(buffer, bytesRead, kMaximumMemoryBufferCapture), ""},
        {"nSize", "SIZE_T", (uint64_t)size, {}, ""}, {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)bytesRead, {}, ""}
    }); return result;
}

typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
static NtQueryVirtualMemory_t pfnNtQueryVirtualMemory = nullptr;
static NTSTATUS WINAPI Detour_NtQueryVirtualMemory(HANDLE process, PVOID address, ULONG infoClass, PVOID information, SIZE_T length, PSIZE_T returnLength) {
    HookGuard guard; NTSTATUS result = pfnNtQueryVirtualMemory(process, address, infoClass, information, length, returnLength);
    MEMORY_BASIC_INFORMATION copy{};
    if (result >= 0 && infoClass == 0 && information) SafeCopyBuffer(&copy, information, (std::min<size_t>)((size_t)length, sizeof(copy)));
    if (!guard.WasInside()) LogTelemetry("NtQueryVirtualMemory", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpAddress", "PVOID", (uint64_t)address, {}, ""}, {"MemoryInformationClass", "ULONG", infoClass, {}, ""},
        {"BaseAddress", "PVOID", (uint64_t)copy.BaseAddress, {}, ""}, {"RegionSize", "SIZE_T", (uint64_t)copy.RegionSize, {}, ""},
        {"State", "DWORD", copy.State, {}, ""}, {"Protect", "DWORD", copy.Protect, {}, ""}, {"Type", "DWORD", copy.Type, {}, ""}
    }); return result;
}

typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
static NtUnmapViewOfSection_t pfnNtUnmapViewOfSection = nullptr;
static NTSTATUS WINAPI Detour_NtUnmapViewOfSection(HANDLE process, PVOID baseAddress) {
    HookGuard guard; NTSTATUS result = pfnNtUnmapViewOfSection(process, baseAddress);
    if (!guard.WasInside()) LogTelemetry("NtUnmapViewOfSection", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"hProcess", "HANDLE", (uint64_t)process, {}, ""}, {"dwProcessId", "DWORD", process ? (uint64_t)GetProcessId(process) : 0, {}, ""},
        {"lpAddress", "PVOID", (uint64_t)baseAddress, {}, ""}
    }); return result;
}

typedef NTSTATUS(WINAPI* NtOpenSection_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*);
static NtOpenSection_t pfnNtOpenSection = nullptr;
static NTSTATUS WINAPI Detour_NtOpenSection(PHANDLE sectionHandle, ACCESS_MASK desiredAccess, NativeObjectAttributes* attributes) {
    HookGuard guard; NTSTATUS result = pfnNtOpenSection(sectionHandle, desiredAccess, attributes);
    HANDLE handle = nullptr; if (result >= 0 && sectionHandle) SafeCopyBuffer(&handle, sectionHandle, sizeof(handle));
    if (!guard.WasInside()) LogTelemetry("NtOpenSection", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"SectionHandle", "HANDLE", (uint64_t)handle, {}, ""}, {"DesiredAccess", "ACCESS_MASK", desiredAccess, {}, ""},
        {"ObjectName", "UNICODE_STRING", (uint64_t)(attributes ? attributes->ObjectName : nullptr), {}, ReadNativeObjectNameSafe(attributes)}
    }); return result;
}

typedef PVOID(WINAPI* RtlAllocateHeap_t)(PVOID, ULONG, SIZE_T);
static RtlAllocateHeap_t pfnRtlAllocateHeap = nullptr;
static PVOID WINAPI Detour_RtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size) {
    HookGuard guard; PVOID result = pfnRtlAllocateHeap(heap, flags, size);
    if (!guard.WasInside()) LogTelemetry("RtlAllocateHeap", "ntdll.dll", _ReturnAddress(), (uint64_t)result,
        {{"hHeap", "PVOID", (uint64_t)heap, {}, ""}, {"dwFlags", "ULONG", flags, {}, ""}, {"dwSize", "SIZE_T", (uint64_t)size, {}, ""}});
    return result;
}
typedef BOOLEAN(WINAPI* RtlFreeHeap_t)(PVOID, ULONG, PVOID);
static RtlFreeHeap_t pfnRtlFreeHeap = nullptr;
static BOOLEAN WINAPI Detour_RtlFreeHeap(PVOID heap, ULONG flags, PVOID memory) {
    HookGuard guard; BOOLEAN result = pfnRtlFreeHeap(heap, flags, memory);
    if (!guard.WasInside()) LogTelemetry("RtlFreeHeap", "ntdll.dll", _ReturnAddress(), (uint64_t)result,
        {{"hHeap", "PVOID", (uint64_t)heap, {}, ""}, {"lpAddress", "PVOID", (uint64_t)memory, {}, ""}});
    return result;
}
typedef VOID(WINAPI* RtlMoveMemory_t)(VOID*, const VOID*, SIZE_T);
static RtlMoveMemory_t pfnRtlMoveMemory = nullptr;
static VOID WINAPI Detour_RtlMoveMemory(VOID* destination, const VOID* source, SIZE_T length) {
    HookGuard guard; pfnRtlMoveMemory(destination, source, length);
    if (!guard.WasInside()) LogTelemetry("RtlMoveMemory", "ntdll.dll", _ReturnAddress(), 1, {
        {"lpBaseAddress", "PVOID", (uint64_t)destination, {}, ""},
        {"lpBuffer", "PVOID", (uint64_t)source, ReadBufferSafe(destination, length, kMaximumMemoryBufferCapture), ""},
        {"nSize", "SIZE_T", (uint64_t)length, {}, ""}, {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)length, {}, ""}
    });
}

typedef void* (__cdecl* CrtMemcpy_t)(void*, const void*, size_t);
static CrtMemcpy_t pfnUcrtMemcpy = nullptr;
static void* __cdecl Detour_UcrtMemcpy(void* destination, const void* source, size_t length) {
    HookGuard guard; void* result = pfnUcrtMemcpy(destination, source, length);
    if (!guard.WasInside()) LogTelemetry("memcpy", "ucrtbase.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpBaseAddress", "PVOID", (uint64_t)destination, {}, ""},
        {"lpBuffer", "PVOID", (uint64_t)source, ReadBufferSafe(destination, length, kMaximumMemoryBufferCapture), ""},
        {"nSize", "SIZE_T", (uint64_t)length, {}, ""}, {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)length, {}, ""}
    });
    return result;
}
static CrtMemcpy_t pfnMsvcrtMemcpy = nullptr;
static void* __cdecl Detour_MsvcrtMemcpy(void* destination, const void* source, size_t length) {
    HookGuard guard; void* result = pfnMsvcrtMemcpy(destination, source, length);
    if (!guard.WasInside()) LogTelemetry("memcpy", "msvcrt.dll", _ReturnAddress(), (uint64_t)result, {
        {"lpBaseAddress", "PVOID", (uint64_t)destination, {}, ""},
        {"lpBuffer", "PVOID", (uint64_t)source, ReadBufferSafe(destination, length, kMaximumMemoryBufferCapture), ""},
        {"nSize", "SIZE_T", (uint64_t)length, {}, ""}, {"NumberOfBytesTransferred", "SIZE_T", (uint64_t)length, {}, ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* RtlCreateUserThread_t)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, NativeClientId*);
static RtlCreateUserThread_t pfnRtlCreateUserThread = nullptr;
static NTSTATUS WINAPI Detour_RtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, NativeClientId* ClientId) {
    HookGuard guard;
    if (!guard.WasInside()) InjectAgentIntoProcess(ProcessHandle);
    NTSTATUS res = pfnRtlCreateUserThread(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientId);
    if (!guard.WasInside()) {
        NativeClientId cid {};
        if (ClientId) SafeCopyBuffer(&cid, ClientId, sizeof(cid));
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        uint64_t thread = (res >= 0 && ThreadHandle) ? (uint64_t)*ThreadHandle : 0;
        std::vector<ParameterCapture> params = {
            {"ProcessHandle", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"StartRoutine", "PVOID", (uint64_t)StartAddress, {}, ""},
            {"Argument", "PVOID", (uint64_t)StartParameter, {}, ""},
            {"CreateFlags", "BOOLEAN", (uint64_t)CreateSuspended, {}, ""},
            {"ThreadHandle", "HANDLE", thread, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)(uintptr_t)cid.UniqueThread, {}, ""}
        };
        LogTelemetry("RtlCreateUserThread", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
static NtQueueApcThread_t pfnNtQueueApcThread = nullptr;
static NTSTATUS WINAPI Detour_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    HookGuard guard;
    if (!guard.WasInside()) InjectAgentIntoThreadOwner(ThreadHandle);
    NTSTATUS res = pfnNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hThread", "HANDLE", (uint64_t)ThreadHandle, {}, ""},
            {"pfnAPC", "PVOID", (uint64_t)ApcRoutine, {}, ""},
            {"dwData", "PVOID", (uint64_t)ApcArgument1, {}, ""},
            {"ApcArgument2", "PVOID", (uint64_t)ApcArgument2, {}, ""},
            {"ApcArgument3", "PVOID", (uint64_t)ApcArgument3, {}, ""}
        };
        LogTelemetry("NtQueueApcThread", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* SuspendThread_t)(HANDLE);
static SuspendThread_t pfnSuspendThread = nullptr;
static DWORD WINAPI Detour_SuspendThread(HANDLE hThread) {
    HookGuard guard;
    if (!guard.WasInside()) InjectAgentIntoThreadOwner(hThread);
    DWORD res = pfnSuspendThread(hThread);
    if (!guard.WasInside()) {
        DWORD tid = hThread ? GetThreadId(hThread) : 0;
        DWORD pid = hThread ? GetProcessIdOfThread(hThread) : 0;
        std::vector<ParameterCapture> params = {
            {"hThread", "HANDLE", (uint64_t)hThread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("SuspendThread", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* ResumeThread_t)(HANDLE);
static ResumeThread_t pfnResumeThread = nullptr;
static DWORD WINAPI Detour_ResumeThread(HANDLE hThread) {
    HookGuard guard;
    if (!guard.WasInside()) InjectAgentIntoThreadOwner(hThread);
    DWORD res = pfnResumeThread(hThread);
    if (!guard.WasInside()) {
        DWORD tid = hThread ? GetThreadId(hThread) : 0;
        DWORD pid = hThread ? GetProcessIdOfThread(hThread) : 0;
        std::vector<ParameterCapture> params = {
            {"hThread", "HANDLE", (uint64_t)hThread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""}
        };
        LogTelemetry("ResumeThread", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);
static GetThreadContext_t pfnGetThreadContext = nullptr;
static BOOL WINAPI Detour_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    HookGuard guard;
    if (!guard.WasInside()) InjectAgentIntoThreadOwner(hThread);
    BOOL res = pfnGetThreadContext(hThread, lpContext);
    if (!guard.WasInside()) {
        DWORD tid = hThread ? GetThreadId(hThread) : 0;
        DWORD pid = hThread ? GetProcessIdOfThread(hThread) : 0;
        uint64_t instructionPointer = 0;
        CONTEXT contextCopy{};
        if (res && lpContext && SafeCopyBuffer(&contextCopy, lpContext, sizeof(contextCopy))) {
#ifdef _WIN64
            instructionPointer = contextCopy.Rip;
#else
            instructionPointer = contextCopy.Eip;
#endif
        }
        std::vector<ParameterCapture> params = {
            {"hThread", "HANDLE", (uint64_t)hThread, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)tid, {}, ""},
            {"lpContext", "LPCONTEXT", (uint64_t)lpContext, ReadBufferSafe(lpContext, res ? sizeof(CONTEXT) : 0), ""},
            {"InstructionPointer", "PVOID", instructionPointer, {}, "Thread instruction pointer"}
        };
        LogTelemetry("GetThreadContext", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
static NtCreateSection_t pfnNtCreateSection = nullptr;
static NTSTATUS WINAPI Detour_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, NativeObjectAttributes* ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    HookGuard guard;
    NTSTATUS res = pfnNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    if (!guard.WasInside()) {
        LARGE_INTEGER maxSize {};
        if (MaximumSize) SafeCopyBuffer(&maxSize, MaximumSize, sizeof(maxSize));
        uint64_t handle = (res >= 0 && SectionHandle) ? (uint64_t)*SectionHandle : 0;
        std::vector<ParameterCapture> params = {
            {"SectionHandle", "HANDLE", handle, {}, ""},
            {"DesiredAccess", "ACCESS_MASK", (uint64_t)DesiredAccess, {}, ""},
            {"MaximumSize", "LARGE_INTEGER", (uint64_t)maxSize.QuadPart, {}, ""},
            {"SectionPageProtection", "ULONG", (uint64_t)SectionPageProtection, {}, ""},
            {"AllocationAttributes", "ULONG", (uint64_t)AllocationAttributes, {}, ""},
            {"FileHandle", "HANDLE", (uint64_t)FileHandle, {}, ""}
        };
        LogTelemetry("NtCreateSection", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
static NtMapViewOfSection_t pfnNtMapViewOfSection = nullptr;
static NTSTATUS WINAPI Detour_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    HookGuard guard;
    NTSTATUS res = pfnNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    if (!guard.WasInside()) {
        PVOID base = nullptr;
        SIZE_T viewSize = 0;
        if (BaseAddress) SafeCopyBuffer(&base, BaseAddress, sizeof(base));
        if (ViewSize) SafeCopyBuffer(&viewSize, ViewSize, sizeof(viewSize));
        DWORD pid = ProcessHandle ? GetProcessId(ProcessHandle) : 0;
        std::vector<ParameterCapture> params = {
            {"SectionHandle", "HANDLE", (uint64_t)SectionHandle, {}, ""},
            {"ProcessHandle", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)pid, {}, ""},
            {"BaseAddress", "PVOID*", (uint64_t)base, {}, ""},
            {"ViewSize", "SIZE_T", (uint64_t)viewSize, {}, ""},
            {"AllocationType", "ULONG", (uint64_t)AllocationType, {}, ""},
            {"Win32Protect", "ULONG", (uint64_t)Win32Protect, {}, ""}
        };
        LogTelemetry("NtMapViewOfSection", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// Socket hooks (ws2_32.dll - connect, send, recv)
typedef SOCKET(WSAAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
static WSASocketA_t pfnWSASocketA = nullptr;
static SOCKET WSAAPI Detour_WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags) {
    HookGuard guard;
    SOCKET res = pfnWSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"af", "int", (uint64_t)af, {}, ""},
            {"type", "int", (uint64_t)type, {}, ""},
            {"protocol", "int", (uint64_t)protocol, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("WSASocketA", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SOCKET(WSAAPI* WSASocketW_t)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
static WSASocketW_t pfnWSASocketW = nullptr;
static SOCKET WSAAPI Detour_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) {
    HookGuard guard;
    SOCKET res = pfnWSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"af", "int", (uint64_t)af, {}, ""},
            {"type", "int", (uint64_t)type, {}, ""},
            {"protocol", "int", (uint64_t)protocol, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("WSASocketW", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SOCKET(WSAAPI* socket_t)(int, int, int);
static socket_t pfnsocket = nullptr;
static SOCKET WSAAPI Detour_socket(int af, int type, int protocol) {
    HookGuard guard;
    SOCKET res = pfnsocket(af, type, protocol);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"af", "int", (uint64_t)af, {}, ""},
            {"type", "int", (uint64_t)type, {}, ""},
            {"protocol", "int", (uint64_t)protocol, {}, ""}
        };
        LogTelemetry("socket", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* bind_t)(SOCKET, const struct sockaddr*, int);
static bind_t pfnbind = nullptr;
static int WSAAPI Detour_bind(SOCKET s, const struct sockaddr* name, int namelen) {
    HookGuard guard;
    int res = pfnbind(s, name, namelen);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"name", "const sockaddr*", (uint64_t)name, ReadBufferSafe(name, namelen), DecodeSockaddr(name)}
        };
        LogTelemetry("bind", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* listen_t)(SOCKET, int);
static listen_t pfnlisten = nullptr;
static int WSAAPI Detour_listen(SOCKET s, int backlog) {
    HookGuard guard;
    int res = pfnlisten(s, backlog);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"backlog", "int", (uint64_t)backlog, {}, ""}
        };
        LogTelemetry("listen", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SOCKET(WSAAPI* accept_t)(SOCKET, struct sockaddr*, int*);
static accept_t pfnaccept = nullptr;
static SOCKET WSAAPI Detour_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    HookGuard guard;
    SOCKET res = pfnaccept(s, addr, addrlen);
    if (!guard.WasInside()) {
        int len = addrlen ? *addrlen : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"addr", "sockaddr*", (uint64_t)addr, ReadBufferSafe(addr, len), DecodeSockaddr(addr)}
        };
        LogTelemetry("accept", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
static WSAConnect_t pfnWSAConnect = nullptr;
static int WSAAPI Detour_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    HookGuard guard;
    int res = pfnWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"name", "const sockaddr*", (uint64_t)name, ReadBufferSafe(name, namelen), DecodeSockaddr(name)}
        };
        LogTelemetry("WSAConnect", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
static sendto_t pfnsendto = nullptr;
static int WSAAPI Detour_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    HookGuard guard;
    int res = pfnsendto(s, buf, len, flags, to, tolen);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "const char*", (uint64_t)buf, ReadBufferSafe(buf, len, 64u * 1024u), ""},
            {"len", "int", (uint64_t)len, {}, ""},
            {"to", "const sockaddr*", (uint64_t)to, ReadBufferSafe(to, tolen), DecodeSockaddr(to)}
        };
        LogTelemetry("sendto", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
static recvfrom_t pfnrecvfrom = nullptr;
static int WSAAPI Detour_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    HookGuard guard;
    int res = pfnrecvfrom(s, buf, len, flags, from, fromlen);
    if (!guard.WasInside()) {
        int read = (res > 0) ? res : 0;
        int addrLen = fromlen ? *fromlen : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "char*", (uint64_t)buf, ReadBufferSafe(buf, read, 64u * 1024u), ""},
            {"len", "int", (uint64_t)len, {}, ""},
            {"from", "sockaddr*", (uint64_t)from, ReadBufferSafe(from, addrLen), DecodeSockaddr(from)}
        };
        LogTelemetry("recvfrom", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* closesocket_t)(SOCKET);
static closesocket_t pfnclosesocket = nullptr;
static int WSAAPI Detour_closesocket(SOCKET s) {
    HookGuard guard;
    int res = pfnclosesocket(s);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""}
        };
        LogTelemetry("closesocket", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSASend_t pfnWSASend = nullptr;
static int WSAAPI Detour_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    int res = pfnWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    int wsaError = res == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!guard.WasInside()) {
        DWORD bytes = lpNumberOfBytesSent ? *lpNumberOfBytesSent : 0;
        const char* data = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].buf : nullptr;
        DWORD len = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].len : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "WSABUF", (uint64_t)data, ReadBufferSafe(data, len, 64u * 1024u), ""},
            {"len", "DWORD", (uint64_t)len, {}, ""},
            {"bytesSent", "DWORD", (uint64_t)bytes, {}, ""},
            {"WSAError", "int", (uint64_t)wsaError, {}, wsaError == WSA_IO_PENDING ? "I/O pending" : ""}
        };
        LogTelemetry("WSASend", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSARecv_t pfnWSARecv = nullptr;
static int WSAAPI Detour_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    int res = pfnWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    int wsaError = res == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!guard.WasInside()) {
        DWORD bytes = lpNumberOfBytesRecvd ? *lpNumberOfBytesRecvd : 0;
        const char* data = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].buf : nullptr;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "WSABUF", (uint64_t)data, ReadBufferSafe(data, bytes, 64u * 1024u), ""},
            {"len", "DWORD", (uint64_t)bytes, {}, ""},
            {"WSAError", "int", (uint64_t)wsaError, {}, wsaError == WSA_IO_PENDING ? "I/O pending" : ""}
        };
        LogTelemetry("WSARecv", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSASendTo_t pfnWSASendTo = nullptr;
static int WSAAPI Detour_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    int res = pfnWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
    int wsaError = res == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!guard.WasInside()) {
        const char* data = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].buf : nullptr;
        DWORD len = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].len : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "WSABUF", (uint64_t)data, ReadBufferSafe(data, len, 64u * 1024u), ""},
            {"len", "DWORD", (uint64_t)len, {}, ""},
            {"to", "const sockaddr*", (uint64_t)lpTo, ReadBufferSafe(lpTo, iToLen), DecodeSockaddr(lpTo)},
            {"WSAError", "int", (uint64_t)wsaError, {}, wsaError == WSA_IO_PENDING ? "I/O pending" : ""}
        };
        LogTelemetry("WSASendTo", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSARecvFrom_t pfnWSARecvFrom = nullptr;
static int WSAAPI Detour_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    HookGuard guard;
    int res = pfnWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    int wsaError = res == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!guard.WasInside()) {
        DWORD bytes = lpNumberOfBytesRecvd ? *lpNumberOfBytesRecvd : 0;
        const char* data = (lpBuffers && dwBufferCount > 0) ? lpBuffers[0].buf : nullptr;
        int addrLen = lpFromlen ? *lpFromlen : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "WSABUF", (uint64_t)data, ReadBufferSafe(data, bytes, 64u * 1024u), ""},
            {"len", "DWORD", (uint64_t)bytes, {}, ""},
            {"from", "sockaddr*", (uint64_t)lpFrom, ReadBufferSafe(lpFrom, addrLen), DecodeSockaddr(lpFrom)},
            {"WSAError", "int", (uint64_t)wsaError, {}, wsaError == WSA_IO_PENDING ? "I/O pending" : ""}
        };
        LogTelemetry("WSARecvFrom", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* connect_t)(SOCKET, const struct sockaddr*, int);
static connect_t pfnconnect = nullptr;
static int WSAAPI Detour_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    HookGuard guard;
    int res = pfnconnect(s, name, namelen);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"name", "const sockaddr*", (uint64_t)name, ReadBufferSafe(name, namelen), DecodeSockaddr(name)}
        };
        LogTelemetry("connect", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* send_t)(SOCKET, const char*, int, int);
static send_t pfnsend = nullptr;
static int WSAAPI Detour_send(SOCKET s, const char* buf, int len, int flags) {
    HookGuard guard;
    int res = pfnsend(s, buf, len, flags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "const char*", (uint64_t)buf, ReadBufferSafe(buf, len, 64u * 1024u), ""},
            {"len", "int", (uint64_t)len, {}, ""}
        };
        LogTelemetry("send", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* recv_t)(SOCKET, char*, int, int);
static recv_t pfnrecv = nullptr;
static int WSAAPI Detour_recv(SOCKET s, char* buf, int len, int flags) {
    HookGuard guard;
    int res = pfnrecv(s, buf, len, flags);
    if (!guard.WasInside()) {
        int read = (res > 0) ? res : 0;
        std::vector<ParameterCapture> params = {
            {"s", "SOCKET", (uint64_t)s, {}, ""},
            {"buf", "char*", (uint64_t)buf, ReadBufferSafe(buf, read, 64u * 1024u), ""},
            {"len", "int", (uint64_t)len, {}, ""}
        };
        LogTelemetry("recv", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
static getaddrinfo_t pfngetaddrinfo = nullptr;

template <typename T>
static std::string DecodeAddrInfoResults(T** results) {
    if (!results) return "";
    T* current = nullptr;
    if (!SafeCopyBuffer(&current, results, sizeof(current))) return "";
    std::ostringstream decoded;
    for (int i = 0; current && i < 32; ++i) {
        T entry{};
        if (!SafeCopyBuffer(&entry, current, sizeof(entry))) break;
        std::string endpoint = DecodeSockaddr(entry.ai_addr);
        if (!endpoint.empty()) {
            if (decoded.tellp() > 0) decoded << "; ";
            decoded << endpoint;
        }
        current = entry.ai_next;
    }
    return decoded.str();
}

static int WSAAPI Detour_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    HookGuard guard;
    int res = pfngetaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pNodeName", "PCSTR", (uint64_t)pNodeName, {}, ReadAStringSafe(pNodeName)},
            {"pServiceName", "PCSTR", (uint64_t)pServiceName, {}, ReadAStringSafe(pServiceName)},
            {"ResolvedAddresses", "ADDRINFOA", (uint64_t)ppResult, {}, res == 0 ? DecodeAddrInfoResults(ppResult) : ""}
        };
        LogTelemetry("getaddrinfo", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
static GetAddrInfoW_t pfnGetAddrInfoW = nullptr;
static int WSAAPI Detour_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    HookGuard guard;
    int res = pfnGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pNodeName", "PCWSTR", (uint64_t)pNodeName, {}, WideToUtf8(ReadWStringSafe(pNodeName))},
            {"pServiceName", "PCWSTR", (uint64_t)pServiceName, {}, WideToUtf8(ReadWStringSafe(pServiceName))},
            {"ResolvedAddresses", "ADDRINFOW", (uint64_t)ppResult, {}, res == 0 ? DecodeAddrInfoResults(ppResult) : ""}
        };
        LogTelemetry("GetAddrInfoW", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef int(WSAAPI* getnameinfo_t)(const SOCKADDR*, socklen_t, PCHAR, DWORD, PCHAR, DWORD, INT);
static getnameinfo_t pfngetnameinfo = nullptr;
static int WSAAPI Detour_getnameinfo(const SOCKADDR* address, socklen_t addressLength, PCHAR host, DWORD hostLength, PCHAR service, DWORD serviceLength, INT flags) {
    HookGuard guard;
    int result = pfngetnameinfo(address, addressLength, host, hostLength, service, serviceLength, flags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"address", "SOCKADDR*", (uint64_t)address, ReadBufferSafe(address, addressLength), DecodeSockaddr(address)},
            {"host", "PCHAR", (uint64_t)host, {}, result == 0 ? ReadAStringSafe(host, hostLength) : ""},
            {"service", "PCHAR", (uint64_t)service, {}, result == 0 ? ReadAStringSafe(service, serviceLength) : ""}
        };
        LogTelemetry("getnameinfo", "ws2_32.dll", _ReturnAddress(), (uint64_t)(int64_t)result, params);
    }
    return result;
}

typedef int(WSAAPI* GetNameInfoW_t)(const SOCKADDR*, socklen_t, PWCHAR, DWORD, PWCHAR, DWORD, INT);
static GetNameInfoW_t pfnGetNameInfoW = nullptr;
static int WSAAPI Detour_GetNameInfoW(const SOCKADDR* address, socklen_t addressLength, PWCHAR host, DWORD hostLength, PWCHAR service, DWORD serviceLength, INT flags) {
    HookGuard guard;
    int result = pfnGetNameInfoW(address, addressLength, host, hostLength, service, serviceLength, flags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"address", "SOCKADDR*", (uint64_t)address, ReadBufferSafe(address, addressLength), DecodeSockaddr(address)},
            {"host", "PWCHAR", (uint64_t)host, {}, result == 0 ? WideToUtf8(ReadWStringSafe(host, hostLength)) : ""},
            {"service", "PWCHAR", (uint64_t)service, {}, result == 0 ? WideToUtf8(ReadWStringSafe(service, serviceLength)) : ""}
        };
        LogTelemetry("GetNameInfoW", "ws2_32.dll", _ReturnAddress(), (uint64_t)(int64_t)result, params);
    }
    return result;
}

typedef hostent*(WSAAPI* gethostbyname_t)(const char*);
static gethostbyname_t pfngethostbyname = nullptr;
static hostent* WSAAPI Detour_gethostbyname(const char* name) {
    HookGuard guard;
    hostent* res = pfngethostbyname(name);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"name", "const char*", (uint64_t)name, {}, ReadAStringSafe(name)}
        };
        LogTelemetry("gethostbyname", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef unsigned long(WSAAPI* inet_addr_t)(const char*);
static inet_addr_t pfninet_addr = nullptr;
static unsigned long WSAAPI Detour_inet_addr(const char* cp) {
    HookGuard guard;
    unsigned long res = pfninet_addr(cp);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"cp", "const char*", (uint64_t)cp, {}, ReadAStringSafe(cp)}
        };
        LogTelemetry("inet_addr", "ws2_32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

template <typename T>
static std::string DecodeDnsRecordAddresses(T** records) {
    if (!records) return "";
    T* current = nullptr;
    if (!SafeCopyBuffer(&current, records, sizeof(current))) return "";
    std::ostringstream decoded;
    for (int i = 0; current && i < 64; ++i) {
        T record{};
        if (!SafeCopyBuffer(&record, current, sizeof(record))) break;
        char address[INET6_ADDRSTRLEN] = {};
        bool captured = false;
        if (record.wType == DNS_TYPE_A) {
            IN_ADDR ipv4{};
            ipv4.S_un.S_addr = record.Data.A.IpAddress;
            captured = InetNtopA(AF_INET, &ipv4, address, sizeof(address)) != nullptr;
        } else if (record.wType == DNS_TYPE_AAAA) {
            captured = InetNtopA(AF_INET6, &record.Data.AAAA.Ip6Address, address, sizeof(address)) != nullptr;
        }
        if (captured) {
            if (decoded.tellp() > 0) decoded << "; ";
            decoded << address;
        }
        current = record.pNext;
    }
    return decoded.str();
}

typedef DNS_STATUS(WINAPI* DnsQuery_W_t)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
static DnsQuery_W_t pfnDnsQuery_W = nullptr;
static DNS_STATUS WINAPI Detour_DnsQuery_W(PCWSTR pszName, WORD wType, DWORD options, PVOID pExtra, PDNS_RECORDW* ppQueryResults, PVOID* pReserved) {
    HookGuard guard;
    DNS_STATUS res = pfnDnsQuery_W(pszName, wType, options, pExtra, ppQueryResults, pReserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pszName", "PCWSTR", (uint64_t)pszName, {}, WideToUtf8(ReadWStringSafe(pszName))},
            {"wType", "WORD", (uint64_t)wType, {}, ""},
            {"options", "DWORD", (uint64_t)options, {}, ""},
            {"ResolvedAddresses", "DNS_RECORDW", (uint64_t)ppQueryResults, {}, res == 0 ? DecodeDnsRecordAddresses(ppQueryResults) : ""}
        };
        LogTelemetry("DnsQuery_W", "dnsapi.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DNS_STATUS(WINAPI* DnsQuery_A_t)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORDA*, PVOID*);
static DnsQuery_A_t pfnDnsQuery_A = nullptr;
static DNS_STATUS WINAPI Detour_DnsQuery_A(PCSTR pszName, WORD wType, DWORD options, PVOID pExtra, PDNS_RECORDA* ppQueryResults, PVOID* pReserved) {
    HookGuard guard;
    DNS_STATUS res = pfnDnsQuery_A(pszName, wType, options, pExtra, ppQueryResults, pReserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pszName", "PCSTR", (uint64_t)pszName, {}, ReadAStringSafe(pszName)},
            {"wType", "WORD", (uint64_t)wType, {}, ""},
            {"options", "DWORD", (uint64_t)options, {}, ""},
            {"ResolvedAddresses", "DNS_RECORDA", (uint64_t)ppQueryResults, {}, res == 0 ? DecodeDnsRecordAddresses(ppQueryResults) : ""}
        };
        LogTelemetry("DnsQuery_A", "dnsapi.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// InternetOpenW (wininet.dll)
typedef HINTERNET(WINAPI* InternetOpenW_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
static InternetOpenW_t pfnInternetOpenW = nullptr;
static HINTERNET WINAPI Detour_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
    HookGuard guard;
    HINTERNET res = pfnInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpszAgent", "LPCWSTR", (uint64_t)lpszAgent, {}, WideToUtf8(ReadWStringSafe(lpszAgent))},
            {"dwAccessType", "DWORD", (uint64_t)dwAccessType, {}, ""}
        };
        LogTelemetry("InternetOpenW", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* InternetOpenA_t)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
static InternetOpenA_t pfnInternetOpenA = nullptr;
static HINTERNET WINAPI Detour_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags) {
    HookGuard guard;
    HINTERNET res = pfnInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpszAgent", "LPCSTR", (uint64_t)lpszAgent, {}, ReadAStringSafe(lpszAgent)},
            {"dwAccessType", "DWORD", (uint64_t)dwAccessType, {}, ""}
        };
        LogTelemetry("InternetOpenA", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* InternetConnectW_t)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
static InternetConnectW_t pfnInternetConnectW = nullptr;
static HINTERNET WINAPI Detour_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hInternet", "HINTERNET", (uint64_t)hInternet, {}, ""},
            {"lpszServerName", "LPCWSTR", (uint64_t)lpszServerName, {}, WideToUtf8(ReadWStringSafe(lpszServerName))},
            {"nServerPort", "INTERNET_PORT", (uint64_t)nServerPort, {}, ""},
            {"dwService", "DWORD", (uint64_t)dwService, {}, ""}
        };
        LogTelemetry("InternetConnectW", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* InternetConnectA_t)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
static InternetConnectA_t pfnInternetConnectA = nullptr;
static HINTERNET WINAPI Detour_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hInternet", "HINTERNET", (uint64_t)hInternet, {}, ""},
            {"lpszServerName", "LPCSTR", (uint64_t)lpszServerName, {}, ReadAStringSafe(lpszServerName)},
            {"nServerPort", "INTERNET_PORT", (uint64_t)nServerPort, {}, ""},
            {"dwService", "DWORD", (uint64_t)dwService, {}, ""}
        };
        LogTelemetry("InternetConnectA", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* HttpOpenRequestW_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
static HttpOpenRequestW_t pfnHttpOpenRequestW = nullptr;
static HINTERNET WINAPI Detour_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hConnect", "HINTERNET", (uint64_t)hConnect, {}, ""},
            {"lpszVerb", "LPCWSTR", (uint64_t)lpszVerb, {}, WideToUtf8(ReadWStringSafe(lpszVerb))},
            {"lpszObjectName", "LPCWSTR", (uint64_t)lpszObjectName, {}, WideToUtf8(ReadWStringSafe(lpszObjectName))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("HttpOpenRequestW", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* HttpOpenRequestA_t)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
static HttpOpenRequestA_t pfnHttpOpenRequestA = nullptr;
static HINTERNET WINAPI Detour_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hConnect", "HINTERNET", (uint64_t)hConnect, {}, ""},
            {"lpszVerb", "LPCSTR", (uint64_t)lpszVerb, {}, ReadAStringSafe(lpszVerb)},
            {"lpszObjectName", "LPCSTR", (uint64_t)lpszObjectName, {}, ReadAStringSafe(lpszObjectName)},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("HttpOpenRequestA", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* InternetOpenUrlW_t)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
static InternetOpenUrlW_t pfnInternetOpenUrlW = nullptr;
static HINTERNET WINAPI Detour_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hInternet", "HINTERNET", (uint64_t)hInternet, {}, ""},
            {"lpszUrl", "LPCWSTR", (uint64_t)lpszUrl, {}, WideToUtf8(ReadWStringSafe(lpszUrl))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("InternetOpenUrlW", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* InternetOpenUrlA_t)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
static InternetOpenUrlA_t pfnInternetOpenUrlA = nullptr;
static HINTERNET WINAPI Detour_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    HookGuard guard;
    HINTERNET res = pfnInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hInternet", "HINTERNET", (uint64_t)hInternet, {}, ""},
            {"lpszUrl", "LPCSTR", (uint64_t)lpszUrl, {}, ReadAStringSafe(lpszUrl)},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("InternetOpenUrlA", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* HttpSendRequestW_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
static HttpSendRequestW_t pfnHttpSendRequestW = nullptr;
static BOOL WINAPI Detour_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    HookGuard guard;
    BOOL res = pfnHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""},
            {"lpszHeaders", "LPCWSTR", (uint64_t)lpszHeaders, {}, WideToUtf8(ReadWStringSafe(lpszHeaders))},
            {"lpOptional", "LPVOID", (uint64_t)lpOptional, ReadBufferSafe(lpOptional, dwOptionalLength, 64u * 1024u), ""}
        };
        LogTelemetry("HttpSendRequestW", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* HttpSendRequestA_t)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
static HttpSendRequestA_t pfnHttpSendRequestA = nullptr;
static BOOL WINAPI Detour_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    HookGuard guard;
    BOOL res = pfnHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""},
            {"lpszHeaders", "LPCSTR", (uint64_t)lpszHeaders, {}, ReadAStringSafe(lpszHeaders)},
            {"lpOptional", "LPVOID", (uint64_t)lpOptional, ReadBufferSafe(lpOptional, dwOptionalLength, 64u * 1024u), ""}
        };
        LogTelemetry("HttpSendRequestA", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* InternetReadFile_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
static InternetReadFile_t pfnInternetReadFile = nullptr;
static BOOL WINAPI Detour_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    HookGuard guard;
    BOOL res = pfnInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    if (!guard.WasInside()) {
        DWORD read = (res && lpdwNumberOfBytesRead) ? *lpdwNumberOfBytesRead : 0;
        std::vector<ParameterCapture> params = {
            {"hFile", "HINTERNET", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, read, 64u * 1024u), ""},
            {"dwNumberOfBytesToRead", "DWORD", (uint64_t)dwNumberOfBytesToRead, {}, ""},
            {"dwNumberOfBytesRead", "DWORD", (uint64_t)read, {}, ""}
        };
        LogTelemetry("InternetReadFile", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* InternetWriteFile_t)(HINTERNET, LPCVOID, DWORD, LPDWORD);
static InternetWriteFile_t pfnInternetWriteFile = nullptr;
static BOOL WINAPI Detour_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten) {
    HookGuard guard;
    BOOL res = pfnInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    if (!guard.WasInside()) {
        DWORD written = (res && lpdwNumberOfBytesWritten) ? *lpdwNumberOfBytesWritten : dwNumberOfBytesToWrite;
        std::vector<ParameterCapture> params = {
            {"hFile", "HINTERNET", (uint64_t)hFile, {}, ""},
            {"lpBuffer", "LPCVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, written, 64u * 1024u), ""},
            {"dwNumberOfBytesToWrite", "DWORD", (uint64_t)dwNumberOfBytesToWrite, {}, ""},
            {"dwNumberOfBytesWritten", "DWORD", (uint64_t)written, {}, ""}
        };
        LogTelemetry("InternetWriteFile", "wininet.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* WinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
static WinHttpOpen_t pfnWinHttpOpen = nullptr;
static HINTERNET WINAPI Detour_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) {
    HookGuard guard;
    HINTERNET res = pfnWinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pszAgentW", "LPCWSTR", (uint64_t)pszAgentW, {}, WideToUtf8(ReadWStringSafe(pszAgentW))},
            {"dwAccessType", "DWORD", (uint64_t)dwAccessType, {}, ""}
        };
        LogTelemetry("WinHttpOpen", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* WinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
static WinHttpConnect_t pfnWinHttpConnect = nullptr;
static HINTERNET WINAPI Detour_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    HookGuard guard;
    HINTERNET res = pfnWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSession", "HINTERNET", (uint64_t)hSession, {}, ""},
            {"pswzServerName", "LPCWSTR", (uint64_t)pswzServerName, {}, WideToUtf8(ReadWStringSafe(pswzServerName))},
            {"nServerPort", "INTERNET_PORT", (uint64_t)nServerPort, {}, ""}
        };
        LogTelemetry("WinHttpConnect", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HINTERNET(WINAPI* WinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
static WinHttpOpenRequest_t pfnWinHttpOpenRequest = nullptr;
static HINTERNET WINAPI Detour_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    HookGuard guard;
    HINTERNET res = pfnWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hConnect", "HINTERNET", (uint64_t)hConnect, {}, ""},
            {"pwszVerb", "LPCWSTR", (uint64_t)pwszVerb, {}, WideToUtf8(ReadWStringSafe(pwszVerb))},
            {"pwszObjectName", "LPCWSTR", (uint64_t)pwszObjectName, {}, WideToUtf8(ReadWStringSafe(pwszObjectName))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("WinHttpOpenRequest", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
static WinHttpSendRequest_t pfnWinHttpSendRequest = nullptr;
static BOOL WINAPI Detour_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    HookGuard guard;
    BOOL res = pfnWinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""},
            {"lpszHeaders", "LPCWSTR", (uint64_t)lpszHeaders, {}, WideToUtf8(ReadWStringSafe(lpszHeaders))},
            {"lpOptional", "LPVOID", (uint64_t)lpOptional, ReadBufferSafe(lpOptional, dwOptionalLength, 64u * 1024u), ""},
            {"dwOptionalLength", "DWORD", (uint64_t)dwOptionalLength, {}, ""},
            {"dwTotalLength", "DWORD", (uint64_t)dwTotalLength, {}, ""}
        };
        LogTelemetry("WinHttpSendRequest", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WinHttpReceiveResponse_t)(HINTERNET, LPVOID);
static WinHttpReceiveResponse_t pfnWinHttpReceiveResponse = nullptr;
static BOOL WINAPI Detour_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    HookGuard guard;
    BOOL res = pfnWinHttpReceiveResponse(hRequest, lpReserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""}
        };
        LogTelemetry("WinHttpReceiveResponse", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
static WinHttpReadData_t pfnWinHttpReadData = nullptr;
static BOOL WINAPI Detour_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    HookGuard guard;
    BOOL res = pfnWinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    if (!guard.WasInside()) {
        DWORD read = (res && lpdwNumberOfBytesRead) ? *lpdwNumberOfBytesRead : 0;
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""},
            {"lpBuffer", "LPVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, read, 64u * 1024u), ""},
            {"dwNumberOfBytesRead", "DWORD", (uint64_t)read, {}, ""}
        };
        LogTelemetry("WinHttpReadData", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* WinHttpWriteData_t)(HINTERNET, LPCVOID, DWORD, LPDWORD);
static WinHttpWriteData_t pfnWinHttpWriteData = nullptr;
static BOOL WINAPI Detour_WinHttpWriteData(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten) {
    HookGuard guard;
    BOOL res = pfnWinHttpWriteData(hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    if (!guard.WasInside()) {
        DWORD written = (res && lpdwNumberOfBytesWritten) ? *lpdwNumberOfBytesWritten : dwNumberOfBytesToWrite;
        std::vector<ParameterCapture> params = {
            {"hRequest", "HINTERNET", (uint64_t)hRequest, {}, ""},
            {"lpBuffer", "LPCVOID", (uint64_t)lpBuffer, ReadBufferSafe(lpBuffer, written, 64u * 1024u), ""},
            {"dwNumberOfBytesWritten", "DWORD", (uint64_t)written, {}, ""}
        };
        LogTelemetry("WinHttpWriteData", "winhttp.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CoInitialize_t)(LPVOID);
static CoInitialize_t pfnCoInitialize = nullptr;
static HRESULT WINAPI Detour_CoInitialize(LPVOID pvReserved) {
    HookGuard guard;
    HRESULT res = pfnCoInitialize(pvReserved);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pvReserved", "LPVOID", (uint64_t)pvReserved, {}, ""}
        };
        LogTelemetry("CoInitialize", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CoInitializeEx_t)(LPVOID, DWORD);
static CoInitializeEx_t pfnCoInitializeEx = nullptr;
static HRESULT WINAPI Detour_CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit) {
    HookGuard guard;
    HRESULT res = pfnCoInitializeEx(pvReserved, dwCoInit);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"pvReserved", "LPVOID", (uint64_t)pvReserved, {}, ""},
            {"dwCoInit", "DWORD", (uint64_t)dwCoInit, {}, ""}
        };
        LogTelemetry("CoInitializeEx", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef void(WINAPI* CoUninitialize_t)(void);
static CoUninitialize_t pfnCoUninitialize = nullptr;
static void WINAPI Detour_CoUninitialize(void) {
    HookGuard guard;
    pfnCoUninitialize();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params;
        LogTelemetry("CoUninitialize", "ole32.dll", _ReturnAddress(), 0, params);
    }
}

static std::mutex g_VTableHookMutex;

static void HookVTableIndex(void* interfacePtr, int index, void* detourFunc, void** originalFunc) {
    if (!interfacePtr) return;
    std::lock_guard<std::mutex> lock(g_VTableHookMutex);
    void** vtable = *(void***)interfacePtr;
    if (!vtable) return;
    void* target = vtable[index];
    if (target == detourFunc) return; // Already hooked
    *originalFunc = target;
    DWORD oldProtect = 0;
    if (VirtualProtect(&vtable[index], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        vtable[index] = detourFunc;
        VirtualProtect(&vtable[index], sizeof(void*), oldProtect, &oldProtect);
    }
}

// 1. Task Scheduler Detours
typedef HRESULT(STDMETHODCALLTYPE* RegisterTaskDefinition_t)(void* pThis, BSTR path, void* pDefinition, LONG flags, VARIANT userId, VARIANT password, int logonType, VARIANT sddl, void** ppTask);
static RegisterTaskDefinition_t pfnRegisterTaskDefinition = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_RegisterTaskDefinition(void* pThis, BSTR path, void* pDefinition, LONG flags, VARIANT userId, VARIANT password, int logonType, VARIANT sddl, void** ppTask) {
    HRESULT res = pfnRegisterTaskDefinition(pThis, path, pDefinition, flags, userId, password, logonType, sddl, ppTask);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"path", "BSTR", 0, {}, WideToUtf8(path ? path : L"")},
            {"flags", "LONG", (uint64_t)flags, {}, ""},
            {"logonType", "int", (uint64_t)logonType, {}, ""}
        };
        LogTelemetry("ITaskFolder_RegisterTaskDefinition", "taskschd.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* RegisterTask_t)(void* pThis, BSTR path, BSTR xmlText, LONG flags, VARIANT userId, VARIANT password, int logonType, VARIANT sddl, void** ppTask);
static RegisterTask_t pfnRegisterTask = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_RegisterTask(void* pThis, BSTR path, BSTR xmlText, LONG flags, VARIANT userId, VARIANT password, int logonType, VARIANT sddl, void** ppTask) {
    HRESULT res = pfnRegisterTask(pThis, path, xmlText, flags, userId, password, logonType, sddl, ppTask);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"path", "BSTR", 0, {}, WideToUtf8(path ? path : L"")},
            {"xmlText", "BSTR", 0, {}, WideToUtf8(xmlText ? xmlText : L"")},
            {"flags", "LONG", (uint64_t)flags, {}, ""},
            {"logonType", "int", (uint64_t)logonType, {}, ""}
        };
        LogTelemetry("ITaskFolder_RegisterTask", "taskschd.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* GetFolder_t)(void* pThis, BSTR path, void** ppFolder);
static GetFolder_t pfnGetFolder = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_GetFolder(void* pThis, BSTR path, void** ppFolder); // Forward decl

// 2. WMI Detours
typedef HRESULT(STDMETHODCALLTYPE* ExecQuery_t)(void* pThis, const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags, void* pCtx, void** ppEnum);
static ExecQuery_t pfnExecQuery = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_ExecQuery(void* pThis, const BSTR strQueryLanguage, const BSTR strQuery, LONG lFlags, void* pCtx, void** ppEnum) {
    HRESULT res = pfnExecQuery(pThis, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"QueryLanguage", "BSTR", 0, {}, WideToUtf8(strQueryLanguage ? strQueryLanguage : L"")},
            {"Query", "BSTR", 0, {}, WideToUtf8(strQuery ? strQuery : L"")}
        };
        LogTelemetry("IWbemServices_ExecQuery", "wbemcli.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* ExecMethod_t)(void* pThis, const BSTR strObjectPath, const BSTR strMethodName, LONG lFlags, void* pCtx, void* pInParams, void** ppOutParams, void** ppCallResult);
static ExecMethod_t pfnExecMethod = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_ExecMethod(void* pThis, const BSTR strObjectPath, const BSTR strMethodName, LONG lFlags, void* pCtx, void* pInParams, void** ppOutParams, void** ppCallResult) {
    HRESULT res = pfnExecMethod(pThis, strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ObjectPath", "BSTR", 0, {}, WideToUtf8(strObjectPath ? strObjectPath : L"")},
            {"MethodName", "BSTR", 0, {}, WideToUtf8(strMethodName ? strMethodName : L"")}
        };
        LogTelemetry("IWbemServices_ExecMethod", "wbemcli.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* PutInstance_t)(void* pThis, void* pInst, LONG lFlags, void* pCtx, void** ppCallResult);
static PutInstance_t pfnPutInstance = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_PutInstance(void* pThis, void* pInst, LONG lFlags, void* pCtx, void** ppCallResult) {
    HRESULT res = pfnPutInstance(pThis, pInst, lFlags, pCtx, ppCallResult);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"Flags", "LONG", (uint64_t)lFlags, {}, ""}
        };
        LogTelemetry("IWbemServices_PutInstance", "wbemcli.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* ConnectServer_t)(void* pThis, const BSTR NetworkResource, const BSTR User, const BSTR Password, const BSTR Locale, LONG SecurityFlags, const BSTR Authority, void* pCtx, void** ppNamespace);
static ConnectServer_t pfnConnectServer = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_ConnectServer(void* pThis, const BSTR NetworkResource, const BSTR User, const BSTR Password, const BSTR Locale, LONG SecurityFlags, const BSTR Authority, void* pCtx, void** ppNamespace) {
    HRESULT res = pfnConnectServer(pThis, NetworkResource, User, Password, Locale, SecurityFlags, Authority, pCtx, ppNamespace);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"NetworkResource", "BSTR", 0, {}, WideToUtf8(NetworkResource ? NetworkResource : L"")},
            {"User", "BSTR", 0, {}, WideToUtf8(User ? User : L"")}
        };
        LogTelemetry("IWbemLocator_ConnectServer", "wbemcli.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    if (SUCCEEDED(res) && ppNamespace && *ppNamespace) {
        HookVTableIndex(*ppNamespace, 20, (void*)Detour_ExecQuery, (void**)&pfnExecQuery);
        HookVTableIndex(*ppNamespace, 24, (void*)Detour_ExecMethod, (void**)&pfnExecMethod);
        HookVTableIndex(*ppNamespace, 14, (void*)Detour_PutInstance, (void**)&pfnPutInstance);
    }
    return res;
}

// 3. BITS Detours
typedef HRESULT(STDMETHODCALLTYPE* AddFile_t)(void* pThis, LPCWSTR RemoteUrl, LPCWSTR LocalName);
static AddFile_t pfnAddFile = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_AddFile(void* pThis, LPCWSTR RemoteUrl, LPCWSTR LocalName) {
    HRESULT res = pfnAddFile(pThis, RemoteUrl, LocalName);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"RemoteUrl", "LPCWSTR", 0, {}, WideToUtf8(RemoteUrl ? RemoteUrl : L"")},
            {"LocalName", "LPCWSTR", 0, {}, WideToUtf8(LocalName ? LocalName : L"")}
        };
        LogTelemetry("IBackgroundCopyJob_AddFile", "qmgr.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(STDMETHODCALLTYPE* CreateJob_t)(void* pThis, LPCWSTR DisplayName, int Type, GUID* pJobId, void** ppJob);
static CreateJob_t pfnCreateJob = nullptr;
static HRESULT STDMETHODCALLTYPE Detour_CreateJob(void* pThis, LPCWSTR DisplayName, int Type, GUID* pJobId, void** ppJob) {
    HRESULT res = pfnCreateJob(pThis, DisplayName, Type, pJobId, ppJob);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"DisplayName", "LPCWSTR", 0, {}, WideToUtf8(DisplayName ? DisplayName : L"")},
            {"JobType", "int", (uint64_t)Type, {}, ""}
        };
        LogTelemetry("IBackgroundCopyManager_CreateJob", "qmgr.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    if (SUCCEEDED(res) && ppJob && *ppJob) {
        HookVTableIndex(*ppJob, 3, (void*)Detour_AddFile, (void**)&pfnAddFile);
    }
    return res;
}

// 4. Connect GetFolder Implementation
static HRESULT STDMETHODCALLTYPE Detour_GetFolder(void* pThis, BSTR path, void** ppFolder) {
    HRESULT res = pfnGetFolder(pThis, path, ppFolder);
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"path", "BSTR", 0, {}, WideToUtf8(path ? path : L"")}
        };
        LogTelemetry("ITaskService_GetFolder", "taskschd.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    if (SUCCEEDED(res) && ppFolder && *ppFolder) {
        HookVTableIndex(*ppFolder, 10, (void*)Detour_RegisterTaskDefinition, (void**)&pfnRegisterTaskDefinition);
        HookVTableIndex(*ppFolder, 9, (void*)Detour_RegisterTask, (void**)&pfnRegisterTask);
    }
    return res;
}

// 5. Bootstrap Handler
static void OnCoCreateInstanceSuccess(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv || !*ppv) return;
    std::string clsidLower = GuidToUtf8(rclsid);
    for (char& c : clsidLower) {
        c = (char)tolower(c);
    }
    if (!clsidLower.empty() && clsidLower.front() == '{') clsidLower = clsidLower.substr(1, clsidLower.size() - 2);

    if (clsidLower == "0f87369f-a4e5-4cfc-bd3e-73e6154572dd") {
        HookVTableIndex(*ppv, 8, (void*)Detour_GetFolder, (void**)&pfnGetFolder);
    }
    else if (clsidLower == "4590f811-1d3a-11d0-891f-00aa004b2e24") {
        HookVTableIndex(*ppv, 3, (void*)Detour_ConnectServer, (void**)&pfnConnectServer);
    }
    else if (clsidLower == "4991d34b-80a1-4291-83b6-3328366b9097") {
        HookVTableIndex(*ppv, 3, (void*)Detour_CreateJob, (void**)&pfnCreateJob);
    }
}

typedef HRESULT(WINAPI* CoCreateInstance_t)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
static CoCreateInstance_t pfnCoCreateInstance = nullptr;
static HRESULT WINAPI Detour_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv) {
    HookGuard guard;
    HRESULT res = pfnCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    if (SUCCEEDED(res) && ppv && *ppv) {
        OnCoCreateInstanceSuccess(rclsid, riid, ppv);
    }
    if (!guard.WasInside()) {
        uint64_t objectPtr = 0;
        if (ppv) SafeCopyBuffer(&objectPtr, ppv, sizeof(objectPtr));
        std::vector<ParameterCapture> params = {
            {"rclsid", "REFCLSID", (uint64_t)&rclsid, {}, GuidToUtf8(rclsid)},
            {"pUnkOuter", "LPUNKNOWN", (uint64_t)pUnkOuter, {}, ""},
            {"dwClsContext", "DWORD", (uint64_t)dwClsContext, {}, ""},
            {"riid", "REFIID", (uint64_t)&riid, {}, GuidToUtf8(riid)},
            {"ppv", "LPVOID*", (uint64_t)ppv, {}, objectPtr ? GuidToUtf8(riid) : ""},
            {"object", "LPVOID", objectPtr, {}, ""}
        };
        LogTelemetry("CoCreateInstance", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CoCreateInstanceEx_t)(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
static CoCreateInstanceEx_t pfnCoCreateInstanceEx = nullptr;
static HRESULT WINAPI Detour_CoCreateInstanceEx(REFCLSID Clsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults) {
    HookGuard guard;
    HRESULT res = pfnCoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);
    if (SUCCEEDED(res) && pResults && dwCount > 0) {
        for (DWORD j = 0; j < dwCount; ++j) {
            MULTI_QI qi = {};
            if (SafeCopyBuffer(&qi, pResults + j, sizeof(qi))) {
                if (SUCCEEDED(qi.hr) && qi.pItf && qi.pIID) {
                    OnCoCreateInstanceSuccess(Clsid, *qi.pIID, (LPVOID*)&(pResults[j].pItf));
                }
            }
        }
    }
    if (!guard.WasInside()) {
        std::string firstIid;
        uint64_t firstObject = 0;
        if (pResults && dwCount > 0) {
            MULTI_QI first = {};
            if (SafeCopyBuffer(&first, pResults, sizeof(first))) {
                firstIid = GuidPtrToUtf8(first.pIID);
                firstObject = (uint64_t)first.pItf;
            }
        }
        std::vector<ParameterCapture> params = {
            {"Clsid", "REFCLSID", (uint64_t)&Clsid, {}, GuidToUtf8(Clsid)},
            {"punkOuter", "IUnknown*", (uint64_t)punkOuter, {}, ""},
            {"dwClsCtx", "DWORD", (uint64_t)dwClsCtx, {}, ""},
            {"pServerInfo", "COSERVERINFO*", (uint64_t)pServerInfo, {}, ""},
            {"dwCount", "DWORD", (uint64_t)dwCount, {}, ""},
            {"firstIID", "IID", 0, {}, firstIid},
            {"firstObject", "IUnknown*", firstObject, {}, ""}
        };
        LogTelemetry("CoCreateInstanceEx", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CoGetClassObject_t)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);
static CoGetClassObject_t pfnCoGetClassObject = nullptr;
static HRESULT WINAPI Detour_CoGetClassObject(REFCLSID rclsid, DWORD dwClsContext, LPVOID pvReserved, REFIID riid, LPVOID* ppv) {
    HookGuard guard;
    HRESULT res = pfnCoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv);
    if (!guard.WasInside()) {
        uint64_t objectPtr = 0;
        if (ppv) SafeCopyBuffer(&objectPtr, ppv, sizeof(objectPtr));
        std::vector<ParameterCapture> params = {
            {"rclsid", "REFCLSID", (uint64_t)&rclsid, {}, GuidToUtf8(rclsid)},
            {"dwClsContext", "DWORD", (uint64_t)dwClsContext, {}, ""},
            {"pvReserved", "LPVOID", (uint64_t)pvReserved, {}, ""},
            {"riid", "REFIID", (uint64_t)&riid, {}, GuidToUtf8(riid)},
            {"object", "LPVOID", objectPtr, {}, ""}
        };
        LogTelemetry("CoGetClassObject", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CLSIDFromString_t)(LPCOLESTR, LPCLSID);
static CLSIDFromString_t pfnCLSIDFromString = nullptr;
static HRESULT WINAPI Detour_CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid) {
    HookGuard guard;
    HRESULT res = pfnCLSIDFromString(lpsz, pclsid);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpsz", "LPCOLESTR", (uint64_t)lpsz, {}, WideToUtf8(ReadWStringSafe(lpsz))},
            {"pclsid", "LPCLSID", (uint64_t)pclsid, {}, SUCCEEDED(res) ? GuidPtrToUtf8(pclsid) : ""}
        };
        LogTelemetry("CLSIDFromString", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HRESULT(WINAPI* CLSIDFromProgID_t)(LPCOLESTR, LPCLSID);
static CLSIDFromProgID_t pfnCLSIDFromProgID = nullptr;
static HRESULT WINAPI Detour_CLSIDFromProgID(LPCOLESTR lpszProgID, LPCLSID lpclsid) {
    HookGuard guard;
    HRESULT res = pfnCLSIDFromProgID(lpszProgID, lpclsid);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpszProgID", "LPCOLESTR", (uint64_t)lpszProgID, {}, WideToUtf8(ReadWStringSafe(lpszProgID))},
            {"lpclsid", "LPCLSID", (uint64_t)lpclsid, {}, SUCCEEDED(res) ? GuidPtrToUtf8(lpclsid) : ""}
        };
        LogTelemetry("CLSIDFromProgID", "ole32.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* OpenSCManagerW_t)(LPCWSTR, LPCWSTR, DWORD);
static OpenSCManagerW_t pfnOpenSCManagerW = nullptr;
static SC_HANDLE WINAPI Detour_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
    HookGuard guard;
    SC_HANDLE res = pfnOpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpMachineName", "LPCWSTR", (uint64_t)lpMachineName, {}, WideToUtf8(ReadWStringSafe(lpMachineName))},
            {"lpDatabaseName", "LPCWSTR", (uint64_t)lpDatabaseName, {}, WideToUtf8(ReadWStringSafe(lpDatabaseName))},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""}
        };
        LogTelemetry("OpenSCManagerW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* OpenSCManagerA_t)(LPCSTR, LPCSTR, DWORD);
static OpenSCManagerA_t pfnOpenSCManagerA = nullptr;
static SC_HANDLE WINAPI Detour_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess) {
    HookGuard guard;
    SC_HANDLE res = pfnOpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpMachineName", "LPCSTR", (uint64_t)lpMachineName, {}, ReadAStringSafe(lpMachineName)},
            {"lpDatabaseName", "LPCSTR", (uint64_t)lpDatabaseName, {}, ReadAStringSafe(lpDatabaseName)},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""}
        };
        LogTelemetry("OpenSCManagerA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* OpenServiceW_t)(SC_HANDLE, LPCWSTR, DWORD);
static OpenServiceW_t pfnOpenServiceW = nullptr;
static SC_HANDLE WINAPI Detour_OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) {
    HookGuard guard;
    SC_HANDLE res = pfnOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSCManager", "SC_HANDLE", (uint64_t)hSCManager, {}, ""},
            {"lpServiceName", "LPCWSTR", (uint64_t)lpServiceName, {}, WideToUtf8(ReadWStringSafe(lpServiceName))},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""}
        };
        LogTelemetry("OpenServiceW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* OpenServiceA_t)(SC_HANDLE, LPCSTR, DWORD);
static OpenServiceA_t pfnOpenServiceA = nullptr;
static SC_HANDLE WINAPI Detour_OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess) {
    HookGuard guard;
    SC_HANDLE res = pfnOpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSCManager", "SC_HANDLE", (uint64_t)hSCManager, {}, ""},
            {"lpServiceName", "LPCSTR", (uint64_t)lpServiceName, {}, ReadAStringSafe(lpServiceName)},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""}
        };
        LogTelemetry("OpenServiceA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* CreateServiceW_t)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
static CreateServiceW_t pfnCreateServiceW = nullptr;
static SC_HANDLE WINAPI Detour_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
    HookGuard guard;
    SC_HANDLE res = pfnCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSCManager", "SC_HANDLE", (uint64_t)hSCManager, {}, ""},
            {"lpServiceName", "LPCWSTR", (uint64_t)lpServiceName, {}, WideToUtf8(ReadWStringSafe(lpServiceName))},
            {"lpDisplayName", "LPCWSTR", (uint64_t)lpDisplayName, {}, WideToUtf8(ReadWStringSafe(lpDisplayName))},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwServiceType", "DWORD", (uint64_t)dwServiceType, {}, ""},
            {"dwStartType", "DWORD", (uint64_t)dwStartType, {}, ""},
            {"dwErrorControl", "DWORD", (uint64_t)dwErrorControl, {}, ""},
            {"lpBinaryPathName", "LPCWSTR", (uint64_t)lpBinaryPathName, {}, WideToUtf8(ReadWStringSafe(lpBinaryPathName))},
            {"lpServiceStartName", "LPCWSTR", (uint64_t)lpServiceStartName, {}, WideToUtf8(ReadWStringSafe(lpServiceStartName))}
        };
        LogTelemetry("CreateServiceW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef SC_HANDLE(WINAPI* CreateServiceA_t)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
static CreateServiceA_t pfnCreateServiceA = nullptr;
static SC_HANDLE WINAPI Detour_CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword) {
    HookGuard guard;
    SC_HANDLE res = pfnCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSCManager", "SC_HANDLE", (uint64_t)hSCManager, {}, ""},
            {"lpServiceName", "LPCSTR", (uint64_t)lpServiceName, {}, ReadAStringSafe(lpServiceName)},
            {"lpDisplayName", "LPCSTR", (uint64_t)lpDisplayName, {}, ReadAStringSafe(lpDisplayName)},
            {"dwDesiredAccess", "DWORD", (uint64_t)dwDesiredAccess, {}, ""},
            {"dwServiceType", "DWORD", (uint64_t)dwServiceType, {}, ""},
            {"dwStartType", "DWORD", (uint64_t)dwStartType, {}, ""},
            {"dwErrorControl", "DWORD", (uint64_t)dwErrorControl, {}, ""},
            {"lpBinaryPathName", "LPCSTR", (uint64_t)lpBinaryPathName, {}, ReadAStringSafe(lpBinaryPathName)},
            {"lpServiceStartName", "LPCSTR", (uint64_t)lpServiceStartName, {}, ReadAStringSafe(lpServiceStartName)}
        };
        LogTelemetry("CreateServiceA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ChangeServiceConfigW_t)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
static ChangeServiceConfigW_t pfnChangeServiceConfigW = nullptr;
static BOOL WINAPI Detour_ChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName) {
    HookGuard guard;
    BOOL res = pfnChangeServiceConfigW(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwServiceType", "DWORD", (uint64_t)dwServiceType, {}, ""},
            {"dwStartType", "DWORD", (uint64_t)dwStartType, {}, ""},
            {"dwErrorControl", "DWORD", (uint64_t)dwErrorControl, {}, ""},
            {"lpBinaryPathName", "LPCWSTR", (uint64_t)lpBinaryPathName, {}, WideToUtf8(ReadWStringSafe(lpBinaryPathName))},
            {"lpDisplayName", "LPCWSTR", (uint64_t)lpDisplayName, {}, WideToUtf8(ReadWStringSafe(lpDisplayName))}
        };
        LogTelemetry("ChangeServiceConfigW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ChangeServiceConfigA_t)(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
static ChangeServiceConfigA_t pfnChangeServiceConfigA = nullptr;
static BOOL WINAPI Detour_ChangeServiceConfigA(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword, LPCSTR lpDisplayName) {
    HookGuard guard;
    BOOL res = pfnChangeServiceConfigA(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwServiceType", "DWORD", (uint64_t)dwServiceType, {}, ""},
            {"dwStartType", "DWORD", (uint64_t)dwStartType, {}, ""},
            {"dwErrorControl", "DWORD", (uint64_t)dwErrorControl, {}, ""},
            {"lpBinaryPathName", "LPCSTR", (uint64_t)lpBinaryPathName, {}, ReadAStringSafe(lpBinaryPathName)},
            {"lpDisplayName", "LPCSTR", (uint64_t)lpDisplayName, {}, ReadAStringSafe(lpDisplayName)}
        };
        LogTelemetry("ChangeServiceConfigA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ChangeServiceConfig2W_t)(SC_HANDLE, DWORD, LPVOID);
static ChangeServiceConfig2W_t pfnChangeServiceConfig2W = nullptr;
static BOOL WINAPI Detour_ChangeServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo) {
    HookGuard guard;
    BOOL res = pfnChangeServiceConfig2W(hService, dwInfoLevel, lpInfo);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwInfoLevel", "DWORD", (uint64_t)dwInfoLevel, {}, ""},
            {"lpInfo", "LPVOID", (uint64_t)lpInfo, ReadBufferSafe(lpInfo, 64), ""}
        };
        LogTelemetry("ChangeServiceConfig2W", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ChangeServiceConfig2A_t)(SC_HANDLE, DWORD, LPVOID);
static ChangeServiceConfig2A_t pfnChangeServiceConfig2A = nullptr;
static BOOL WINAPI Detour_ChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo) {
    HookGuard guard;
    BOOL res = pfnChangeServiceConfig2A(hService, dwInfoLevel, lpInfo);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwInfoLevel", "DWORD", (uint64_t)dwInfoLevel, {}, ""},
            {"lpInfo", "LPVOID", (uint64_t)lpInfo, ReadBufferSafe(lpInfo, 64), ""}
        };
        LogTelemetry("ChangeServiceConfig2A", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* StartServiceW_t)(SC_HANDLE, DWORD, LPCWSTR*);
static StartServiceW_t pfnStartServiceW = nullptr;
static BOOL WINAPI Detour_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    HookGuard guard;
    BOOL res = pfnStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwNumServiceArgs", "DWORD", (uint64_t)dwNumServiceArgs, {}, ""},
            {"lpServiceArgVectors", "LPCWSTR*", (uint64_t)lpServiceArgVectors, {}, ""}
        };
        LogTelemetry("StartServiceW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* StartServiceA_t)(SC_HANDLE, DWORD, LPCSTR*);
static StartServiceA_t pfnStartServiceA = nullptr;
static BOOL WINAPI Detour_StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors) {
    HookGuard guard;
    BOOL res = pfnStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwNumServiceArgs", "DWORD", (uint64_t)dwNumServiceArgs, {}, ""},
            {"lpServiceArgVectors", "LPCSTR*", (uint64_t)lpServiceArgVectors, {}, ""}
        };
        LogTelemetry("StartServiceA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* ControlService_t)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
static ControlService_t pfnControlService = nullptr;
static BOOL WINAPI Detour_ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
    HookGuard guard;
    BOOL res = pfnControlService(hService, dwControl, lpServiceStatus);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""},
            {"dwControl", "DWORD", (uint64_t)dwControl, {}, ""},
            {"lpServiceStatus", "LPSERVICE_STATUS", (uint64_t)lpServiceStatus, ReadBufferSafe(lpServiceStatus, sizeof(SERVICE_STATUS)), ""}
        };
        LogTelemetry("ControlService", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* DeleteService_t)(SC_HANDLE);
static DeleteService_t pfnDeleteService = nullptr;
static BOOL WINAPI Detour_DeleteService(SC_HANDLE hService) {
    HookGuard guard;
    BOOL res = pfnDeleteService(hService);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hService", "SC_HANDLE", (uint64_t)hService, {}, ""}
        };
        LogTelemetry("DeleteService", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CloseServiceHandle_t)(SC_HANDLE);
static CloseServiceHandle_t pfnCloseServiceHandle = nullptr;
static BOOL WINAPI Detour_CloseServiceHandle(SC_HANDLE hSCObject) {
    HookGuard guard;
    BOOL res = pfnCloseServiceHandle(hSCObject);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hSCObject", "SC_HANDLE", (uint64_t)hSCObject, {}, ""}
        };
        LogTelemetry("CloseServiceHandle", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

static std::wstring GetHandleNameSafe(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) return L"";

    DWORD fileType = GetFileType(handle);
    if (fileType == FILE_TYPE_PIPE) {
        return L"";
    }

    wchar_t pathBuf[MAX_PATH * 2] = {};
    DWORD len = GetFinalPathNameByHandleW(handle, pathBuf, static_cast<DWORD>(_countof(pathBuf)), 0);
    if (len > 0 && len < _countof(pathBuf)) {
        return std::wstring(pathBuf);
    }

    typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, int, PVOID, ULONG, PULONG);
    static NtQueryObject_t pfnNtQueryObject = nullptr;
    if (!pfnNtQueryObject) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pfnNtQueryObject = (NtQueryObject_t)GetProcAddress(hNtdll, "NtQueryObject");
        }
    }

    if (pfnNtQueryObject) {
        std::vector<uint8_t> buffer(4096);
        ULONG returnLength = 0;
        NTSTATUS status = pfnNtQueryObject(handle, 1, buffer.data(), static_cast<ULONG>(buffer.size()), &returnLength);
        if (status == 0) {
            NativeUnicodeString* nameInfo = reinterpret_cast<NativeUnicodeString*>(buffer.data());
            if (nameInfo->Buffer && nameInfo->Length > 0) {
                return std::wstring(nameInfo->Buffer, nameInfo->Length / sizeof(wchar_t));
            }
        }
    }

    return L"";
}

typedef BOOL(WINAPI* DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static DeviceIoControl_t pfnDeviceIoControl = nullptr;
static BOOL WINAPI Detour_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    BOOL res = pfnDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
    DWORD error = res ? ERROR_SUCCESS : GetLastError();
    if (!guard.WasInside()) {
        DWORD bytesReturned = 0; if (res && lpBytesReturned) SafeCopyBuffer(&bytesReturned, lpBytesReturned, sizeof(bytesReturned));
        std::vector<ParameterCapture> params = {
            {"hDevice", "HANDLE", (uint64_t)hDevice, {}, ""},
            {"DevicePath", "LPWSTR", 0, {}, WideToUtf8(GetHandleNameSafe(hDevice))},
            {"dwIoControlCode", "DWORD", (uint64_t)dwIoControlCode, {}, ""},
            {"lpInBuffer", "LPVOID", (uint64_t)lpInBuffer, ReadBufferSafe(lpInBuffer, nInBufferSize, kMaximumMemoryBufferCapture), ""},
            {"nInBufferSize", "DWORD", (uint64_t)nInBufferSize, {}, ""},
            {"lpOutBuffer", "LPVOID", (uint64_t)lpOutBuffer, ReadBufferSafe(lpOutBuffer, bytesReturned, kMaximumMemoryBufferCapture), ""},
            {"nOutBufferSize", "DWORD", (uint64_t)nOutBufferSize, {}, ""},
            {"lpBytesReturned", "DWORD", (uint64_t)bytesReturned, {}, ""}, {"LastError", "DWORD", error, {}, ""},
            {"Asynchronous", "BOOL", lpOverlapped ? 1ull : 0ull, {}, ""}
        };
        LogTelemetry("DeviceIoControl", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    if (!res) SetLastError(error); return res;
}

typedef NTSTATUS(WINAPI* NtLoadDriver_t)(NativeUnicodeString*);
static NtLoadDriver_t pfnNtLoadDriver = nullptr;
static NTSTATUS WINAPI Detour_NtLoadDriver(NativeUnicodeString* DriverServiceName) {
    HookGuard guard;
    NTSTATUS res = pfnNtLoadDriver(DriverServiceName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"DriverServiceName", "UNICODE_STRING", (uint64_t)DriverServiceName, {}, ReadNativeUnicodeStringSafe(DriverServiceName)}
        };
        LogTelemetry("NtLoadDriver", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtUnloadDriver_t)(NativeUnicodeString*);
static NtUnloadDriver_t pfnNtUnloadDriver = nullptr;
static NTSTATUS WINAPI Detour_NtUnloadDriver(NativeUnicodeString* DriverServiceName) {
    HookGuard guard;
    NTSTATUS res = pfnNtUnloadDriver(DriverServiceName);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"DriverServiceName", "UNICODE_STRING", (uint64_t)DriverServiceName, {}, ReadNativeUnicodeStringSafe(DriverServiceName)}
        };
        LogTelemetry("NtUnloadDriver", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtDeviceIoControlFile_t)(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
static NtDeviceIoControlFile_t pfnNtDeviceIoControlFile = nullptr;
static NTSTATUS WINAPI Detour_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"FileHandle", "HANDLE", (uint64_t)FileHandle, {}, ""},
            {"DevicePath", "LPWSTR", 0, {}, WideToUtf8(GetHandleNameSafe(FileHandle))},
            {"IoControlCode", "ULONG", (uint64_t)IoControlCode, {}, ""},
            {"InputBuffer", "PVOID", (uint64_t)InputBuffer, ReadBufferSafe(InputBuffer, InputBufferLength, kMaximumMemoryBufferCapture), ""},
            {"InputBufferLength", "ULONG", (uint64_t)InputBufferLength, {}, ""},
            {"OutputBuffer", "PVOID", (uint64_t)OutputBuffer, ReadBufferSafe(OutputBuffer, res >= 0 ? OutputBufferLength : 0, kMaximumMemoryBufferCapture), ""},
            {"OutputBufferLength", "ULONG", (uint64_t)OutputBufferLength, {}, ""}, {"Asynchronous", "BOOL", (Event || ApcRoutine) ? 1ull : 0ull, {}, ""}
        };
        LogTelemetry("NtDeviceIoControlFile", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* TerminateProcess_t)(HANDLE, UINT);
static TerminateProcess_t pfnTerminateProcess = nullptr;
static BOOL WINAPI Detour_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    HookGuard guard;
    DWORD targetPid = hProcess ? GetProcessId(hProcess) : 0;
    bool terminatesSelf = targetPid != 0 && targetPid == GetCurrentProcessId();
    if (!guard.WasInside() && terminatesSelf) {
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)targetPid, {}, ""},
            {"uExitCode", "UINT", (uint64_t)uExitCode, {}, ""}
        };
        LogTelemetry("TerminateProcess", "kernel32.dll", _ReturnAddress(), 1, params);
    }
    BOOL res = pfnTerminateProcess(hProcess, uExitCode);
    if (!guard.WasInside() && !terminatesSelf) {
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)targetPid, {}, ""},
            {"uExitCode", "UINT", (uint64_t)uExitCode, {}, ""}
        };
        LogTelemetry("TerminateProcess", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef VOID(WINAPI* ExitProcess_t)(UINT);
static ExitProcess_t pfnExitProcess = nullptr;
static VOID WINAPI Detour_ExitProcess(UINT uExitCode) {
    HookGuard guard;
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwProcessId", "DWORD", (uint64_t)GetCurrentProcessId(), {}, ""},
            {"uExitCode", "UINT", (uint64_t)uExitCode, {}, ""}
        };
        LogTelemetry("ExitProcess", "kernel32.dll", _ReturnAddress(), 1, params);
    }
    pfnExitProcess(uExitCode);
}

typedef BOOL(WINAPI* QueryFullProcessImageNameW_t)(HANDLE, DWORD, LPWSTR, PDWORD);
static QueryFullProcessImageNameW_t pfnQueryFullProcessImageNameW = nullptr;
static BOOL WINAPI Detour_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) {
    HookGuard guard;
    BOOL res = pfnQueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
    if (!guard.WasInside()) {
        DWORD length = 0;
        if (lpdwSize) SafeCopyBuffer(&length, lpdwSize, sizeof(length));
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(hProcess ? GetProcessId(hProcess) : 0), {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"lpExeName", "LPWSTR", (uint64_t)lpExeName, {}, res ? WideToUtf8(ReadWStringSafe(lpExeName, length + 1)) : ""}
        };
        LogTelemetry("QueryFullProcessImageNameW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* QueryFullProcessImageNameA_t)(HANDLE, DWORD, LPSTR, PDWORD);
static QueryFullProcessImageNameA_t pfnQueryFullProcessImageNameA = nullptr;
static BOOL WINAPI Detour_QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize) {
    HookGuard guard;
    BOOL res = pfnQueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, lpdwSize);
    if (!guard.WasInside()) {
        DWORD length = 0;
        if (lpdwSize) SafeCopyBuffer(&length, lpdwSize, sizeof(length));
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(hProcess ? GetProcessId(hProcess) : 0), {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"lpExeName", "LPSTR", (uint64_t)lpExeName, {}, res ? ReadAStringSafe(lpExeName, length + 1) : ""}
        };
        LogTelemetry("QueryFullProcessImageNameA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetProcessId_t)(HANDLE);
static GetProcessId_t pfnGetProcessId = nullptr;
static DWORD WINAPI Detour_GetProcessId(HANDLE Process) {
    HookGuard guard;
    DWORD res = pfnGetProcessId(Process);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)Process, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)res, {}, ""}
        };
        LogTelemetry("GetProcessId", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);
static std::string DescribeSidSafe(PSID sid, DWORD* finalRid = nullptr) {
    if (!sid) return "";
    SID_IDENTIFIER_AUTHORITY authority = {};
    BYTE revision = 0;
    BYTE count = 0;
    if (!SafeCopyBuffer(&revision, sid, sizeof(revision)) ||
        !SafeCopyBuffer(&count, reinterpret_cast<const BYTE*>(sid) + 1, sizeof(count)) ||
        !SafeCopyBuffer(&authority, reinterpret_cast<const BYTE*>(sid) + 2, sizeof(authority)) || count > 15) {
        return "";
    }
    uint64_t authorityValue = 0;
    for (BYTE byte : authority.Value) authorityValue = (authorityValue << 8) | byte;
    std::ostringstream text;
    text << "S-" << static_cast<unsigned int>(revision) << "-" << authorityValue;
    for (BYTE i = 0; i < count; ++i) {
        DWORD subAuthority = 0;
        if (!SafeCopyBuffer(&subAuthority, reinterpret_cast<const BYTE*>(sid) + 8 + i * sizeof(DWORD), sizeof(subAuthority))) return "";
        text << "-" << subAuthority;
        if (finalRid && i + 1 == count) *finalRid = subAuthority;
    }
    return text.str();
}

static OpenProcessToken_t pfnOpenProcessToken = nullptr;
static BOOL WINAPI Detour_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    HookGuard guard;
    BOOL res = pfnOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    HANDLE token = nullptr;
    if (res && TokenHandle) SafeCopyBuffer(&token, TokenHandle, sizeof(token));
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ProcessHandle", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(ProcessHandle ? GetProcessId(ProcessHandle) : 0), {}, ""},
            {"DesiredAccess", "DWORD", (uint64_t)DesiredAccess, {}, ""},
            {"TokenHandle", "HANDLE", (uint64_t)token, {}, ""}
        };
        LogTelemetry("OpenProcessToken", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetTokenInformation_t)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
static GetTokenInformation_t pfnGetTokenInformation = nullptr;
static BOOL WINAPI Detour_GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength) {
    HookGuard guard;
    BOOL res = pfnGetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
    DWORD returned = 0;
    if (ReturnLength) SafeCopyBuffer(&returned, ReturnLength, sizeof(returned));
    if (!guard.WasInside()) {
        std::string summary;
        if (res && TokenInformation) {
            if (TokenInformationClass == TokenElevation && TokenInformationLength >= sizeof(TOKEN_ELEVATION)) {
                TOKEN_ELEVATION elevation = {};
                if (SafeCopyBuffer(&elevation, TokenInformation, sizeof(elevation))) {
                    summary = std::string("Elevated=") + (elevation.TokenIsElevated ? "true" : "false");
                }
            } else if (TokenInformationClass == TokenSessionId && TokenInformationLength >= sizeof(DWORD)) {
                DWORD sessionId = 0;
                if (SafeCopyBuffer(&sessionId, TokenInformation, sizeof(sessionId))) summary = "SessionId=" + std::to_string(sessionId);
            } else if (TokenInformationClass == TokenType && TokenInformationLength >= sizeof(TOKEN_TYPE)) {
                TOKEN_TYPE tokenType = TokenPrimary;
                if (SafeCopyBuffer(&tokenType, TokenInformation, sizeof(tokenType))) {
                    summary = tokenType == TokenPrimary ? "Type=Primary" : "Type=Impersonation";
                }
            } else if (TokenInformationClass == TokenPrivileges && TokenInformationLength >= sizeof(DWORD)) {
                DWORD privilegeCount = 0;
                if (SafeCopyBuffer(&privilegeCount, TokenInformation, sizeof(privilegeCount))) {
                    summary = "Privileges=";
                    DWORD limit = (std::min)(privilegeCount, static_cast<DWORD>(64));
                    for (DWORD i = 0; i < limit; ++i) {
                        LUID_AND_ATTRIBUTES privilege = {};
                        const BYTE* item = reinterpret_cast<const BYTE*>(TokenInformation) + sizeof(DWORD) + i * sizeof(LUID_AND_ATTRIBUTES);
                        if (!SafeCopyBuffer(&privilege, item, sizeof(privilege))) break;
                        wchar_t privilegeName[128] = {};
                        DWORD nameLength = 128;
                        std::string name;
                        if (LookupPrivilegeNameW(nullptr, &privilege.Luid, privilegeName, &nameLength)) {
                            name = WideToUtf8(std::wstring(privilegeName, nameLength));
                        } else {
                            name = "LUID(" + std::to_string(privilege.Luid.HighPart) + ":" + std::to_string(privilege.Luid.LowPart) + ")";
                        }
                        if (i) summary += ", ";
                        summary += name;
                        if (privilege.Attributes & SE_PRIVILEGE_ENABLED) summary += "[enabled]";
                    }
                    if (privilegeCount > limit) summary += ", ...";
                }
            } else if (TokenInformationClass == TokenUser && TokenInformationLength >= sizeof(TOKEN_USER)) {
                TOKEN_USER tokenUser = {};
                if (SafeCopyBuffer(&tokenUser, TokenInformation, sizeof(tokenUser))) {
                    summary = "UserSid=" + DescribeSidSafe(tokenUser.User.Sid);
                }
            } else if (TokenInformationClass == TokenIntegrityLevel && TokenInformationLength >= sizeof(TOKEN_MANDATORY_LABEL)) {
                TOKEN_MANDATORY_LABEL label = {};
                if (SafeCopyBuffer(&label, TokenInformation, sizeof(label))) {
                    DWORD integrityRid = 0;
                    std::string sid = DescribeSidSafe(label.Label.Sid, &integrityRid);
                    const char* level = integrityRid >= SECURITY_MANDATORY_SYSTEM_RID ? "System" :
                        (integrityRid >= SECURITY_MANDATORY_HIGH_RID ? "High" :
                        (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID ? "Medium" : "Low"));
                    summary = std::string("Integrity=") + level + " SID=" + sid;
                }
            } else if (TokenInformationClass == TokenOwner && TokenInformationLength >= sizeof(TOKEN_OWNER)) {
                TOKEN_OWNER owner = {};
                if (SafeCopyBuffer(&owner, TokenInformation, sizeof(owner))) {
                    summary = "OwnerSid=" + DescribeSidSafe(owner.Owner);
                }
            } else if (TokenInformationClass == TokenStatistics && TokenInformationLength >= sizeof(TOKEN_STATISTICS)) {
                TOKEN_STATISTICS statistics = {};
                if (SafeCopyBuffer(&statistics, TokenInformation, sizeof(statistics))) {
                    summary = "PrivilegeCount=" + std::to_string(statistics.PrivilegeCount) +
                        " GroupCount=" + std::to_string(statistics.GroupCount);
                }
            }
        }
        std::vector<ParameterCapture> params = {
            {"TokenHandle", "HANDLE", (uint64_t)TokenHandle, {}, ""},
            {"TokenInformationClass", "DWORD", (uint64_t)TokenInformationClass, {}, ""},
            {"TokenInformation", "LPVOID", (uint64_t)TokenInformation, ReadBufferSafe(TokenInformation, res ? (std::min)(TokenInformationLength, returned) : 0, 512), ""},
            {"TokenSummary", "STRING", 0, {}, summary},
            {"ReturnLength", "DWORD", (uint64_t)returned, {}, ""}
        };
        LogTelemetry("GetTokenInformation", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* AdjustTokenPrivileges_t)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
static AdjustTokenPrivileges_t pfnAdjustTokenPrivileges = nullptr;
static BOOL WINAPI Detour_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    HookGuard guard;
    BOOL res = pfnAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"TokenHandle", "HANDLE", (uint64_t)TokenHandle, {}, ""},
            {"DisableAllPrivileges", "BOOL", (uint64_t)DisableAllPrivileges, {}, DisableAllPrivileges ? "true" : "false"},
            {"NewState", "PTOKEN_PRIVILEGES", (uint64_t)NewState, ReadBufferSafe(NewState, BufferLength, 512), ""}
        };
        LogTelemetry("AdjustTokenPrivileges", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetEnvironmentVariableW_t)(LPCWSTR, LPWSTR, DWORD);
static GetEnvironmentVariableW_t pfnGetEnvironmentVariableW = nullptr;
static DWORD WINAPI Detour_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnGetEnvironmentVariableW(lpName, lpBuffer, nSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))},
            {"lpValue", "LPWSTR", (uint64_t)lpBuffer, {}, (res && res < nSize) ? WideToUtf8(ReadWStringSafe(lpBuffer, res + 1)) : ""},
            {"nSize", "DWORD", (uint64_t)nSize, {}, ""}
        };
        LogTelemetry("GetEnvironmentVariableW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetEnvironmentVariableA_t)(LPCSTR, LPSTR, DWORD);
static GetEnvironmentVariableA_t pfnGetEnvironmentVariableA = nullptr;
static DWORD WINAPI Detour_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnGetEnvironmentVariableA(lpName, lpBuffer, nSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)},
            {"lpValue", "LPSTR", (uint64_t)lpBuffer, {}, (res && res < nSize) ? ReadAStringSafe(lpBuffer, res + 1) : ""},
            {"nSize", "DWORD", (uint64_t)nSize, {}, ""}
        };
        LogTelemetry("GetEnvironmentVariableA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetEnvironmentVariableW_t)(LPCWSTR, LPCWSTR);
static SetEnvironmentVariableW_t pfnSetEnvironmentVariableW = nullptr;
static BOOL WINAPI Detour_SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
    HookGuard guard;
    BOOL res = pfnSetEnvironmentVariableW(lpName, lpValue);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCWSTR", (uint64_t)lpName, {}, WideToUtf8(ReadWStringSafe(lpName))},
            {"lpValue", "LPCWSTR", (uint64_t)lpValue, {}, WideToUtf8(ReadWStringSafe(lpValue))}
        };
        LogTelemetry("SetEnvironmentVariableW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* SetEnvironmentVariableA_t)(LPCSTR, LPCSTR);
static SetEnvironmentVariableA_t pfnSetEnvironmentVariableA = nullptr;
static BOOL WINAPI Detour_SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue) {
    HookGuard guard;
    BOOL res = pfnSetEnvironmentVariableA(lpName, lpValue);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpName", "LPCSTR", (uint64_t)lpName, {}, ReadAStringSafe(lpName)},
            {"lpValue", "LPCSTR", (uint64_t)lpValue, {}, ReadAStringSafe(lpValue)}
        };
        LogTelemetry("SetEnvironmentVariableA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* ExpandEnvironmentStringsW_t)(LPCWSTR, LPWSTR, DWORD);
static ExpandEnvironmentStringsW_t pfnExpandEnvironmentStringsW = nullptr;
static DWORD WINAPI Detour_ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnExpandEnvironmentStringsW(lpSrc, lpDst, nSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpSrc", "LPCWSTR", (uint64_t)lpSrc, {}, WideToUtf8(ReadWStringSafe(lpSrc))},
            {"lpDst", "LPWSTR", (uint64_t)lpDst, {}, (res && res <= nSize) ? WideToUtf8(ReadWStringSafe(lpDst, res)) : ""}
        };
        LogTelemetry("ExpandEnvironmentStringsW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* ExpandEnvironmentStringsA_t)(LPCSTR, LPSTR, DWORD);
static ExpandEnvironmentStringsA_t pfnExpandEnvironmentStringsA = nullptr;
static DWORD WINAPI Detour_ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnExpandEnvironmentStringsA(lpSrc, lpDst, nSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpSrc", "LPCSTR", (uint64_t)lpSrc, {}, ReadAStringSafe(lpSrc)},
            {"lpDst", "LPSTR", (uint64_t)lpDst, {}, (res && res <= nSize) ? ReadAStringSafe(lpDst, res) : ""}
        };
        LogTelemetry("ExpandEnvironmentStringsA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HANDLE(WINAPI* GetCurrentProcess_t)();
static GetCurrentProcess_t pfnGetCurrentProcess = nullptr;
static HANDLE WINAPI Detour_GetCurrentProcess() {
    HookGuard guard;
    HANDLE res = pfnGetCurrentProcess();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"Value", "HANDLE", (uint64_t)res, {}, "Current process pseudo-handle"} };
        LogTelemetry("GetCurrentProcess", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetCurrentProcessId_t)();
static GetCurrentProcessId_t pfnGetCurrentProcessId = nullptr;
static DWORD WINAPI Detour_GetCurrentProcessId() {
    HookGuard guard;
    DWORD res = pfnGetCurrentProcessId();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"Value", "DWORD", (uint64_t)res, {}, std::to_string(res)} };
        LogTelemetry("GetCurrentProcessId", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LPWSTR(WINAPI* GetCommandLineW_t)();
static GetCommandLineW_t pfnGetCommandLineW = nullptr;
static LPWSTR WINAPI Detour_GetCommandLineW() {
    HookGuard guard;
    LPWSTR res = pfnGetCommandLineW();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"CommandLine", "LPWSTR", (uint64_t)res, {}, WideToUtf8(ReadWStringSafe(res, 2048))} };
        LogTelemetry("GetCommandLineW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef LPSTR(WINAPI* GetCommandLineA_t)();
static GetCommandLineA_t pfnGetCommandLineA = nullptr;
static LPSTR WINAPI Detour_GetCommandLineA() {
    HookGuard guard;
    LPSTR res = pfnGetCommandLineA();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"CommandLine", "LPSTR", (uint64_t)res, {}, ReadAStringSafe(res, 2048)} };
        LogTelemetry("GetCommandLineA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetCurrentDirectoryW_t)(DWORD, LPWSTR);
static GetCurrentDirectoryW_t pfnGetCurrentDirectoryW = nullptr;
static DWORD WINAPI Detour_GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) {
    HookGuard guard;
    DWORD res = pfnGetCurrentDirectoryW(nBufferLength, lpBuffer);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"CurrentDirectory", "LPWSTR", (uint64_t)lpBuffer, {}, (res && res < nBufferLength) ? WideToUtf8(ReadWStringSafe(lpBuffer, res + 1)) : ""},
            {"nBufferLength", "DWORD", (uint64_t)nBufferLength, {}, ""}
        };
        LogTelemetry("GetCurrentDirectoryW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetCurrentDirectoryA_t)(DWORD, LPSTR);
static GetCurrentDirectoryA_t pfnGetCurrentDirectoryA = nullptr;
static DWORD WINAPI Detour_GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer) {
    HookGuard guard;
    DWORD res = pfnGetCurrentDirectoryA(nBufferLength, lpBuffer);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"CurrentDirectory", "LPSTR", (uint64_t)lpBuffer, {}, (res && res < nBufferLength) ? ReadAStringSafe(lpBuffer, res + 1) : ""},
            {"nBufferLength", "DWORD", (uint64_t)nBufferLength, {}, ""}
        };
        LogTelemetry("GetCurrentDirectoryA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);
static GetModuleFileNameW_t pfnGetModuleFileNameW = nullptr;
static DWORD WINAPI Detour_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnGetModuleFileNameW(hModule, lpFilename, nSize);
    if (!guard.WasInside()) {
        const size_t capturedCharacters = (lpFilename && nSize && res)
            ? static_cast<size_t>((std::min)(res, nSize - 1)) + 1
            : 0;
        std::vector<ParameterCapture> params = {
            {"hModule", "HMODULE", (uint64_t)hModule, {}, ""},
            {"ModuleFileName", "LPWSTR", (uint64_t)lpFilename, {}, capturedCharacters ? WideToUtf8(ReadWStringSafe(lpFilename, capturedCharacters)) : ""},
            {"nSize", "DWORD", (uint64_t)nSize, {}, ""}
        };
        LogTelemetry("GetModuleFileNameW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
static GetModuleFileNameA_t pfnGetModuleFileNameA = nullptr;
static DWORD WINAPI Detour_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
    HookGuard guard;
    DWORD res = pfnGetModuleFileNameA(hModule, lpFilename, nSize);
    if (!guard.WasInside()) {
        const size_t capturedCharacters = (lpFilename && nSize && res)
            ? static_cast<size_t>((std::min)(res, nSize - 1)) + 1
            : 0;
        std::vector<ParameterCapture> params = {
            {"hModule", "HMODULE", (uint64_t)hModule, {}, ""},
            {"ModuleFileName", "LPSTR", (uint64_t)lpFilename, {}, capturedCharacters ? ReadAStringSafe(lpFilename, capturedCharacters) : ""},
            {"nSize", "DWORD", (uint64_t)nSize, {}, ""}
        };
        LogTelemetry("GetModuleFileNameA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* IsDebuggerPresent_t)();
static IsDebuggerPresent_t pfnIsDebuggerPresent = nullptr;
static BOOL WINAPI Detour_IsDebuggerPresent() {
    HookGuard guard;
    BOOL res = pfnIsDebuggerPresent();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"DebuggerPresent", "BOOL", (uint64_t)res, {}, res ? "true" : "false"}
        };
        LogTelemetry("IsDebuggerPresent", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CheckRemoteDebuggerPresent_t)(HANDLE, PBOOL);
static CheckRemoteDebuggerPresent_t pfnCheckRemoteDebuggerPresent = nullptr;
static BOOL WINAPI Detour_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    HookGuard guard;
    BOOL res = pfnCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
    if (!guard.WasInside()) {
        BOOL present = FALSE;
        if (pbDebuggerPresent) SafeCopyBuffer(&present, pbDebuggerPresent, sizeof(present));
        std::vector<ParameterCapture> params = {
            {"hProcess", "HANDLE", (uint64_t)hProcess, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(hProcess ? GetProcessId(hProcess) : 0), {}, ""},
            {"DebuggerPresent", "BOOL", (uint64_t)present, {}, present ? "true" : "false"}
        };
        LogTelemetry("CheckRemoteDebuggerPresent", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef VOID(WINAPI* OutputDebugStringW_t)(LPCWSTR);
static OutputDebugStringW_t pfnOutputDebugStringW = nullptr;
static VOID WINAPI Detour_OutputDebugStringW(LPCWSTR lpOutputString) {
    HookGuard guard;
    pfnOutputDebugStringW(lpOutputString);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpOutputString", "LPCWSTR", (uint64_t)lpOutputString, {}, WideToUtf8(ReadWStringSafe(lpOutputString))}
        };
        LogTelemetry("OutputDebugStringW", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef VOID(WINAPI* OutputDebugStringA_t)(LPCSTR);
static OutputDebugStringA_t pfnOutputDebugStringA = nullptr;
static VOID WINAPI Detour_OutputDebugStringA(LPCSTR lpOutputString) {
    HookGuard guard;
    pfnOutputDebugStringA(lpOutputString);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpOutputString", "LPCSTR", (uint64_t)lpOutputString, {}, ReadAStringSafe(lpOutputString)}
        };
        LogTelemetry("OutputDebugStringA", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryInformationProcess_t pfnNtQueryInformationProcess = nullptr;
static NTSTATUS WINAPI Detour_NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if (!guard.WasInside()) {
        ULONG outLen = 0;
        if (ReturnLength) SafeCopyBuffer(&outLen, ReturnLength, sizeof(outLen));
        std::vector<ParameterCapture> params = {
            {"ProcessHandle", "HANDLE", (uint64_t)ProcessHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(ProcessHandle ? GetProcessId(ProcessHandle) : 0), {}, ""},
            {"ProcessInformationClass", "ULONG", (uint64_t)ProcessInformationClass, {}, ProcessInformationClass == 0 ? "ProcessBasicInformation (PEB discovery)" : ""},
            {"ProcessInformation", "PVOID", (uint64_t)ProcessInformation, ReadBufferSafe(ProcessInformation, (res >= 0) ? ProcessInformationLength : 0), ""},
            {"ProcessInformationLength", "ULONG", (uint64_t)ProcessInformationLength, {}, ""},
            {"ReturnLength", "ULONG", (uint64_t)outLen, {}, ""}
        };
        LogTelemetry("NtQueryInformationProcess", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryInformationThread_t pfnNtQueryInformationThread = nullptr;
static NTSTATUS WINAPI Detour_NtQueryInformationThread(HANDLE thread, ULONG infoClass, PVOID information, ULONG length, PULONG returnLength) {
    HookGuard guard;
    NTSTATUS result = pfnNtQueryInformationThread(thread, infoClass, information, length, returnLength);
    ULONG returned = 0; if (returnLength) SafeCopyBuffer(&returned, returnLength, sizeof(returned));
    if (!guard.WasInside()) LogTelemetry("NtQueryInformationThread", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"ThreadHandle", "HANDLE", (uint64_t)thread, {}, ""}, {"dwThreadId", "DWORD", (uint64_t)(thread ? GetThreadId(thread) : 0), {}, ""},
        {"ThreadInformationClass", "ULONG", infoClass, {}, infoClass == 0 ? "ThreadBasicInformation (TEB discovery)" : ""},
        {"ThreadInformation", "PVOID", (uint64_t)information, ReadBufferSafe(information, result >= 0 ? length : 0), ""},
        {"ThreadInformationLength", "ULONG", length, {}, ""}, {"ReturnLength", "ULONG", returned, {}, ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* NtSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);
static NtSetInformationThread_t pfnNtSetInformationThread = nullptr;
static NTSTATUS WINAPI Detour_NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ThreadHandle", "HANDLE", (uint64_t)ThreadHandle, {}, ""},
            {"dwProcessId", "DWORD", (uint64_t)(ThreadHandle ? GetProcessIdOfThread(ThreadHandle) : 0), {}, ""},
            {"dwThreadId", "DWORD", (uint64_t)(ThreadHandle ? GetThreadId(ThreadHandle) : 0), {}, ""},
            {"ThreadInformationClass", "ULONG", (uint64_t)ThreadInformationClass, {}, ""},
            {"ThreadInformation", "PVOID", (uint64_t)ThreadInformation, ReadBufferSafe(ThreadInformation, ThreadInformationLength), ""},
            {"ThreadInformationLength", "ULONG", (uint64_t)ThreadInformationLength, {}, ""}
        };
        LogTelemetry("NtSetInformationThread", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* DebugActiveProcess_t)(DWORD);
static DebugActiveProcess_t pfnDebugActiveProcess = nullptr;
static BOOL WINAPI Detour_DebugActiveProcess(DWORD dwProcessId) {
    HookGuard guard;
    BOOL res = pfnDebugActiveProcess(dwProcessId);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwProcessId", "DWORD", (uint64_t)dwProcessId, {}, ""}
        };
        LogTelemetry("DebugActiveProcess", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetTickCount_t)();
static GetTickCount_t pfnGetTickCount = nullptr;
static DWORD WINAPI Detour_GetTickCount() {
    HookGuard guard;
    DWORD res = pfnGetTickCount();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"TickCount", "DWORD", (uint64_t)res, {}, ""} };
        LogTelemetry("GetTickCount", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef ULONGLONG(WINAPI* GetTickCount64_t)();
static GetTickCount64_t pfnGetTickCount64 = nullptr;
static ULONGLONG WINAPI Detour_GetTickCount64() {
    HookGuard guard;
    ULONGLONG res = pfnGetTickCount64();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"TickCount64", "ULONGLONG", (uint64_t)res, {}, ""} };
        LogTelemetry("GetTickCount64", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* QueryPerformanceCounter_t)(LARGE_INTEGER*);
static QueryPerformanceCounter_t pfnQueryPerformanceCounter = nullptr;
static BOOL WINAPI Detour_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    HookGuard guard;
    BOOL res = pfnQueryPerformanceCounter(lpPerformanceCount);
    if (!guard.WasInside()) {
        LARGE_INTEGER value {};
        if (lpPerformanceCount) SafeCopyBuffer(&value, lpPerformanceCount, sizeof(value));
        std::vector<ParameterCapture> params = {
            {"PerformanceCount", "LARGE_INTEGER", (uint64_t)value.QuadPart, {}, ""}
        };
        LogTelemetry("QueryPerformanceCounter", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* TimeGetTime_t)();
static TimeGetTime_t pfnTimeGetTime = nullptr;
static DWORD WINAPI Detour_timeGetTime() {
    HookGuard guard;
    DWORD res = pfnTimeGetTime();
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"Time", "DWORD", (uint64_t)res, {}, ""} };
        LogTelemetry("timeGetTime", "winmm.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetUserNameW_t)(LPWSTR, LPDWORD);
static GetUserNameW_t pfnGetUserNameW = nullptr;
static BOOL WINAPI Detour_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer) {
    HookGuard guard;
    BOOL res = pfnGetUserNameW(lpBuffer, pcbBuffer);
    if (!guard.WasInside()) {
        DWORD chars = 0;
        if (pcbBuffer) SafeCopyBuffer(&chars, pcbBuffer, sizeof(chars));
        std::vector<ParameterCapture> params = {
            {"lpBuffer", "LPWSTR", (uint64_t)lpBuffer, {}, res ? WideToUtf8(ReadWStringSafe(lpBuffer)) : ""},
            {"nSize", "DWORD", (uint64_t)chars, {}, ""}
        };
        LogTelemetry("GetUserNameW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetUserNameA_t)(LPSTR, LPDWORD);
static GetUserNameA_t pfnGetUserNameA = nullptr;
static BOOL WINAPI Detour_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer) {
    HookGuard guard;
    BOOL res = pfnGetUserNameA(lpBuffer, pcbBuffer);
    if (!guard.WasInside()) {
        DWORD chars = 0;
        if (pcbBuffer) SafeCopyBuffer(&chars, pcbBuffer, sizeof(chars));
        std::vector<ParameterCapture> params = {
            {"lpBuffer", "LPSTR", (uint64_t)lpBuffer, {}, res ? ReadAStringSafe(lpBuffer) : ""},
            {"nSize", "DWORD", (uint64_t)chars, {}, ""}
        };
        LogTelemetry("GetUserNameA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetComputerNameW_t)(LPWSTR, LPDWORD);
static GetComputerNameW_t pfnGetComputerNameW = nullptr;
static BOOL WINAPI Detour_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
    HookGuard guard;
    BOOL res = pfnGetComputerNameW(lpBuffer, nSize);
    if (!guard.WasInside()) {
        DWORD chars = 0;
        if (nSize) SafeCopyBuffer(&chars, nSize, sizeof(chars));
        std::vector<ParameterCapture> params = {
            {"lpBuffer", "LPWSTR", (uint64_t)lpBuffer, {}, res ? WideToUtf8(ReadWStringSafe(lpBuffer)) : ""},
            {"nSize", "DWORD", (uint64_t)chars, {}, ""}
        };
        LogTelemetry("GetComputerNameW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetComputerNameA_t)(LPSTR, LPDWORD);
static GetComputerNameA_t pfnGetComputerNameA = nullptr;
static BOOL WINAPI Detour_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize) {
    HookGuard guard;
    BOOL res = pfnGetComputerNameA(lpBuffer, nSize);
    if (!guard.WasInside()) {
        DWORD chars = 0;
        if (nSize) SafeCopyBuffer(&chars, nSize, sizeof(chars));
        std::vector<ParameterCapture> params = {
            {"lpBuffer", "LPSTR", (uint64_t)lpBuffer, {}, res ? ReadAStringSafe(lpBuffer) : ""},
            {"nSize", "DWORD", (uint64_t)chars, {}, ""}
        };
        LogTelemetry("GetComputerNameA", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef VOID(WINAPI* GetSystemInfo_t)(LPSYSTEM_INFO);
static GetSystemInfo_t pfnGetSystemInfo = nullptr;
static VOID WINAPI Detour_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    HookGuard guard;
    pfnGetSystemInfo(lpSystemInfo);
    if (!guard.WasInside()) {
        SYSTEM_INFO info {};
        if (lpSystemInfo) SafeCopyBuffer(&info, lpSystemInfo, sizeof(info));
        std::vector<ParameterCapture> params = {
            {"wProcessorArchitecture", "WORD", (uint64_t)info.wProcessorArchitecture, {}, ""},
            {"dwNumberOfProcessors", "DWORD", (uint64_t)info.dwNumberOfProcessors, {}, ""},
            {"dwPageSize", "DWORD", (uint64_t)info.dwPageSize, {}, ""}
        };
        LogTelemetry("GetSystemInfo", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef BOOL(WINAPI* GlobalMemoryStatusEx_t)(LPMEMORYSTATUSEX);
static GlobalMemoryStatusEx_t pfnGlobalMemoryStatusEx = nullptr;
static BOOL WINAPI Detour_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer) {
    HookGuard guard;
    BOOL res = pfnGlobalMemoryStatusEx(lpBuffer);
    if (!guard.WasInside()) {
        MEMORYSTATUSEX mem {};
        if (lpBuffer) SafeCopyBuffer(&mem, lpBuffer, sizeof(mem));
        std::vector<ParameterCapture> params = {
            {"ullTotalPhys", "ULONGLONG", (uint64_t)mem.ullTotalPhys, {}, ""},
            {"ullAvailPhys", "ULONGLONG", (uint64_t)mem.ullAvailPhys, {}, ""},
            {"dwMemoryLoad", "DWORD", (uint64_t)mem.dwMemoryLoad, {}, ""}
        };
        LogTelemetry("GlobalMemoryStatusEx", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* GetCursorPos_t)(LPPOINT);
static GetCursorPos_t pfnGetCursorPos = nullptr;
static BOOL WINAPI Detour_GetCursorPos(LPPOINT lpPoint) {
    HookGuard guard;
    BOOL res = pfnGetCursorPos(lpPoint);
    if (!guard.WasInside()) {
        POINT pt {};
        if (lpPoint) SafeCopyBuffer(&pt, lpPoint, sizeof(pt));
        std::vector<ParameterCapture> params = {
            {"x", "LONG", (uint64_t)(int64_t)pt.x, {}, ""},
            {"y", "LONG", (uint64_t)(int64_t)pt.y, {}, ""}
        };
        LogTelemetry("GetCursorPos", "user32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef DWORD(WINAPI* GetTimeZoneInformation_t)(LPTIME_ZONE_INFORMATION);
static GetTimeZoneInformation_t pfnGetTimeZoneInformation = nullptr;
static DWORD WINAPI Detour_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation) {
    HookGuard guard;
    DWORD res = pfnGetTimeZoneInformation(lpTimeZoneInformation);
    if (!guard.WasInside()) {
        TIME_ZONE_INFORMATION tz {};
        if (lpTimeZoneInformation) SafeCopyBuffer(&tz, lpTimeZoneInformation, sizeof(tz));
        std::vector<ParameterCapture> params = {
            {"Bias", "LONG", (uint64_t)(int64_t)tz.Bias, {}, ""},
            {"StandardName", "WCHAR[]", 0, {}, WideToUtf8(std::wstring(tz.StandardName))},
            {"DaylightName", "WCHAR[]", 0, {}, WideToUtf8(std::wstring(tz.DaylightName))}
        };
        LogTelemetry("GetTimeZoneInformation", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef UINT(WINAPI* EnumSystemFirmwareTables_t)(DWORD, PVOID, DWORD);
static EnumSystemFirmwareTables_t pfnEnumSystemFirmwareTables = nullptr;
static UINT WINAPI Detour_EnumSystemFirmwareTables(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    HookGuard guard;
    UINT res = pfnEnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"FirmwareTableProviderSignature", "DWORD", (uint64_t)FirmwareTableProviderSignature, {}, ""},
            {"BufferSize", "DWORD", (uint64_t)BufferSize, {}, ""}
        };
        LogTelemetry("EnumSystemFirmwareTables", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef UINT(WINAPI* GetSystemFirmwareTable_t)(DWORD, DWORD, PVOID, DWORD);
static GetSystemFirmwareTable_t pfnGetSystemFirmwareTable = nullptr;
static UINT WINAPI Detour_GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    HookGuard guard;
    UINT res = pfnGetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"FirmwareTableProviderSignature", "DWORD", (uint64_t)FirmwareTableProviderSignature, {}, ""},
            {"FirmwareTableID", "DWORD", (uint64_t)FirmwareTableID, {}, ""},
            {"BufferSize", "DWORD", (uint64_t)BufferSize, {}, ""}
        };
        LogTelemetry("GetSystemFirmwareTable", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef void(WINAPI* GetSystemTimeAsFileTime_t)(LPFILETIME);
static GetSystemTimeAsFileTime_t pfnGetSystemTimeAsFileTime = nullptr;
static void WINAPI Detour_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    HookGuard guard;
    pfnGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {};
        LogTelemetry("GetSystemTimeAsFileTime", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef void(WINAPI* GetSystemTimePreciseAsFileTime_t)(LPFILETIME);
static GetSystemTimePreciseAsFileTime_t pfnGetSystemTimePreciseAsFileTime = nullptr;
static void WINAPI Detour_GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    HookGuard guard;
    pfnGetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {};
        LogTelemetry("GetSystemTimePreciseAsFileTime", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef PVOID(WINAPI* AddVectoredExceptionHandler_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
static AddVectoredExceptionHandler_t pfnAddVectoredExceptionHandler = nullptr;
static PVOID WINAPI Detour_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    HookGuard guard;
    PVOID res = pfnAddVectoredExceptionHandler(First, Handler);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"First", "ULONG", (uint64_t)First, {}, ""},
            {"Handler", "PVECTORED_EXCEPTION_HANDLER", (uint64_t)Handler, {}, ""}
        };
        LogTelemetry("AddVectoredExceptionHandler", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef ULONG(WINAPI* RemoveVectoredExceptionHandler_t)(PVOID);
static RemoveVectoredExceptionHandler_t pfnRemoveVectoredExceptionHandler = nullptr;
static ULONG WINAPI Detour_RemoveVectoredExceptionHandler(PVOID Handle) {
    HookGuard guard;
    ULONG res = pfnRemoveVectoredExceptionHandler(Handle);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"Handle", "PVOID", (uint64_t)Handle, {}, ""}
        };
        LogTelemetry("RemoveVectoredExceptionHandler", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef PVOID(WINAPI* AddVectoredContinueHandler_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
static AddVectoredContinueHandler_t pfnAddVectoredContinueHandler = nullptr;
static PVOID WINAPI Detour_AddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
    HookGuard guard;
    PVOID result = pfnAddVectoredContinueHandler(first, handler);
    if (!guard.WasInside()) LogTelemetry("AddVectoredContinueHandler", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"First", "ULONG", first, {}, ""}, {"Callback", "PVECTORED_EXCEPTION_HANDLER", (uint64_t)handler, {}, "Vectored continue callback"}
    });
    return result;
}

typedef BOOL(WINAPI* CreateTimerQueueTimer_t)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
static CreateTimerQueueTimer_t pfnCreateTimerQueueTimer = nullptr;
static BOOL WINAPI Detour_CreateTimerQueueTimer(PHANDLE timer, HANDLE queue, WAITORTIMERCALLBACK callback, PVOID context, DWORD due, DWORD period, ULONG flags) {
    HookGuard guard;
    BOOL result = pfnCreateTimerQueueTimer(timer, queue, callback, context, due, period, flags);
    if (!guard.WasInside()) LogTelemetry("CreateTimerQueueTimer", "kernel32.dll", _ReturnAddress(), result, {
        {"Callback", "WAITORTIMERCALLBACK", (uint64_t)callback, {}, "Timer queue callback"}, {"Context", "PVOID", (uint64_t)context, {}, ""},
        {"DueTime", "DWORD", due, {}, ""}, {"Period", "DWORD", period, {}, ""}, {"Flags", "ULONG", flags, {}, ""}
    });
    return result;
}

typedef BOOL(WINAPI* RegisterWaitForSingleObject_t)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG);
static RegisterWaitForSingleObject_t pfnRegisterWaitForSingleObject = nullptr;
static BOOL WINAPI Detour_RegisterWaitForSingleObject(PHANDLE waitHandle, HANDLE object, WAITORTIMERCALLBACK callback, PVOID context, ULONG timeout, ULONG flags) {
    HookGuard guard;
    BOOL result = pfnRegisterWaitForSingleObject(waitHandle, object, callback, context, timeout, flags);
    if (!guard.WasInside()) LogTelemetry("RegisterWaitForSingleObject", "kernel32.dll", _ReturnAddress(), result, {
        {"Object", "HANDLE", (uint64_t)object, {}, ""}, {"Callback", "WAITORTIMERCALLBACK", (uint64_t)callback, {}, "Registered wait callback"},
        {"Context", "PVOID", (uint64_t)context, {}, ""}, {"Timeout", "ULONG", timeout, {}, ""}, {"Flags", "ULONG", flags, {}, ""}
    });
    return result;
}

typedef PTP_WORK(WINAPI* CreateThreadpoolWork_t)(PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
static CreateThreadpoolWork_t pfnCreateThreadpoolWork = nullptr;
static PTP_WORK WINAPI Detour_CreateThreadpoolWork(PTP_WORK_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment) {
    HookGuard guard;
    PTP_WORK result = pfnCreateThreadpoolWork(callback, context, environment);
    if (!guard.WasInside()) LogTelemetry("CreateThreadpoolWork", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"Callback", "PTP_WORK_CALLBACK", (uint64_t)callback, {}, "Thread-pool work callback"}, {"Context", "PVOID", (uint64_t)context, {}, ""}
    });
    return result;
}

typedef VOID(WINAPI* SubmitThreadpoolWork_t)(PTP_WORK);
static SubmitThreadpoolWork_t pfnSubmitThreadpoolWork = nullptr;
static VOID WINAPI Detour_SubmitThreadpoolWork(PTP_WORK work) {
    HookGuard guard;
    pfnSubmitThreadpoolWork(work);
    if (!guard.WasInside()) LogTelemetry("SubmitThreadpoolWork", "kernel32.dll", _ReturnAddress(), 0, {{"Work", "PTP_WORK", (uint64_t)work, {}, ""}});
}

typedef LPVOID(WINAPI* CreateFiber_t)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
static CreateFiber_t pfnCreateFiber = nullptr;
static LPVOID WINAPI Detour_CreateFiber(SIZE_T stackSize, LPFIBER_START_ROUTINE start, LPVOID parameter) {
    HookGuard guard;
    LPVOID result = pfnCreateFiber(stackSize, start, parameter);
    if (!guard.WasInside()) LogTelemetry("CreateFiber", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"StackSize", "SIZE_T", stackSize, {}, ""}, {"Callback", "LPFIBER_START_ROUTINE", (uint64_t)start, {}, "Fiber start callback"},
        {"Parameter", "LPVOID", (uint64_t)parameter, {}, ""}
    });
    return result;
}

typedef DWORD(WINAPI* FlsAlloc_t)(PFLS_CALLBACK_FUNCTION);
static FlsAlloc_t pfnFlsAlloc = nullptr;
static DWORD WINAPI Detour_FlsAlloc(PFLS_CALLBACK_FUNCTION callback) {
    HookGuard guard;
    DWORD result = pfnFlsAlloc(callback);
    if (!guard.WasInside()) LogTelemetry("FlsAlloc", "kernel32.dll", _ReturnAddress(), result, {
        {"Callback", "PFLS_CALLBACK_FUNCTION", (uint64_t)callback, {}, "Fiber-local cleanup callback"}
    });
    return result;
}

typedef BOOL(WINAPI* EnumWindows_t)(WNDENUMPROC, LPARAM);
static EnumWindows_t pfnEnumWindows = nullptr;
static BOOL WINAPI Detour_EnumWindows(WNDENUMPROC callback, LPARAM data) {
    HookGuard guard;
    BOOL result = pfnEnumWindows(callback, data);
    if (!guard.WasInside()) LogTelemetry("EnumWindows", "user32.dll", _ReturnAddress(), result, {
        {"Callback", "WNDENUMPROC", (uint64_t)callback, {}, "Window enumeration callback"}, {"Context", "LPARAM", (uint64_t)data, {}, ""}
    });
    return result;
}

typedef BOOL(WINAPI* EnumChildWindows_t)(HWND, WNDENUMPROC, LPARAM);
static EnumChildWindows_t pfnEnumChildWindows = nullptr;
static BOOL WINAPI Detour_EnumChildWindows(HWND parent, WNDENUMPROC callback, LPARAM data) {
    HookGuard guard;
    BOOL result = pfnEnumChildWindows(parent, callback, data);
    if (!guard.WasInside()) LogTelemetry("EnumChildWindows", "user32.dll", _ReturnAddress(), result, {
        {"Parent", "HWND", (uint64_t)parent, {}, ""}, {"Callback", "WNDENUMPROC", (uint64_t)callback, {}, "Child-window enumeration callback"},
        {"Context", "LPARAM", (uint64_t)data, {}, ""}
    });
    return result;
}

typedef UINT_PTR(WINAPI* SetTimer_t)(HWND, UINT_PTR, UINT, TIMERPROC);
static SetTimer_t pfnSetTimer = nullptr;
static UINT_PTR WINAPI Detour_SetTimer(HWND window, UINT_PTR id, UINT interval, TIMERPROC callback) {
    HookGuard guard;
    UINT_PTR result = pfnSetTimer(window, id, interval, callback);
    if (!guard.WasInside()) LogTelemetry("SetTimer", "user32.dll", _ReturnAddress(), result, {
        {"Window", "HWND", (uint64_t)window, {}, ""}, {"TimerId", "UINT_PTR", id, {}, ""},
        {"Interval", "UINT", interval, {}, ""}, {"Callback", "TIMERPROC", (uint64_t)callback, {}, "Timer callback"}
    });
    return result;
}

typedef HHOOK(WINAPI* SetWindowsHookExW_t)(int, HOOKPROC, HINSTANCE, DWORD);
static SetWindowsHookExW_t pfnSetWindowsHookExW = nullptr;
static HHOOK WINAPI Detour_SetWindowsHookExW(int id, HOOKPROC callback, HINSTANCE module, DWORD threadId) {
    HookGuard guard;
    HHOOK result = pfnSetWindowsHookExW(id, callback, module, threadId);
    if (!guard.WasInside()) LogTelemetry("SetWindowsHookExW", "user32.dll", _ReturnAddress(), (uint64_t)result, {
        {"HookType", "int", (uint64_t)(uint32_t)id, {}, ""}, {"Callback", "HOOKPROC", (uint64_t)callback, {}, "Windows hook callback"},
        {"Module", "HINSTANCE", (uint64_t)module, {}, ""}, {"ThreadId", "DWORD", threadId, {}, ""}
    });
    return result;
}

typedef HHOOK(WINAPI* SetWindowsHookExA_t)(int, HOOKPROC, HINSTANCE, DWORD);
static SetWindowsHookExA_t pfnSetWindowsHookExA = nullptr;
static HHOOK WINAPI Detour_SetWindowsHookExA(int id, HOOKPROC callback, HINSTANCE module, DWORD threadId) {
    HookGuard guard;
    HHOOK result = pfnSetWindowsHookExA(id, callback, module, threadId);
    if (!guard.WasInside()) LogTelemetry("SetWindowsHookExA", "user32.dll", _ReturnAddress(), (uint64_t)result, {
        {"HookType", "int", (uint64_t)(uint32_t)id, {}, ""}, {"Callback", "HOOKPROC", (uint64_t)callback, {}, "Windows hook callback"},
        {"Module", "HINSTANCE", (uint64_t)module, {}, ""}, {"ThreadId", "DWORD", threadId, {}, ""}
    });
    return result;
}

typedef BOOL(WINAPI* EnumThreadWindows_t)(DWORD, WNDENUMPROC, LPARAM);
static EnumThreadWindows_t pfnEnumThreadWindows = nullptr;
static BOOL WINAPI Detour_EnumThreadWindows(DWORD threadId, WNDENUMPROC callback, LPARAM data) {
    HookGuard guard;
    BOOL result = pfnEnumThreadWindows(threadId, callback, data);
    if (!guard.WasInside()) LogTelemetry("EnumThreadWindows", "user32.dll", _ReturnAddress(), result, {
        {"ThreadId", "DWORD", threadId, {}, ""}, {"Callback", "WNDENUMPROC", (uint64_t)callback, {}, "Thread-window enumeration callback"},
        {"Context", "LPARAM", (uint64_t)data, {}, ""}
    });
    return result;
}

typedef BOOL(WINAPI* EnumDesktopWindows_t)(HDESK, WNDENUMPROC, LPARAM);
static EnumDesktopWindows_t pfnEnumDesktopWindows = nullptr;
static BOOL WINAPI Detour_EnumDesktopWindows(HDESK desktop, WNDENUMPROC callback, LPARAM data) {
    HookGuard guard;
    BOOL result = pfnEnumDesktopWindows(desktop, callback, data);
    if (!guard.WasInside()) LogTelemetry("EnumDesktopWindows", "user32.dll", _ReturnAddress(), result, {
        {"Desktop", "HDESK", (uint64_t)desktop, {}, ""}, {"Callback", "WNDENUMPROC", (uint64_t)callback, {}, "Desktop-window enumeration callback"},
        {"Context", "LPARAM", (uint64_t)data, {}, ""}
    });
    return result;
}

typedef LRESULT(WINAPI* CallWindowProcW_t)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
static CallWindowProcW_t pfnCallWindowProcW = nullptr;
static LRESULT WINAPI Detour_CallWindowProcW(WNDPROC callback, HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    HookGuard guard;
    LRESULT result = pfnCallWindowProcW(callback, window, message, wparam, lparam);
    if (!guard.WasInside()) LogTelemetry("CallWindowProcW", "user32.dll", _ReturnAddress(), (uint64_t)result, {
        {"Callback", "WNDPROC", (uint64_t)callback, {}, "Invoked window procedure"}, {"Window", "HWND", (uint64_t)window, {}, ""},
        {"Message", "UINT", message, {}, ""}
    });
    return result;
}

typedef LPVOID(WINAPI* CreateFiberEx_t)(SIZE_T, SIZE_T, DWORD, LPFIBER_START_ROUTINE, LPVOID);
static CreateFiberEx_t pfnCreateFiberEx = nullptr;
static LPVOID WINAPI Detour_CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags, LPFIBER_START_ROUTINE start, LPVOID parameter) {
    HookGuard guard;
    LPVOID result = pfnCreateFiberEx(commit, reserve, flags, start, parameter);
    if (!guard.WasInside()) LogTelemetry("CreateFiberEx", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"CommitSize", "SIZE_T", commit, {}, ""}, {"ReserveSize", "SIZE_T", reserve, {}, ""}, {"Flags", "DWORD", flags, {}, ""},
        {"Callback", "LPFIBER_START_ROUTINE", (uint64_t)start, {}, "Fiber start callback"}, {"Parameter", "LPVOID", (uint64_t)parameter, {}, ""}
    });
    return result;
}

typedef PTP_TIMER(WINAPI* CreateThreadpoolTimer_t)(PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
static CreateThreadpoolTimer_t pfnCreateThreadpoolTimer = nullptr;
static PTP_TIMER WINAPI Detour_CreateThreadpoolTimer(PTP_TIMER_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment) {
    HookGuard guard;
    PTP_TIMER result = pfnCreateThreadpoolTimer(callback, context, environment);
    if (!guard.WasInside()) LogTelemetry("CreateThreadpoolTimer", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"Callback", "PTP_TIMER_CALLBACK", (uint64_t)callback, {}, "Thread-pool timer callback"}, {"Context", "PVOID", (uint64_t)context, {}, ""}
    });
    return result;
}

typedef PTP_WAIT(WINAPI* CreateThreadpoolWait_t)(PTP_WAIT_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
static CreateThreadpoolWait_t pfnCreateThreadpoolWait = nullptr;
static PTP_WAIT WINAPI Detour_CreateThreadpoolWait(PTP_WAIT_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment) {
    HookGuard guard;
    PTP_WAIT result = pfnCreateThreadpoolWait(callback, context, environment);
    if (!guard.WasInside()) LogTelemetry("CreateThreadpoolWait", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"Callback", "PTP_WAIT_CALLBACK", (uint64_t)callback, {}, "Thread-pool wait callback"},
        {"Context", "PVOID", (uint64_t)context, {}, ""}, {"Environment", "PTP_CALLBACK_ENVIRON", (uint64_t)environment, {}, ""}
    });
    return result;
}

typedef VOID(WINAPI* SetThreadpoolWait_t)(PTP_WAIT, HANDLE, PFILETIME);
static SetThreadpoolWait_t pfnSetThreadpoolWait = nullptr;
static VOID WINAPI Detour_SetThreadpoolWait(PTP_WAIT wait, HANDLE object, PFILETIME timeout) {
    HookGuard guard;
    pfnSetThreadpoolWait(wait, object, timeout);
    if (!guard.WasInside()) LogTelemetry("SetThreadpoolWait", "kernel32.dll", _ReturnAddress(), 0, {
        {"Wait", "PTP_WAIT", (uint64_t)wait, {}, ""}, {"Object", "HANDLE", (uint64_t)object, {}, ""},
        {"Timeout", "PFILETIME", (uint64_t)timeout, ReadBufferSafe(timeout, timeout ? sizeof(FILETIME) : 0), "Arms the thread-pool wait"}
    });
}

typedef LPVOID(WINAPI* ConvertThreadToFiberEx_t)(LPVOID, DWORD);
static ConvertThreadToFiberEx_t pfnConvertThreadToFiberEx = nullptr;
static LPVOID WINAPI Detour_ConvertThreadToFiberEx(LPVOID parameter, DWORD flags) {
    HookGuard guard;
    LPVOID result = pfnConvertThreadToFiberEx(parameter, flags);
    if (!guard.WasInside()) LogTelemetry("ConvertThreadToFiberEx", "kernel32.dll", _ReturnAddress(), (uint64_t)result, {
        {"Parameter", "LPVOID", (uint64_t)parameter, {}, ""}, {"Flags", "DWORD", flags, {}, ""}
    });
    return result;
}

typedef VOID(WINAPI* SwitchToFiber_t)(LPVOID);
static SwitchToFiber_t pfnSwitchToFiber = nullptr;
static VOID WINAPI Detour_SwitchToFiber(LPVOID fiber) {
    HookGuard guard;
    if (!guard.WasInside()) LogTelemetry("SwitchToFiber", "kernel32.dll", _ReturnAddress(), 0, {
        {"Fiber", "LPVOID", (uint64_t)fiber, {}, "Transfers execution to a fiber callback"}
    });
    pfnSwitchToFiber(fiber);
}

typedef VOID(WINAPI* RaiseException_t)(DWORD, DWORD, DWORD, const ULONG_PTR*);
static RaiseException_t pfnRaiseException = nullptr;
static VOID WINAPI Detour_RaiseException(DWORD code, DWORD flags, DWORD argumentCount, const ULONG_PTR* arguments) {
    HookGuard guard;
    if (!guard.WasInside()) LogTelemetry("RaiseException", "kernel32.dll", _ReturnAddress(), code, {
        {"ExceptionCode", "DWORD", code, {}, "SEH dispatch trigger"}, {"ExceptionFlags", "DWORD", flags, {}, ""},
        {"ArgumentCount", "DWORD", argumentCount, {}, ""}, {"Arguments", "ULONG_PTR*", (uint64_t)arguments, ReadBufferSafe(arguments, (argumentCount > 8 ? 8 : argumentCount) * sizeof(ULONG_PTR)), ""}
    });
    pfnRaiseException(code, flags, argumentCount, arguments);
}

typedef NTSTATUS(NTAPI* NtTestAlert_t)();
static NtTestAlert_t pfnNtTestAlert = nullptr;
static NTSTATUS NTAPI Detour_NtTestAlert() {
    HookGuard guard;
    NTSTATUS result = pfnNtTestAlert();
    if (!guard.WasInside()) LogTelemetry("NtTestAlert", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {});
    return result;
}

typedef NTSTATUS(NTAPI* NtRaiseException_t)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
static NtRaiseException_t pfnNtRaiseException = nullptr;
static NTSTATUS NTAPI Detour_NtRaiseException(PEXCEPTION_RECORD record, PCONTEXT context, BOOLEAN firstChance) {
    HookGuard guard;
    DWORD code = 0; if (record) { EXCEPTION_RECORD copy{}; if (SafeCopyBuffer(&copy, record, sizeof(copy))) code = copy.ExceptionCode; }
    NTSTATUS result = pfnNtRaiseException(record, context, firstChance);
    if (!guard.WasInside()) LogTelemetry("NtRaiseException", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"ExceptionCode", "DWORD", code, {}, "Native SEH dispatch"}, {"FirstChance", "BOOLEAN", firstChance, {}, ""},
        {"ExceptionRecord", "PEXCEPTION_RECORD", (uint64_t)record, ReadBufferSafe(record, record ? sizeof(EXCEPTION_RECORD) : 0), ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* RtlCompressBuffer_t)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
static RtlCompressBuffer_t pfnRtlCompressBuffer = nullptr;
static NTSTATUS WINAPI Detour_RtlCompressBuffer(USHORT format, PUCHAR input, ULONG inputSize, PUCHAR output, ULONG outputSize, ULONG chunkSize, PULONG finalSize, PVOID workspace) {
    HookGuard guard;
    NTSTATUS result = pfnRtlCompressBuffer(format, input, inputSize, output, outputSize, chunkSize, finalSize, workspace);
    ULONG written = 0; if (finalSize) SafeCopyBuffer(&written, finalSize, sizeof(written));
    if (!guard.WasInside()) LogTelemetry("RtlCompressBuffer", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"CompressionFormat", "USHORT", format, {}, "LZNT/XPRESS format flags"}, {"InputBuffer", "PUCHAR", (uint64_t)input, ReadBufferSafe(input, inputSize, kMaximumMemoryBufferCapture), ""},
        {"InputSize", "ULONG", inputSize, {}, ""}, {"OutputBuffer", "PUCHAR", (uint64_t)output, ReadBufferSafe(output, result >= 0 ? written : 0, kMaximumMemoryBufferCapture), ""},
        {"OutputSize", "ULONG", outputSize, {}, ""}, {"FinalSize", "ULONG", written, {}, ""}
    });
    return result;
}

typedef NTSTATUS(WINAPI* RtlDecompressBuffer_t)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
static RtlDecompressBuffer_t pfnRtlDecompressBuffer = nullptr;
static NTSTATUS WINAPI Detour_RtlDecompressBuffer(USHORT format, PUCHAR output, ULONG outputSize, PUCHAR input, ULONG inputSize, PULONG finalSize) {
    HookGuard guard;
    NTSTATUS result = pfnRtlDecompressBuffer(format, output, outputSize, input, inputSize, finalSize);
    ULONG written = 0; if (finalSize) SafeCopyBuffer(&written, finalSize, sizeof(written));
    if (!guard.WasInside()) LogTelemetry("RtlDecompressBuffer", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, {
        {"CompressionFormat", "USHORT", format, {}, "LZNT/XPRESS format flags"}, {"CompressedBuffer", "PUCHAR", (uint64_t)input, ReadBufferSafe(input, inputSize, kMaximumMemoryBufferCapture), ""},
        {"CompressedSize", "ULONG", inputSize, {}, ""}, {"UncompressedBuffer", "PUCHAR", (uint64_t)output, ReadBufferSafe(output, result >= 0 ? written : 0, kMaximumMemoryBufferCapture), ""},
        {"UncompressedSize", "ULONG", written, {}, ""}
    });
    return result;
}

typedef VOID(WINAPI* GetSystemTime_t)(LPSYSTEMTIME);
static GetSystemTime_t pfnGetSystemTime = nullptr;
static VOID WINAPI Detour_GetSystemTime(LPSYSTEMTIME lpSystemTime) {
    HookGuard guard;
    pfnGetSystemTime(lpSystemTime);
    if (!guard.WasInside()) {
        SYSTEMTIME st {};
        if (lpSystemTime) SafeCopyBuffer(&st, lpSystemTime, sizeof(st));
        std::vector<ParameterCapture> params = {
            {"wYear", "WORD", (uint64_t)st.wYear, {}, ""},
            {"wMonth", "WORD", (uint64_t)st.wMonth, {}, ""},
            {"wDay", "WORD", (uint64_t)st.wDay, {}, ""},
            {"wHour", "WORD", (uint64_t)st.wHour, {}, ""}
        };
        LogTelemetry("GetSystemTime", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef VOID(WINAPI* GetLocalTime_t)(LPSYSTEMTIME);
static GetLocalTime_t pfnGetLocalTime = nullptr;
static VOID WINAPI Detour_GetLocalTime(LPSYSTEMTIME lpSystemTime) {
    HookGuard guard;
    pfnGetLocalTime(lpSystemTime);
    if (!guard.WasInside()) {
        SYSTEMTIME st {};
        if (lpSystemTime) SafeCopyBuffer(&st, lpSystemTime, sizeof(st));
        std::vector<ParameterCapture> params = {
            {"wYear", "WORD", (uint64_t)st.wYear, {}, ""},
            {"wMonth", "WORD", (uint64_t)st.wMonth, {}, ""},
            {"wDay", "WORD", (uint64_t)st.wDay, {}, ""},
            {"wHour", "WORD", (uint64_t)st.wHour, {}, ""}
        };
        LogTelemetry("GetLocalTime", "kernel32.dll", _ReturnAddress(), 0, params);
    }
}

typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
static CreateToolhelp32Snapshot_t pfnCreateToolhelp32Snapshot = nullptr;
static HANDLE WINAPI Detour_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    HookGuard guard;
    HANDLE res = pfnCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"th32ProcessID", "DWORD", (uint64_t)th32ProcessID, {}, ""}
        };
        LogTelemetry("CreateToolhelp32Snapshot", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
static Process32FirstW_t pfnProcess32FirstW = nullptr;
static BOOL WINAPI Detour_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    HookGuard guard;
    BOOL res = pfnProcess32FirstW(hSnapshot, lppe);
    if (!guard.WasInside()) {
        PROCESSENTRY32W entry {};
        if (res && lppe) SafeCopyBuffer(&entry, lppe, sizeof(entry));
        std::vector<ParameterCapture> params = {
            {"hSnapshot", "HANDLE", (uint64_t)hSnapshot, {}, ""},
            {"th32ProcessID", "DWORD", (uint64_t)entry.th32ProcessID, {}, ""},
            {"szExeFile", "WCHAR[]", 0, {}, res ? WideToUtf8(std::wstring(entry.szExeFile)) : ""}
        };
        LogTelemetry("Process32FirstW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
static Process32NextW_t pfnProcess32NextW = nullptr;
static BOOL WINAPI Detour_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    HookGuard guard;
    BOOL res = pfnProcess32NextW(hSnapshot, lppe);
    if (!guard.WasInside()) {
        PROCESSENTRY32W entry {};
        if (res && lppe) SafeCopyBuffer(&entry, lppe, sizeof(entry));
        std::vector<ParameterCapture> params = {
            {"hSnapshot", "HANDLE", (uint64_t)hSnapshot, {}, ""},
            {"th32ProcessID", "DWORD", (uint64_t)entry.th32ProcessID, {}, ""},
            {"szExeFile", "WCHAR[]", 0, {}, res ? WideToUtf8(std::wstring(entry.szExeFile)) : ""}
        };
        LogTelemetry("Process32NextW", "kernel32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t pfnNtQuerySystemInformation = nullptr;
static NTSTATUS WINAPI Detour_NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    HookGuard guard;
    NTSTATUS res = pfnNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (!guard.WasInside()) {
        ULONG outLen = 0;
        if (ReturnLength) SafeCopyBuffer(&outLen, ReturnLength, sizeof(outLen));
        std::vector<ParameterCapture> params = {
            {"SystemInformationClass", "ULONG", (uint64_t)SystemInformationClass, {}, ""},
            {"SystemInformation", "PVOID", (uint64_t)SystemInformation, ReadBufferSafe(SystemInformation, (res >= 0) ? SystemInformationLength : 0, 256), ""},
            {"SystemInformationLength", "ULONG", (uint64_t)SystemInformationLength, {}, ""},
            {"ReturnLength", "ULONG", (uint64_t)outLen, {}, ""}
        };
        LogTelemetry("NtQuerySystemInformation", "ntdll.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptAcquireContextW_t)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
static CryptAcquireContextW_t pfnCryptAcquireContextW = nullptr;
static BOOL WINAPI Detour_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    HookGuard guard;
    BOOL res = pfnCryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);
    if (!guard.WasInside()) {
        HCRYPTPROV prov = (res && phProv) ? *phProv : 0;
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)prov, {}, ""},
            {"szContainer", "LPCWSTR", (uint64_t)szContainer, {}, WideToUtf8(ReadWStringSafe(szContainer))},
            {"szProvider", "LPCWSTR", (uint64_t)szProvider, {}, WideToUtf8(ReadWStringSafe(szProvider))},
            {"dwProvType", "DWORD", (uint64_t)dwProvType, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("CryptAcquireContextW", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptAcquireContextA_t)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
static CryptAcquireContextA_t pfnCryptAcquireContextA = nullptr;
static BOOL WINAPI Detour_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    HookGuard guard;
    BOOL res = pfnCryptAcquireContextA(phProv, szContainer, szProvider, dwProvType, dwFlags);
    if (!guard.WasInside()) {
        HCRYPTPROV prov = (res && phProv) ? *phProv : 0;
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)prov, {}, ""},
            {"szContainer", "LPCSTR", (uint64_t)szContainer, {}, ReadAStringSafe(szContainer)},
            {"szProvider", "LPCSTR", (uint64_t)szProvider, {}, ReadAStringSafe(szProvider)},
            {"dwProvType", "DWORD", (uint64_t)dwProvType, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("CryptAcquireContextA", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptCreateHash_t)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
static CryptCreateHash_t pfnCryptCreateHash = nullptr;
static BOOL WINAPI Detour_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash) {
    HookGuard guard;
    BOOL res = pfnCryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
    if (!guard.WasInside()) {
        HCRYPTHASH hash = (res && phHash) ? *phHash : 0;
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)hProv, {}, ""},
            {"Algid", "ALG_ID", (uint64_t)Algid, {}, ""},
            {"hKey", "HCRYPTKEY", (uint64_t)hKey, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"hHash", "HCRYPTHASH", (uint64_t)hash, {}, ""}
        };
        LogTelemetry("CryptCreateHash", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptHashData_t)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
static CryptHashData_t pfnCryptHashData = nullptr;
static BOOL WINAPI Detour_CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags) {
    HookGuard guard;
    BOOL res = pfnCryptHashData(hHash, pbData, dwDataLen, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hHash", "HCRYPTHASH", (uint64_t)hHash, {}, ""},
            {"pbData", "BYTE*", (uint64_t)pbData, ReadBufferSafe(pbData, dwDataLen), ""},
            {"dwDataLen", "DWORD", (uint64_t)dwDataLen, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("CryptHashData", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptDeriveKey_t)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
static CryptDeriveKey_t pfnCryptDeriveKey = nullptr;
static BOOL WINAPI Detour_CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey) {
    HookGuard guard;
    BOOL res = pfnCryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);
    if (!guard.WasInside()) {
        HCRYPTKEY key = (res && phKey) ? *phKey : 0;
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)hProv, {}, ""},
            {"Algid", "ALG_ID", (uint64_t)Algid, {}, ""},
            {"hBaseData", "HCRYPTHASH", (uint64_t)hBaseData, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"hKey", "HCRYPTKEY", (uint64_t)key, {}, ""}
        };
        LogTelemetry("CryptDeriveKey", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptGenKey_t)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
static CryptGenKey_t pfnCryptGenKey = nullptr;
static BOOL WINAPI Detour_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    HookGuard guard;
    BOOL res = pfnCryptGenKey(hProv, Algid, dwFlags, phKey);
    if (!guard.WasInside()) {
        HCRYPTKEY key = (res && phKey) ? *phKey : 0;
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)hProv, {}, ""},
            {"Algid", "ALG_ID", (uint64_t)Algid, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"hKey", "HCRYPTKEY", (uint64_t)key, {}, ""}
        };
        LogTelemetry("CryptGenKey", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptGenRandom_t)(HCRYPTPROV, DWORD, BYTE*);
static CryptGenRandom_t pfnCryptGenRandom = nullptr;
static BOOL WINAPI Detour_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    HookGuard guard;
    BOOL res = pfnCryptGenRandom(hProv, dwLen, pbBuffer);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hProv", "HCRYPTPROV", (uint64_t)hProv, {}, ""},
            {"dwLen", "DWORD", (uint64_t)dwLen, {}, ""},
            {"pbBuffer", "BYTE*", (uint64_t)pbBuffer, ReadBufferSafe(pbBuffer, res ? dwLen : 0), ""}
        };
        LogTelemetry("CryptGenRandom", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptEncrypt_t)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
static CryptEncrypt_t pfnCryptEncrypt = nullptr;
static BOOL WINAPI Detour_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    DWORD beforeLen = 0;
    if (pdwDataLen) SafeCopyBuffer(&beforeLen, pdwDataLen, sizeof(beforeLen));
    std::vector<uint8_t> before = ReadBufferSafe(pbData, beforeLen);
    HookGuard guard;
    BOOL res = pfnCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    if (!guard.WasInside()) {
        DWORD afterLen = 0;
        if (pdwDataLen) SafeCopyBuffer(&afterLen, pdwDataLen, sizeof(afterLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "HCRYPTKEY", (uint64_t)hKey, {}, ""},
            {"hHash", "HCRYPTHASH", (uint64_t)hHash, {}, ""},
            {"Final", "BOOL", (uint64_t)Final, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"pbDataBefore", "BYTE*", (uint64_t)pbData, before, ""},
            {"pbData", "BYTE*", (uint64_t)pbData, ReadBufferSafe(pbData, res ? afterLen : beforeLen), ""},
            {"dwDataLenBefore", "DWORD", (uint64_t)beforeLen, {}, ""},
            {"dwDataLen", "DWORD", (uint64_t)afterLen, {}, ""},
            {"dwBufLen", "DWORD", (uint64_t)dwBufLen, {}, ""}
        };
        LogTelemetry("CryptEncrypt", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptDecrypt_t)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
static CryptDecrypt_t pfnCryptDecrypt = nullptr;
static BOOL WINAPI Detour_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    DWORD beforeLen = 0;
    if (pdwDataLen) SafeCopyBuffer(&beforeLen, pdwDataLen, sizeof(beforeLen));
    std::vector<uint8_t> before = ReadBufferSafe(pbData, beforeLen);
    HookGuard guard;
    BOOL res = pfnCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    if (!guard.WasInside()) {
        DWORD afterLen = 0;
        if (pdwDataLen) SafeCopyBuffer(&afterLen, pdwDataLen, sizeof(afterLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "HCRYPTKEY", (uint64_t)hKey, {}, ""},
            {"hHash", "HCRYPTHASH", (uint64_t)hHash, {}, ""},
            {"Final", "BOOL", (uint64_t)Final, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"pbDataBefore", "BYTE*", (uint64_t)pbData, before, ""},
            {"pbData", "BYTE*", (uint64_t)pbData, ReadBufferSafe(pbData, res ? afterLen : beforeLen), ""},
            {"dwDataLenBefore", "DWORD", (uint64_t)beforeLen, {}, ""},
            {"dwDataLen", "DWORD", (uint64_t)afterLen, {}, ""}
        };
        LogTelemetry("CryptDecrypt", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptDestroyHash_t)(HCRYPTHASH);
static CryptDestroyHash_t pfnCryptDestroyHash = nullptr;
static BOOL WINAPI Detour_CryptDestroyHash(HCRYPTHASH hHash) {
    HookGuard guard;
    BOOL res = pfnCryptDestroyHash(hHash);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hHash", "HCRYPTHASH", (uint64_t)hHash, {}, ""} };
        LogTelemetry("CryptDestroyHash", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef BOOL(WINAPI* CryptDestroyKey_t)(HCRYPTKEY);
static CryptDestroyKey_t pfnCryptDestroyKey = nullptr;
static BOOL WINAPI Detour_CryptDestroyKey(HCRYPTKEY hKey) {
    HookGuard guard;
    BOOL res = pfnCryptDestroyKey(hKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "HCRYPTKEY", (uint64_t)hKey, {}, ""} };
        LogTelemetry("CryptDestroyKey", "advapi32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
static BCryptOpenAlgorithmProvider_t pfnBCryptOpenAlgorithmProvider = nullptr;
static NTSTATUS WINAPI Detour_BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
    if (!guard.WasInside()) {
        BCRYPT_ALG_HANDLE alg = (res >= 0 && phAlgorithm) ? *phAlgorithm : nullptr;
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)alg, {}, ""},
            {"pszAlgId", "LPCWSTR", (uint64_t)pszAlgId, {}, WideToUtf8(ReadWStringSafe(pszAlgId))},
            {"pszImplementation", "LPCWSTR", (uint64_t)pszImplementation, {}, WideToUtf8(ReadWStringSafe(pszImplementation))},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptOpenAlgorithmProvider", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
static BCryptGenerateSymmetricKey_t pfnBCryptGenerateSymmetricKey = nullptr;
static NTSTATUS WINAPI Detour_BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptGenerateSymmetricKey(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);
    if (!guard.WasInside()) {
        BCRYPT_KEY_HANDLE key = (res >= 0 && phKey) ? *phKey : nullptr;
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)hAlgorithm, {}, ""},
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)key, {}, ""},
            {"pbSecret", "PUCHAR", (uint64_t)pbSecret, ReadBufferSafe(pbSecret, cbSecret), ""},
            {"cbSecret", "ULONG", (uint64_t)cbSecret, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptGenerateSymmetricKey", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptCreateHash_t)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
static BCryptCreateHash_t pfnBCryptCreateHash = nullptr;
static NTSTATUS WINAPI Detour_BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptCreateHash(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
    if (!guard.WasInside()) {
        BCRYPT_HASH_HANDLE hash = (res >= 0 && phHash) ? *phHash : nullptr;
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)hAlgorithm, {}, ""},
            {"hHash", "BCRYPT_HASH_HANDLE", (uint64_t)hash, {}, ""},
            {"pbSecret", "PUCHAR", (uint64_t)pbSecret, ReadBufferSafe(pbSecret, cbSecret), ""},
            {"cbSecret", "ULONG", (uint64_t)cbSecret, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptCreateHash", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptHashData_t)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
static BCryptHashData_t pfnBCryptHashData = nullptr;
static NTSTATUS WINAPI Detour_BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptHashData(hHash, pbInput, cbInput, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hHash", "BCRYPT_HASH_HANDLE", (uint64_t)hHash, {}, ""},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptHashData", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptFinishHash_t)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
static BCryptFinishHash_t pfnBCryptFinishHash = nullptr;
static NTSTATUS WINAPI Detour_BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hHash", "BCRYPT_HASH_HANDLE", (uint64_t)hHash, {}, ""},
            {"pbOutput", "PUCHAR", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res >= 0 ? cbOutput : 0), ""},
            {"cbOutput", "ULONG", (uint64_t)cbOutput, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptFinishHash", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptEncrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
static BCryptEncrypt_t pfnBCryptEncrypt = nullptr;
static NTSTATUS WINAPI Detour_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        ULONG resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"pbIV", "PUCHAR", (uint64_t)pbIV, ReadBufferSafe(pbIV, cbIV), ""},
            {"cbIV", "ULONG", (uint64_t)cbIV, {}, ""},
            {"pbOutput", "PUCHAR", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res >= 0 ? resultLen : 0), ""},
            {"cbOutput", "ULONG", (uint64_t)cbOutput, {}, ""},
            {"pcbResult", "ULONG", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptEncrypt", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptDecrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
static BCryptDecrypt_t pfnBCryptDecrypt = nullptr;
static NTSTATUS WINAPI Detour_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        ULONG resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"pbIV", "PUCHAR", (uint64_t)pbIV, ReadBufferSafe(pbIV, cbIV), ""},
            {"cbIV", "ULONG", (uint64_t)cbIV, {}, ""},
            {"pbOutput", "PUCHAR", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res >= 0 ? resultLen : 0), ""},
            {"cbOutput", "ULONG", (uint64_t)cbOutput, {}, ""},
            {"pcbResult", "ULONG", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptDecrypt", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptGenRandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
static BCryptGenRandom_t pfnBCryptGenRandom = nullptr;
static NTSTATUS WINAPI Detour_BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)hAlgorithm, {}, ""},
            {"pbBuffer", "PUCHAR", (uint64_t)pbBuffer, ReadBufferSafe(pbBuffer, res >= 0 ? cbBuffer : 0), ""},
            {"cbBuffer", "ULONG", (uint64_t)cbBuffer, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptGenRandom", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef NTSTATUS(WINAPI* BCryptDeriveKeyPBKDF2_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, ULONGLONG, PUCHAR, ULONG, ULONG);
static BCryptDeriveKeyPBKDF2_t pfnBCryptDeriveKeyPBKDF2 = nullptr;
static NTSTATUS WINAPI Detour_BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptDeriveKeyPBKDF2(hPrf, pbPassword, cbPassword, pbSalt, cbSalt, cIterations, pbDerivedKey, cbDerivedKey, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hPrf", "BCRYPT_ALG_HANDLE", (uint64_t)hPrf, {}, ""},
            {"pbPassword", "PUCHAR", (uint64_t)pbPassword, ReadBufferSafe(pbPassword, cbPassword), ""},
            {"cbPassword", "ULONG", (uint64_t)cbPassword, {}, ""},
            {"pbSalt", "PUCHAR", (uint64_t)pbSalt, ReadBufferSafe(pbSalt, cbSalt), ""},
            {"cbSalt", "ULONG", (uint64_t)cbSalt, {}, ""},
            {"cIterations", "ULONGLONG", (uint64_t)cIterations, {}, ""},
            {"pbDerivedKey", "PUCHAR", (uint64_t)pbDerivedKey, ReadBufferSafe(pbDerivedKey, res >= 0 ? cbDerivedKey : 0), ""},
            {"cbDerivedKey", "ULONG", (uint64_t)cbDerivedKey, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptDeriveKeyPBKDF2", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef SECURITY_STATUS(WINAPI* NCryptOpenStorageProvider_t)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
static NCryptOpenStorageProvider_t pfnNCryptOpenStorageProvider = nullptr;
static SECURITY_STATUS WINAPI Detour_NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags) {
    HookGuard guard;
    SECURITY_STATUS res = pfnNCryptOpenStorageProvider(phProvider, pszProviderName, dwFlags);
    if (!guard.WasInside()) {
        NCRYPT_PROV_HANDLE prov = (res == 0 && phProvider) ? *phProvider : 0;
        std::vector<ParameterCapture> params = {
            {"hProvider", "NCRYPT_PROV_HANDLE", (uint64_t)prov, {}, ""},
            {"pszProviderName", "LPCWSTR", (uint64_t)pszProviderName, {}, WideToUtf8(ReadWStringSafe(pszProviderName))},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("NCryptOpenStorageProvider", "ncrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef SECURITY_STATUS(WINAPI* NCryptCreatePersistedKey_t)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD);
static NCryptCreatePersistedKey_t pfnNCryptCreatePersistedKey = nullptr;
static SECURITY_STATUS WINAPI Detour_NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags) {
    HookGuard guard;
    SECURITY_STATUS res = pfnNCryptCreatePersistedKey(hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
    if (!guard.WasInside()) {
        NCRYPT_KEY_HANDLE key = (res == 0 && phKey) ? *phKey : 0;
        std::vector<ParameterCapture> params = {
            {"hProvider", "NCRYPT_PROV_HANDLE", (uint64_t)hProvider, {}, ""},
            {"hKey", "NCRYPT_KEY_HANDLE", (uint64_t)key, {}, ""},
            {"pszAlgId", "LPCWSTR", (uint64_t)pszAlgId, {}, WideToUtf8(ReadWStringSafe(pszAlgId))},
            {"pszKeyName", "LPCWSTR", (uint64_t)pszKeyName, {}, WideToUtf8(ReadWStringSafe(pszKeyName))},
            {"dwLegacyKeySpec", "DWORD", (uint64_t)dwLegacyKeySpec, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("NCryptCreatePersistedKey", "ncrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef SECURITY_STATUS(WINAPI* NCryptEncrypt_t)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
static NCryptEncrypt_t pfnNCryptEncrypt = nullptr;
static SECURITY_STATUS WINAPI Detour_NCryptEncrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    HookGuard guard;
    SECURITY_STATUS res = pfnNCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        DWORD resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "NCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbInput", "PBYTE", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "DWORD", (uint64_t)cbInput, {}, ""},
            {"pbOutput", "PBYTE", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res == 0 ? resultLen : 0), ""},
            {"cbOutput", "DWORD", (uint64_t)cbOutput, {}, ""},
            {"pcbResult", "DWORD", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("NCryptEncrypt", "ncrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef SECURITY_STATUS(WINAPI* NCryptDecrypt_t)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
static NCryptDecrypt_t pfnNCryptDecrypt = nullptr;
static SECURITY_STATUS WINAPI Detour_NCryptDecrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    HookGuard guard;
    SECURITY_STATUS res = pfnNCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        DWORD resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "NCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbInput", "PBYTE", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "DWORD", (uint64_t)cbInput, {}, ""},
            {"pbOutput", "PBYTE", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res == 0 ? resultLen : 0), ""},
            {"cbOutput", "DWORD", (uint64_t)cbOutput, {}, ""},
            {"pcbResult", "DWORD", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("NCryptDecrypt", "ncrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

typedef HCERTSTORE(WINAPI* CertOpenStore_t)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
static CertOpenStore_t pfnCertOpenStore = nullptr;
static HCERTSTORE WINAPI Detour_CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void* pvPara) {
    HookGuard guard;
    HCERTSTORE res = pfnCertOpenStore(lpszStoreProvider, dwEncodingType, hCryptProv, dwFlags, pvPara);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"lpszStoreProvider", "LPCSTR", (uint64_t)lpszStoreProvider, {}, ReadAStringSafe(lpszStoreProvider)},
            {"dwEncodingType", "DWORD", (uint64_t)dwEncodingType, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""},
            {"pvPara", "void*", (uint64_t)pvPara, {}, ""}
        };
        LogTelemetry("CertOpenStore", "crypt32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef PCCERT_CONTEXT(WINAPI* CertFindCertificateInStore_t)(HCERTSTORE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT);
static CertFindCertificateInStore_t pfnCertFindCertificateInStore = nullptr;
static PCCERT_CONTEXT WINAPI Detour_CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT pPrevCertContext) {
    HookGuard guard;
    PCCERT_CONTEXT res = pfnCertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hCertStore", "HCERTSTORE", (uint64_t)hCertStore, {}, ""},
            {"dwCertEncodingType", "DWORD", (uint64_t)dwCertEncodingType, {}, ""},
            {"dwFindFlags", "DWORD", (uint64_t)dwFindFlags, {}, ""},
            {"dwFindType", "DWORD", (uint64_t)dwFindType, {}, ""},
            {"pvFindPara", "void*", (uint64_t)pvFindPara, {}, ""},
            {"pCertContext", "PCCERT_CONTEXT", (uint64_t)res, {}, ""}
        };
        LogTelemetry("CertFindCertificateInStore", "crypt32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

typedef HCERTSTORE(WINAPI* PFXImportCertStore_t)(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
static PFXImportCertStore_t pfnPFXImportCertStore = nullptr;
static HCERTSTORE WINAPI Detour_PFXImportCertStore(CRYPT_DATA_BLOB* pPFX, LPCWSTR szPassword, DWORD dwFlags) {
    HookGuard guard;
    HCERTSTORE res = pfnPFXImportCertStore(pPFX, szPassword, dwFlags);
    if (!guard.WasInside()) {
        DWORD cbData = 0;
        BYTE* pbData = nullptr;
        if (pPFX) {
            CRYPT_DATA_BLOB blob {};
            if (SafeCopyBuffer(&blob, pPFX, sizeof(blob))) {
                cbData = blob.cbData;
                pbData = blob.pbData;
            }
        }
        std::vector<ParameterCapture> params = {
            {"pPFX", "CRYPT_DATA_BLOB*", (uint64_t)pPFX, ReadBufferSafe(pbData, cbData), ""},
            {"cbData", "DWORD", (uint64_t)cbData, {}, ""},
            {"szPassword", "LPCWSTR", (uint64_t)szPassword, {}, szPassword ? "<provided>" : ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("PFXImportCertStore", "crypt32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// ----------------------------------------------------
// EXTENDED CRYPTO HOOKS
// ----------------------------------------------------

// BCryptImportKey — tracks external key material being loaded (e.g. embedded hardcoded keys)
typedef NTSTATUS(WINAPI* BCryptImportKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
static BCryptImportKey_t pfnBCryptImportKey = nullptr;
static NTSTATUS WINAPI Detour_BCryptImportKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptImportKey(hAlgorithm, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
    if (!guard.WasInside()) {
        BCRYPT_KEY_HANDLE key = (res >= 0 && phKey) ? *phKey : nullptr;
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)hAlgorithm, {}, ""},
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)key, {}, ""},
            {"pszBlobType", "LPCWSTR", (uint64_t)pszBlobType, {}, WideToUtf8(ReadWStringSafe(pszBlobType))},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptImportKey", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptImportKeyPair — tracks asymmetric public/private key import (EC, RSA)
typedef NTSTATUS(WINAPI* BCryptImportKeyPair_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG);
static BCryptImportKeyPair_t pfnBCryptImportKeyPair = nullptr;
static NTSTATUS WINAPI Detour_BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptImportKeyPair(hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags);
    if (!guard.WasInside()) {
        BCRYPT_KEY_HANDLE key = (res >= 0 && phKey) ? *phKey : nullptr;
        std::vector<ParameterCapture> params = {
            {"hAlgorithm", "BCRYPT_ALG_HANDLE", (uint64_t)hAlgorithm, {}, ""},
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)key, {}, ""},
            {"pszBlobType", "LPCWSTR", (uint64_t)pszBlobType, {}, WideToUtf8(ReadWStringSafe(pszBlobType))},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptImportKeyPair", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptSignHash — digital signature creation (code signing bypass, data authentication)
typedef NTSTATUS(WINAPI* BCryptSignHash_t)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
static BCryptSignHash_t pfnBCryptSignHash = nullptr;
static NTSTATUS WINAPI Detour_BCryptSignHash(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptSignHash(hKey, pPaddingInfo, pbInput, cbInput, pbOutput, cbOutput, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        ULONG resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbInput", "PUCHAR", (uint64_t)pbInput, ReadBufferSafe(pbInput, cbInput), ""},
            {"cbInput", "ULONG", (uint64_t)cbInput, {}, ""},
            {"pbOutput", "PUCHAR", (uint64_t)pbOutput, ReadBufferSafe(pbOutput, res >= 0 ? resultLen : 0), ""},
            {"pcbResult", "ULONG", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptSignHash", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptVerifySignature — signature verification (integrity checking bypass, tamper detection evasion)
typedef NTSTATUS(WINAPI* BCryptVerifySignature_t)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
static BCryptVerifySignature_t pfnBCryptVerifySignature = nullptr;
static NTSTATUS WINAPI Detour_BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptVerifySignature(hKey, pPaddingInfo, pbHash, cbHash, pbSignature, cbSignature, dwFlags);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""},
            {"pbHash", "PUCHAR", (uint64_t)pbHash, ReadBufferSafe(pbHash, cbHash), ""},
            {"cbHash", "ULONG", (uint64_t)cbHash, {}, ""},
            {"pbSignature", "PUCHAR", (uint64_t)pbSignature, ReadBufferSafe(pbSignature, cbSignature), ""},
            {"cbSignature", "ULONG", (uint64_t)cbSignature, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""},
            {"result", "NTSTATUS", (uint64_t)(uint32_t)res, {}, res >= 0 ? "VALID" : "INVALID"}
        };
        LogTelemetry("BCryptVerifySignature", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptDeriveKey — SP800-108, TLS PRF, ECDH key agreement derivation
typedef NTSTATUS(WINAPI* BCryptDeriveKey_t)(BCRYPT_SECRET_HANDLE, LPCWSTR, BCryptBufferDesc*, PUCHAR, ULONG, ULONG*, ULONG);
static BCryptDeriveKey_t pfnBCryptDeriveKey = nullptr;
static NTSTATUS WINAPI Detour_BCryptDeriveKey(BCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, BCryptBufferDesc* pParameterList, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG* pcbResult, ULONG dwFlags) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptDeriveKey(hSharedSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags);
    if (!guard.WasInside()) {
        ULONG resultLen = 0;
        if (pcbResult) SafeCopyBuffer(&resultLen, pcbResult, sizeof(resultLen));
        std::vector<ParameterCapture> params = {
            {"hSharedSecret", "BCRYPT_SECRET_HANDLE", (uint64_t)hSharedSecret, {}, ""},
            {"pwszKDF", "LPCWSTR", (uint64_t)pwszKDF, {}, WideToUtf8(ReadWStringSafe(pwszKDF))},
            {"pbDerivedKey", "PUCHAR", (uint64_t)pbDerivedKey, ReadBufferSafe(pbDerivedKey, res >= 0 ? resultLen : 0), ""},
            {"cbDerivedKey", "ULONG", (uint64_t)cbDerivedKey, {}, ""},
            {"pcbResult", "ULONG", (uint64_t)resultLen, {}, ""},
            {"dwFlags", "ULONG", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("BCryptDeriveKey", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptDestroyKey — key handle lifecycle end
typedef NTSTATUS(WINAPI* BCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
static BCryptDestroyKey_t pfnBCryptDestroyKey = nullptr;
static NTSTATUS WINAPI Detour_BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptDestroyKey(hKey);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hKey", "BCRYPT_KEY_HANDLE", (uint64_t)hKey, {}, ""} };
        LogTelemetry("BCryptDestroyKey", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// BCryptDestroyHash — hash handle lifecycle end
typedef NTSTATUS(WINAPI* BCryptDestroyHash_t)(BCRYPT_HASH_HANDLE);
static BCryptDestroyHash_t pfnBCryptDestroyHash = nullptr;
static NTSTATUS WINAPI Detour_BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash) {
    HookGuard guard;
    NTSTATUS res = pfnBCryptDestroyHash(hHash);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = { {"hHash", "BCRYPT_HASH_HANDLE", (uint64_t)hHash, {}, ""} };
        LogTelemetry("BCryptDestroyHash", "bcrypt.dll", _ReturnAddress(), (uint64_t)(uint32_t)res, params);
    }
    return res;
}

// CryptProtectData — DPAPI encryption (credential/secrets sealing)
typedef BOOL(WINAPI* CryptProtectData_t)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
static CryptProtectData_t pfnCryptProtectData = nullptr;
static BOOL WINAPI Detour_CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
    HookGuard guard;
    DWORD cbIn = 0; BYTE* pbIn = nullptr;
    if (!guard.WasInside() && pDataIn) {
        DATA_BLOB tmp{}; if (SafeCopyBuffer(&tmp, pDataIn, sizeof(tmp))) { cbIn = tmp.cbData; pbIn = tmp.pbData; }
    }
    BOOL res = pfnCryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
    if (!guard.WasInside()) {
        DWORD cbOut = 0; BYTE* pbOut = nullptr;
        if (pDataOut && res) { DATA_BLOB tmp{}; if (SafeCopyBuffer(&tmp, pDataOut, sizeof(tmp))) { cbOut = tmp.cbData; pbOut = tmp.pbData; } }
        std::vector<ParameterCapture> params = {
            {"pDataIn", "DATA_BLOB*", (uint64_t)pbIn, ReadBufferSafe(pbIn, cbIn), ""},
            {"cbIn", "DWORD", (uint64_t)cbIn, {}, ""},
            {"szDataDescr", "LPCWSTR", (uint64_t)szDataDescr, {}, szDataDescr ? WideToUtf8(ReadWStringSafe(szDataDescr)) : ""},
            {"pDataOut", "DATA_BLOB*", (uint64_t)pbOut, ReadBufferSafe(pbOut, cbOut), ""},
            {"cbOut", "DWORD", (uint64_t)cbOut, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("CryptProtectData", "crypt32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// CryptUnprotectData — DPAPI decryption (credential/secrets unsealing; high-value theft indicator)
typedef BOOL(WINAPI* CryptUnprotectData_t)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
static CryptUnprotectData_t pfnCryptUnprotectData = nullptr;
static BOOL WINAPI Detour_CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
    HookGuard guard;
    DWORD cbIn = 0; BYTE* pbIn = nullptr;
    if (!guard.WasInside() && pDataIn) {
        DATA_BLOB tmp{}; if (SafeCopyBuffer(&tmp, pDataIn, sizeof(tmp))) { cbIn = tmp.cbData; pbIn = tmp.pbData; }
    }
    BOOL res = pfnCryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
    if (!guard.WasInside()) {
        DWORD cbOut = 0; BYTE* pbOut = nullptr;
        if (pDataOut && res) { DATA_BLOB tmp{}; if (SafeCopyBuffer(&tmp, pDataOut, sizeof(tmp))) { cbOut = tmp.cbData; pbOut = tmp.pbData; } }
        std::wstring descr;
        if (ppszDataDescr && *ppszDataDescr) descr = ReadWStringSafe(*ppszDataDescr);
        std::vector<ParameterCapture> params = {
            {"pDataIn", "DATA_BLOB*", (uint64_t)pbIn, ReadBufferSafe(pbIn, cbIn), ""},
            {"cbIn", "DWORD", (uint64_t)cbIn, {}, ""},
            {"szDataDescr", "LPCWSTR", 0, {}, WideToUtf8(descr)},
            {"pDataOut", "DATA_BLOB*", (uint64_t)pbOut, ReadBufferSafe(pbOut, cbOut), "Decrypted plaintext"},
            {"cbOut", "DWORD", (uint64_t)cbOut, {}, ""},
            {"dwFlags", "DWORD", (uint64_t)dwFlags, {}, ""}
        };
        LogTelemetry("CryptUnprotectData", "crypt32.dll", _ReturnAddress(), (uint64_t)res, params);
    }
    return res;
}

// ----------------------------------------------------
// PLAINTEXT NETWORK LAYER HOOKS
// ----------------------------------------------------

static std::vector<uint8_t> CaptureSecBufferData(PSecBufferDesc descriptor) {
    constexpr size_t kMaximumCapture = 64u * 1024u;
    std::vector<uint8_t> captured;
    if (!descriptor) return captured;
    SecBufferDesc localDescriptor{};
    if (!SafeCopyBuffer(&localDescriptor, descriptor, sizeof(localDescriptor)) ||
        !localDescriptor.pBuffers || localDescriptor.cBuffers == 0) return captured;
    const ULONG count = (std::min)(localDescriptor.cBuffers, 64ul);
    for (ULONG i = 0; i < count && captured.size() < kMaximumCapture; ++i) {
        SecBuffer buffer{};
        if (!SafeCopyBuffer(&buffer, localDescriptor.pBuffers + i, sizeof(buffer))) continue;
        const ULONG type = buffer.BufferType & ~SECBUFFER_ATTRMASK;
        if (type != SECBUFFER_DATA || !buffer.pvBuffer || buffer.cbBuffer == 0) continue;
        std::vector<uint8_t> part = ReadBufferSafe(buffer.pvBuffer, buffer.cbBuffer, kMaximumCapture - captured.size());
        captured.insert(captured.end(), part.begin(), part.end());
    }
    return captured;
}

typedef SECURITY_STATUS(SEC_ENTRY* EncryptMessage_t)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
static EncryptMessage_t pfnEncryptMessage = nullptr;
static SECURITY_STATUS SEC_ENTRY Detour_EncryptMessage(PCtxtHandle context, ULONG quality, PSecBufferDesc message, ULONG sequence) {
    HookGuard guard;
    std::vector<uint8_t> plaintext;
    if (!guard.WasInside()) plaintext = CaptureSecBufferData(message);
    SECURITY_STATUS result = pfnEncryptMessage(context, quality, message, sequence);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"hContext", "PCtxtHandle", (uint64_t)context, {}, ""},
            {"buf", "Schannel plaintext", plaintext.empty() ? 0 : (uint64_t)plaintext.data(), std::move(plaintext), "Outbound plaintext"},
            {"direction", "string", 0, {}, "Outbound"}
        };
        LogTelemetry("EncryptMessage", "secur32.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, params);
    }
    return result;
}

typedef SECURITY_STATUS(SEC_ENTRY* DecryptMessage_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
static DecryptMessage_t pfnDecryptMessage = nullptr;
static SECURITY_STATUS SEC_ENTRY Detour_DecryptMessage(PCtxtHandle context, PSecBufferDesc message, ULONG sequence, PULONG quality) {
    HookGuard guard;
    SECURITY_STATUS result = pfnDecryptMessage(context, message, sequence, quality);
    if (!guard.WasInside()) {
        std::vector<uint8_t> plaintext = result == SEC_E_OK ? CaptureSecBufferData(message) : std::vector<uint8_t>{};
        std::vector<ParameterCapture> params = {
            {"hContext", "PCtxtHandle", (uint64_t)context, {}, ""},
            {"buf", "Schannel plaintext", plaintext.empty() ? 0 : (uint64_t)plaintext.data(), std::move(plaintext), "Inbound plaintext"},
            {"direction", "string", 0, {}, "Inbound"}
        };
        LogTelemetry("DecryptMessage", "secur32.dll", _ReturnAddress(), (uint64_t)(uint32_t)result, params);
    }
    return result;
}

typedef int(__cdecl* SSL_write_t)(void*, const void*, int);
typedef int(__cdecl* SSL_read_t)(void*, void*, int);
typedef int(__cdecl* SSL_write_ex_t)(void*, const void*, size_t, size_t*);
typedef int(__cdecl* SSL_read_ex_t)(void*, void*, size_t, size_t*);
typedef int(__cdecl* SSL_get_fd_t)(const void*);
static SSL_write_t pfnSSL_write = nullptr;
static SSL_read_t pfnSSL_read = nullptr;
static SSL_write_ex_t pfnSSL_write_ex = nullptr;
static SSL_read_ex_t pfnSSL_read_ex = nullptr;
static SSL_get_fd_t pfnSSL_get_fd = nullptr;
static std::mutex g_OpenSslHookMutex;

static uint64_t OpenSslSocketHandle(void* ssl) {
    if (!ssl || !pfnSSL_get_fd) return 0;
    int socket = pfnSSL_get_fd(ssl);
    return socket >= 0 ? static_cast<uint64_t>(socket) : 0;
}

static int __cdecl Detour_SSL_write(void* ssl, const void* buffer, int bytes) {
    HookGuard guard;
    std::vector<uint8_t> plaintext;
    if (!guard.WasInside()) plaintext = ReadBufferSafe(buffer, bytes > 0 ? (size_t)bytes : 0, 64u * 1024u);
    int result = pfnSSL_write(ssl, buffer, bytes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ssl", "SSL*", (uint64_t)ssl, {}, ""},
            {"s", "SOCKET", OpenSslSocketHandle(ssl), {}, ""},
            {"buf", "OpenSSL plaintext", (uint64_t)buffer, std::move(plaintext), "Outbound plaintext"},
            {"len", "int", (uint64_t)(bytes > 0 ? bytes : 0), {}, ""},
            {"direction", "string", 0, {}, "Outbound"}
        };
        LogTelemetry("SSL_write", "OpenSSL", _ReturnAddress(), (uint64_t)(int64_t)result, params);
    }
    return result;
}

static int __cdecl Detour_SSL_read(void* ssl, void* buffer, int bytes) {
    HookGuard guard;
    int result = pfnSSL_read(ssl, buffer, bytes);
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ssl", "SSL*", (uint64_t)ssl, {}, ""},
            {"s", "SOCKET", OpenSslSocketHandle(ssl), {}, ""},
            {"buf", "OpenSSL plaintext", (uint64_t)buffer, ReadBufferSafe(buffer, result > 0 ? (size_t)result : 0, 64u * 1024u), "Inbound plaintext"},
            {"len", "int", (uint64_t)(result > 0 ? result : 0), {}, ""},
            {"direction", "string", 0, {}, "Inbound"}
        };
        LogTelemetry("SSL_read", "OpenSSL", _ReturnAddress(), (uint64_t)(int64_t)result, params);
    }
    return result;
}

static int __cdecl Detour_SSL_write_ex(void* ssl, const void* buffer, size_t bytes, size_t* written) {
    HookGuard guard;
    std::vector<uint8_t> plaintext;
    if (!guard.WasInside()) plaintext = ReadBufferSafe(buffer, bytes, 64u * 1024u);
    int result = pfnSSL_write_ex(ssl, buffer, bytes, written);
    size_t actual = bytes;
    if (written) SafeCopyBuffer(&actual, written, sizeof(actual));
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ssl", "SSL*", (uint64_t)ssl, {}, ""},
            {"s", "SOCKET", OpenSslSocketHandle(ssl), {}, ""},
            {"buf", "OpenSSL plaintext", (uint64_t)buffer, std::move(plaintext), "Outbound plaintext"},
            {"len", "size_t", (uint64_t)actual, {}, ""},
            {"direction", "string", 0, {}, "Outbound"}
        };
        LogTelemetry("SSL_write_ex", "OpenSSL", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

static int __cdecl Detour_SSL_read_ex(void* ssl, void* buffer, size_t bytes, size_t* read) {
    HookGuard guard;
    int result = pfnSSL_read_ex(ssl, buffer, bytes, read);
    size_t actual = 0;
    if (read) SafeCopyBuffer(&actual, read, sizeof(actual));
    if (!guard.WasInside()) {
        std::vector<ParameterCapture> params = {
            {"ssl", "SSL*", (uint64_t)ssl, {}, ""},
            {"s", "SOCKET", OpenSslSocketHandle(ssl), {}, ""},
            {"buf", "OpenSSL plaintext", (uint64_t)buffer, ReadBufferSafe(buffer, result ? actual : 0, 64u * 1024u), "Inbound plaintext"},
            {"len", "size_t", (uint64_t)(result ? actual : 0), {}, ""},
            {"direction", "string", 0, {}, "Inbound"}
        };
        LogTelemetry("SSL_read_ex", "OpenSSL", _ReturnAddress(), (uint64_t)result, params);
    }
    return result;
}

static void TryInstallOpenSslHooks(HMODULE module) {
    if (!module || !g_HookNetwork) return;
    wchar_t modulePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(module, modulePath, MAX_PATH)) return;
    if (!GetProcAddress(module, "SSL_write") && !GetProcAddress(module, "SSL_write_ex") &&
        !GetProcAddress(module, "SSL_read") && !GetProcAddress(module, "SSL_read_ex")) return;

    std::lock_guard<std::mutex> lock(g_OpenSslHookMutex);
    if (!pfnSSL_get_fd) pfnSSL_get_fd = reinterpret_cast<SSL_get_fd_t>(GetProcAddress(module, "SSL_get_fd"));
    auto install = [&](const char* name, LPVOID detour, LPVOID* original) {
        if (*original) return;
        LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, name));
        if (!target) {
            RecordHookStatus(modulePath, name, "Skipped", "function not exported by loaded OpenSSL module");
            return;
        }
        MH_STATUS status = MH_CreateHook(target, detour, original);
        if (status == MH_OK || status == MH_ERROR_ALREADY_CREATED) {
            RecordHookStatus(modulePath, name, "Hooked", "OpenSSL plaintext capture");
            if (g_HooksActivated.load()) MH_EnableHook(target);
        } else {
            RecordHookStatus(modulePath, name, "Failed", MH_StatusToString(status));
        }
    };
    install("SSL_write", reinterpret_cast<LPVOID>(Detour_SSL_write), reinterpret_cast<LPVOID*>(&pfnSSL_write));
    install("SSL_read", reinterpret_cast<LPVOID>(Detour_SSL_read), reinterpret_cast<LPVOID*>(&pfnSSL_read));
    install("SSL_write_ex", reinterpret_cast<LPVOID>(Detour_SSL_write_ex), reinterpret_cast<LPVOID*>(&pfnSSL_write_ex));
    install("SSL_read_ex", reinterpret_cast<LPVOID>(Detour_SSL_read_ex), reinterpret_cast<LPVOID*>(&pfnSSL_read_ex));
}

static void InstallLoadedOpenSslHooks() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do { TryInstallOpenSslHooks(entry.hModule); } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

// ----------------------------------------------------
// HOOK MANAGER FUNCTIONS
// ----------------------------------------------------

bool InstallHooks() {
    ClearHookStatuses();
    g_HookAttemptIndex = 0;
    g_HookAttemptLimit = 0;
    wchar_t hookLimit[32] = {};
    if (GetEnvironmentVariableW(L"INSPECTHOR_HOOK_LIMIT", hookLimit, (DWORD)(sizeof(hookLimit) / sizeof(hookLimit[0])))) {
        g_HookAttemptLimit = (size_t)_wcstoui64(hookLimit, nullptr, 10);
    }

    if (MH_Initialize() != MH_OK) {
        RecordHookStatus(L"MinHook", "MH_Initialize", "Failed", "MH_Initialize failed");
        return false;
    }

    // Install base Win32 Hooks
    InstallHookApiTracked(L"kernel32.dll", "CreateProcessW", Detour_CreateProcessW, (LPVOID*)&pfnCreateProcessW);
    InstallHookApiTracked(L"kernel32.dll", "CreateProcessA", Detour_CreateProcessA, (LPVOID*)&pfnCreateProcessA);
    InstallHookApiTracked(L"kernel32.dll", "WinExec", Detour_WinExec, (LPVOID*)&pfnWinExec);
    InstallHookApiTracked(L"kernel32.dll", "CreateFileW", Detour_CreateFileW, (LPVOID*)&pfnCreateFileW);
    InstallHookApiTracked(L"kernel32.dll", "CreateFileA", Detour_CreateFileA, (LPVOID*)&pfnCreateFileA);
    InstallHookApiTracked(L"kernel32.dll", "DeleteFileW", Detour_DeleteFileW, (LPVOID*)&pfnDeleteFileW);
    InstallHookApiTracked(L"kernel32.dll", "DeleteFileA", Detour_DeleteFileA, (LPVOID*)&pfnDeleteFileA);
    InstallHookApiTracked(L"kernel32.dll", "CopyFileW", Detour_CopyFileW, (LPVOID*)&pfnCopyFileW);
    InstallHookApiTracked(L"kernel32.dll", "CopyFileA", Detour_CopyFileA, (LPVOID*)&pfnCopyFileA);
    InstallHookApiTracked(L"kernel32.dll", "CopyFileExW", Detour_CopyFileExW, (LPVOID*)&pfnCopyFileExW);
    InstallHookApiTracked(L"kernel32.dll", "CopyFileExA", Detour_CopyFileExA, (LPVOID*)&pfnCopyFileExA);
    InstallHookApiTracked(L"kernel32.dll", "MoveFileW", Detour_MoveFileW, (LPVOID*)&pfnMoveFileW);
    InstallHookApiTracked(L"kernel32.dll", "MoveFileA", Detour_MoveFileA, (LPVOID*)&pfnMoveFileA);
    InstallHookApiTracked(L"kernel32.dll", "MoveFileExW", Detour_MoveFileExW, (LPVOID*)&pfnMoveFileExW);
    InstallHookApiTracked(L"kernel32.dll", "MoveFileExA", Detour_MoveFileExA, (LPVOID*)&pfnMoveFileExA);
    InstallHookApiTracked(L"kernel32.dll", "CreateDirectoryW", Detour_CreateDirectoryW, (LPVOID*)&pfnCreateDirectoryW);
    InstallHookApiTracked(L"kernel32.dll", "CreateDirectoryA", Detour_CreateDirectoryA, (LPVOID*)&pfnCreateDirectoryA);
    InstallHookApiTracked(L"kernel32.dll", "RemoveDirectoryW", Detour_RemoveDirectoryW, (LPVOID*)&pfnRemoveDirectoryW);
    InstallHookApiTracked(L"kernel32.dll", "RemoveDirectoryA", Detour_RemoveDirectoryA, (LPVOID*)&pfnRemoveDirectoryA);
    InstallHookApiTracked(L"kernel32.dll", "ReadFile", Detour_ReadFile, (LPVOID*)&pfnReadFile);
    InstallHookApiTracked(L"kernel32.dll", "ReadFileEx", Detour_ReadFileEx, (LPVOID*)&pfnReadFileEx);
    InstallHookApiTracked(L"kernel32.dll", "WriteFile", Detour_WriteFile, (LPVOID*)&pfnWriteFile);
    InstallHookApiTracked(L"kernel32.dll", "WriteFileEx", Detour_WriteFileEx, (LPVOID*)&pfnWriteFileEx);
    InstallHookApiTracked(L"kernel32.dll", "SetFileInformationByHandle", Detour_SetFileInformationByHandle, (LPVOID*)&pfnSetFileInformationByHandle);
    InstallHookApiTracked(L"kernel32.dll", "SetFilePointerEx", Detour_SetFilePointerEx, (LPVOID*)&pfnSetFilePointerEx);
    InstallHookApiTracked(L"kernel32.dll", "SetEndOfFile", Detour_SetEndOfFile, (LPVOID*)&pfnSetEndOfFile);
    InstallHookApiTracked(L"kernel32.dll", "FlushFileBuffers", Detour_FlushFileBuffers, (LPVOID*)&pfnFlushFileBuffers);
    InstallHookApiTracked(L"kernel32.dll", "GetFileAttributesExW", Detour_GetFileAttributesExW, (LPVOID*)&pfnGetFileAttributesExW);
    InstallHookApiTracked(L"kernel32.dll", "GetFileAttributesExA", Detour_GetFileAttributesExA, (LPVOID*)&pfnGetFileAttributesExA);
    InstallHookApiTracked(L"kernel32.dll", "SetFileAttributesW", Detour_SetFileAttributesW, (LPVOID*)&pfnSetFileAttributesW);
    InstallHookApiTracked(L"kernel32.dll", "SetFileAttributesA", Detour_SetFileAttributesA, (LPVOID*)&pfnSetFileAttributesA);
    InstallHookApiTracked(L"kernel32.dll", "ReplaceFileW", Detour_ReplaceFileW, (LPVOID*)&pfnReplaceFileW);
    InstallHookApiTracked(L"kernel32.dll", "ReplaceFileA", Detour_ReplaceFileA, (LPVOID*)&pfnReplaceFileA);
    InstallHookApiTracked(L"kernel32.dll", "CreateHardLinkW", Detour_CreateHardLinkW, (LPVOID*)&pfnCreateHardLinkW);
    InstallHookApiTracked(L"kernel32.dll", "CreateHardLinkA", Detour_CreateHardLinkA, (LPVOID*)&pfnCreateHardLinkA);
    InstallHookApiTracked(L"kernel32.dll", "CreateSymbolicLinkW", Detour_CreateSymbolicLinkW, (LPVOID*)&pfnCreateSymbolicLinkW);
    InstallHookApiTracked(L"kernel32.dll", "CreateSymbolicLinkA", Detour_CreateSymbolicLinkA, (LPVOID*)&pfnCreateSymbolicLinkA);
    InstallHookApiTracked(L"kernel32.dll", "CloseHandle", Detour_CloseHandle, (LPVOID*)&pfnCloseHandle);
    InstallHookApiTracked(L"kernel32.dll", "CreateMutexW", Detour_CreateMutexW, (LPVOID*)&pfnCreateMutexW);
    InstallHookApiTracked(L"kernel32.dll", "CreateMutexA", Detour_CreateMutexA, (LPVOID*)&pfnCreateMutexA);
    InstallHookApiTracked(L"kernel32.dll", "OpenMutexW", Detour_OpenMutexW, (LPVOID*)&pfnOpenMutexW);
    InstallHookApiTracked(L"kernel32.dll", "OpenMutexA", Detour_OpenMutexA, (LPVOID*)&pfnOpenMutexA);
    InstallHookApiTracked(L"kernel32.dll", "ReleaseMutex", Detour_ReleaseMutex, (LPVOID*)&pfnReleaseMutex);
    InstallHookApiTracked(L"kernel32.dll", "CreateEventW", Detour_CreateEventW, (LPVOID*)&pfnCreateEventW);
    InstallHookApiTracked(L"kernel32.dll", "CreateEventA", Detour_CreateEventA, (LPVOID*)&pfnCreateEventA);
    InstallHookApiTracked(L"kernel32.dll", "OpenEventW", Detour_OpenEventW, (LPVOID*)&pfnOpenEventW);
    InstallHookApiTracked(L"kernel32.dll", "OpenEventA", Detour_OpenEventA, (LPVOID*)&pfnOpenEventA);
    InstallHookApiTracked(L"kernel32.dll", "SetEvent", Detour_SetEvent, (LPVOID*)&pfnSetEvent);
    InstallHookApiTracked(L"kernel32.dll", "ResetEvent", Detour_ResetEvent, (LPVOID*)&pfnResetEvent);
    InstallHookApiTracked(L"kernel32.dll", "CreateSemaphoreW", Detour_CreateSemaphoreW, (LPVOID*)&pfnCreateSemaphoreW);
    InstallHookApiTracked(L"kernel32.dll", "CreateSemaphoreA", Detour_CreateSemaphoreA, (LPVOID*)&pfnCreateSemaphoreA);
    InstallHookApiTracked(L"kernel32.dll", "OpenSemaphoreW", Detour_OpenSemaphoreW, (LPVOID*)&pfnOpenSemaphoreW);
    InstallHookApiTracked(L"kernel32.dll", "OpenSemaphoreA", Detour_OpenSemaphoreA, (LPVOID*)&pfnOpenSemaphoreA);
    InstallHookApiTracked(L"kernel32.dll", "ReleaseSemaphore", Detour_ReleaseSemaphore, (LPVOID*)&pfnReleaseSemaphore);
    InstallHookApiTracked(L"kernel32.dll", "WaitForSingleObject", Detour_WaitForSingleObject, (LPVOID*)&pfnWaitForSingleObject);
    InstallHookApiTracked(L"kernel32.dll", "WaitForMultipleObjects", Detour_WaitForMultipleObjects, (LPVOID*)&pfnWaitForMultipleObjects);
    InstallHookApiTracked(L"kernel32.dll", "WaitForSingleObjectEx", Detour_WaitForSingleObjectEx, (LPVOID*)&pfnWaitForSingleObjectEx);
    InstallHookApiTracked(L"kernel32.dll", "WaitForMultipleObjectsEx", Detour_WaitForMultipleObjectsEx, (LPVOID*)&pfnWaitForMultipleObjectsEx);
    InstallHookApiTracked(L"kernel32.dll", "VirtualAlloc", Detour_VirtualAlloc, (LPVOID*)&pfnVirtualAlloc);
    InstallHookApiTracked(L"kernel32.dll", "VirtualAllocEx", Detour_VirtualAllocEx, (LPVOID*)&pfnVirtualAllocEx);
    InstallHookApiTracked(L"kernel32.dll", "VirtualProtect", Detour_VirtualProtect, (LPVOID*)&pfnVirtualProtect);
    InstallHookApiTracked(L"kernel32.dll", "VirtualFree", Detour_VirtualFree, (LPVOID*)&pfnVirtualFree);
    InstallHookApiTracked(L"kernel32.dll", "VirtualFreeEx", Detour_VirtualFreeEx, (LPVOID*)&pfnVirtualFreeEx);
    InstallHookApiTracked(L"kernel32.dll", "HeapCreate", Detour_HeapCreate, (LPVOID*)&pfnHeapCreate);
    if (g_HookHeap) {
        InstallHookApiTracked(L"kernel32.dll", "HeapAlloc", Detour_HeapAlloc, (LPVOID*)&pfnHeapAlloc);
        InstallHookApiTracked(L"kernel32.dll", "HeapReAlloc", Detour_HeapReAlloc, (LPVOID*)&pfnHeapReAlloc);
        InstallHookApiTracked(L"kernel32.dll", "HeapFree", Detour_HeapFree, (LPVOID*)&pfnHeapFree);
    } else {
        RecordHookStatus(L"kernel32.dll", "HeapAlloc/HeapReAlloc/HeapFree", "Skipped", "disabled by default because allocator hooks can destabilize the target");
    }
    InstallHookApiTracked(L"kernel32.dll", "LocalAlloc", Detour_LocalAlloc, (LPVOID*)&pfnLocalAlloc);
    InstallHookApiTracked(L"kernel32.dll", "LocalFree", Detour_LocalFree, (LPVOID*)&pfnLocalFree);
    InstallHookApiTracked(L"kernel32.dll", "GlobalAlloc", Detour_GlobalAlloc, (LPVOID*)&pfnGlobalAlloc);
    InstallHookApiTracked(L"kernel32.dll", "GlobalFree", Detour_GlobalFree, (LPVOID*)&pfnGlobalFree);
    InstallHookApiTracked(L"kernel32.dll", "VirtualQuery", Detour_VirtualQuery, (LPVOID*)&pfnVirtualQuery);
    InstallHookApiTracked(L"kernel32.dll", "VirtualQueryEx", Detour_VirtualQueryEx, (LPVOID*)&pfnVirtualQueryEx);
    InstallHookApiTracked(L"kernel32.dll", "UnmapViewOfFile", Detour_UnmapViewOfFile, (LPVOID*)&pfnUnmapViewOfFile);
    InstallHookApiTracked(L"kernel32.dll", "WriteProcessMemory", Detour_WriteProcessMemory, (LPVOID*)&pfnWriteProcessMemory);
    InstallHookApiTracked(L"kernel32.dll", "OpenProcess", Detour_OpenProcess, (LPVOID*)&pfnOpenProcess);
    InstallHookApiTracked(L"kernel32.dll", "TerminateProcess", Detour_TerminateProcess, (LPVOID*)&pfnTerminateProcess);
    InstallHookApiTracked(L"kernel32.dll", "ExitProcess", Detour_ExitProcess, (LPVOID*)&pfnExitProcess);
    InstallHookApiTracked(L"kernel32.dll", "QueryFullProcessImageNameW", Detour_QueryFullProcessImageNameW, (LPVOID*)&pfnQueryFullProcessImageNameW);
    InstallHookApiTracked(L"kernel32.dll", "QueryFullProcessImageNameA", Detour_QueryFullProcessImageNameA, (LPVOID*)&pfnQueryFullProcessImageNameA);
    InstallHookApiTracked(L"kernel32.dll", "GetProcessId", Detour_GetProcessId, (LPVOID*)&pfnGetProcessId);
    InstallHookApiTracked(L"kernel32.dll", "GetEnvironmentVariableW", Detour_GetEnvironmentVariableW, (LPVOID*)&pfnGetEnvironmentVariableW);
    InstallHookApiTracked(L"kernel32.dll", "GetEnvironmentVariableA", Detour_GetEnvironmentVariableA, (LPVOID*)&pfnGetEnvironmentVariableA);
    InstallHookApiTracked(L"kernel32.dll", "SetEnvironmentVariableW", Detour_SetEnvironmentVariableW, (LPVOID*)&pfnSetEnvironmentVariableW);
    InstallHookApiTracked(L"kernel32.dll", "SetEnvironmentVariableA", Detour_SetEnvironmentVariableA, (LPVOID*)&pfnSetEnvironmentVariableA);
    InstallHookApiTracked(L"kernel32.dll", "ExpandEnvironmentStringsW", Detour_ExpandEnvironmentStringsW, (LPVOID*)&pfnExpandEnvironmentStringsW);
    InstallHookApiTracked(L"kernel32.dll", "ExpandEnvironmentStringsA", Detour_ExpandEnvironmentStringsA, (LPVOID*)&pfnExpandEnvironmentStringsA);
    InstallHookApiTracked(L"kernel32.dll", "GetCurrentProcess", Detour_GetCurrentProcess, (LPVOID*)&pfnGetCurrentProcess);
    InstallHookApiTracked(L"kernel32.dll", "GetCurrentProcessId", Detour_GetCurrentProcessId, (LPVOID*)&pfnGetCurrentProcessId);
    InstallHookApiTracked(L"kernel32.dll", "GetCommandLineW", Detour_GetCommandLineW, (LPVOID*)&pfnGetCommandLineW);
    InstallHookApiTracked(L"kernel32.dll", "GetCommandLineA", Detour_GetCommandLineA, (LPVOID*)&pfnGetCommandLineA);
    InstallHookApiTracked(L"kernel32.dll", "GetCurrentDirectoryW", Detour_GetCurrentDirectoryW, (LPVOID*)&pfnGetCurrentDirectoryW);
    InstallHookApiTracked(L"kernel32.dll", "GetCurrentDirectoryA", Detour_GetCurrentDirectoryA, (LPVOID*)&pfnGetCurrentDirectoryA);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleFileNameW", Detour_GetModuleFileNameW, (LPVOID*)&pfnGetModuleFileNameW);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleFileNameA", Detour_GetModuleFileNameA, (LPVOID*)&pfnGetModuleFileNameA);
    InstallHookApiTracked(L"kernel32.dll", "LoadLibraryW", Detour_LoadLibraryW, (LPVOID*)&pfnLoadLibraryW);
    InstallHookApiTracked(L"kernel32.dll", "LoadLibraryA", Detour_LoadLibraryA, (LPVOID*)&pfnLoadLibraryA);
    InstallHookApiTracked(L"kernel32.dll", "LoadLibraryExW", Detour_LoadLibraryExW, (LPVOID*)&pfnLoadLibraryExW);
    InstallHookApiTracked(L"kernel32.dll", "LoadLibraryExA", Detour_LoadLibraryExA, (LPVOID*)&pfnLoadLibraryExA);
    InstallHookApiTracked(L"kernel32.dll", "LoadPackagedLibrary", Detour_LoadPackagedLibrary, (LPVOID*)&pfnLoadPackagedLibrary);
    InstallHookApiTracked(L"kernel32.dll", "SetDllDirectoryW", Detour_SetDllDirectoryW, (LPVOID*)&pfnSetDllDirectoryW);
    InstallHookApiTracked(L"kernel32.dll", "SetDllDirectoryA", Detour_SetDllDirectoryA, (LPVOID*)&pfnSetDllDirectoryA);
    InstallHookApiTracked(L"kernel32.dll", "SetDefaultDllDirectories", Detour_SetDefaultDllDirectories, (LPVOID*)&pfnSetDefaultDllDirectories);
    InstallHookApiTracked(L"kernel32.dll", "AddDllDirectory", Detour_AddDllDirectory, (LPVOID*)&pfnAddDllDirectory);
    InstallHookApiTracked(L"kernel32.dll", "RemoveDllDirectory", Detour_RemoveDllDirectory, (LPVOID*)&pfnRemoveDllDirectory);
    InstallHookApiTracked(L"kernel32.dll", "GetProcAddress", Detour_GetProcAddress, (LPVOID*)&pfnGetProcAddress);
    InstallHookApiTracked(L"kernel32.dll", "FreeLibrary", Detour_FreeLibrary, (LPVOID*)&pfnFreeLibrary);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleHandleW", Detour_GetModuleHandleW, (LPVOID*)&pfnGetModuleHandleW);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleHandleA", Detour_GetModuleHandleA, (LPVOID*)&pfnGetModuleHandleA);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleHandleExW", Detour_GetModuleHandleExW, (LPVOID*)&pfnGetModuleHandleExW);
    InstallHookApiTracked(L"kernel32.dll", "GetModuleHandleExA", Detour_GetModuleHandleExA, (LPVOID*)&pfnGetModuleHandleExA);
    InstallHookApiTracked(L"kernel32.dll", "CreateThread", Detour_CreateThread, (LPVOID*)&pfnCreateThread);
    InstallHookApiTracked(L"kernel32.dll", "CreateRemoteThread", Detour_CreateRemoteThread, (LPVOID*)&pfnCreateRemoteThread);
    InstallHookApiTracked(L"kernel32.dll", "CreateRemoteThreadEx", Detour_CreateRemoteThreadEx, (LPVOID*)&pfnCreateRemoteThreadEx);
    InstallHookApiTracked(L"kernel32.dll", "IsDebuggerPresent", Detour_IsDebuggerPresent, (LPVOID*)&pfnIsDebuggerPresent);
    InstallHookApiTracked(L"kernel32.dll", "CheckRemoteDebuggerPresent", Detour_CheckRemoteDebuggerPresent, (LPVOID*)&pfnCheckRemoteDebuggerPresent);
    InstallHookApiTracked(L"kernel32.dll", "OutputDebugStringW", Detour_OutputDebugStringW, (LPVOID*)&pfnOutputDebugStringW);
    InstallHookApiTracked(L"kernel32.dll", "OutputDebugStringA", Detour_OutputDebugStringA, (LPVOID*)&pfnOutputDebugStringA);
    InstallHookApiTracked(L"kernel32.dll", "DebugActiveProcess", Detour_DebugActiveProcess, (LPVOID*)&pfnDebugActiveProcess);
    InstallHookApiTracked(L"kernel32.dll", "GetTickCount", Detour_GetTickCount, (LPVOID*)&pfnGetTickCount);
    InstallHookApiTracked(L"kernel32.dll", "GetTickCount64", Detour_GetTickCount64, (LPVOID*)&pfnGetTickCount64);
    InstallHookApiTracked(L"kernel32.dll", "QueryPerformanceCounter", Detour_QueryPerformanceCounter, (LPVOID*)&pfnQueryPerformanceCounter);
    InstallHookApiTracked(L"kernel32.dll", "GetComputerNameW", Detour_GetComputerNameW, (LPVOID*)&pfnGetComputerNameW);
    InstallHookApiTracked(L"kernel32.dll", "GetComputerNameA", Detour_GetComputerNameA, (LPVOID*)&pfnGetComputerNameA);
    InstallHookApiTracked(L"kernel32.dll", "GetSystemInfo", Detour_GetSystemInfo, (LPVOID*)&pfnGetSystemInfo);
    InstallHookApiTracked(L"kernel32.dll", "GlobalMemoryStatusEx", Detour_GlobalMemoryStatusEx, (LPVOID*)&pfnGlobalMemoryStatusEx);
    InstallHookApiTracked(L"kernel32.dll", "GetTimeZoneInformation", Detour_GetTimeZoneInformation, (LPVOID*)&pfnGetTimeZoneInformation);
    InstallHookApiTracked(L"kernel32.dll", "GetSystemTime", Detour_GetSystemTime, (LPVOID*)&pfnGetSystemTime);
    InstallHookApiTracked(L"kernel32.dll", "GetLocalTime", Detour_GetLocalTime, (LPVOID*)&pfnGetLocalTime);
    InstallHookApiTracked(L"kernel32.dll", "GetSystemTimeAsFileTime", Detour_GetSystemTimeAsFileTime, (LPVOID*)&pfnGetSystemTimeAsFileTime);
    InstallHookApiTracked(L"kernel32.dll", "GetSystemTimePreciseAsFileTime", Detour_GetSystemTimePreciseAsFileTime, (LPVOID*)&pfnGetSystemTimePreciseAsFileTime);
    InstallHookApiTracked(L"kernel32.dll", "EnumSystemFirmwareTables", Detour_EnumSystemFirmwareTables, (LPVOID*)&pfnEnumSystemFirmwareTables);
    InstallHookApiTracked(L"kernel32.dll", "GetSystemFirmwareTable", Detour_GetSystemFirmwareTable, (LPVOID*)&pfnGetSystemFirmwareTable);
    InstallHookApiTracked(L"kernel32.dll", "AddVectoredExceptionHandler", Detour_AddVectoredExceptionHandler, (LPVOID*)&pfnAddVectoredExceptionHandler);
    InstallHookApiTracked(L"kernel32.dll", "AddVectoredContinueHandler", Detour_AddVectoredContinueHandler, (LPVOID*)&pfnAddVectoredContinueHandler);
    InstallHookApiTracked(L"kernel32.dll", "RemoveVectoredExceptionHandler", Detour_RemoveVectoredExceptionHandler, (LPVOID*)&pfnRemoveVectoredExceptionHandler);
    InstallHookApiTracked(L"kernel32.dll", "CreateTimerQueueTimer", Detour_CreateTimerQueueTimer, (LPVOID*)&pfnCreateTimerQueueTimer);
    InstallHookApiTracked(L"kernel32.dll", "RegisterWaitForSingleObject", Detour_RegisterWaitForSingleObject, (LPVOID*)&pfnRegisterWaitForSingleObject);
    InstallHookApiTracked(L"kernel32.dll", "CreateThreadpoolWork", Detour_CreateThreadpoolWork, (LPVOID*)&pfnCreateThreadpoolWork);
    InstallHookApiTracked(L"kernel32.dll", "SubmitThreadpoolWork", Detour_SubmitThreadpoolWork, (LPVOID*)&pfnSubmitThreadpoolWork);
    InstallHookApiTracked(L"kernel32.dll", "CreateFiber", Detour_CreateFiber, (LPVOID*)&pfnCreateFiber);
    InstallHookApiTracked(L"kernel32.dll", "CreateFiberEx", Detour_CreateFiberEx, (LPVOID*)&pfnCreateFiberEx);
    InstallHookApiTracked(L"kernel32.dll", "FlsAlloc", Detour_FlsAlloc, (LPVOID*)&pfnFlsAlloc);
    InstallHookApiTracked(L"kernel32.dll", "CreateThreadpoolTimer", Detour_CreateThreadpoolTimer, (LPVOID*)&pfnCreateThreadpoolTimer);
    InstallHookApiTracked(L"kernel32.dll", "CreateThreadpoolWait", Detour_CreateThreadpoolWait, (LPVOID*)&pfnCreateThreadpoolWait);
    InstallHookApiTracked(L"kernel32.dll", "SetThreadpoolWait", Detour_SetThreadpoolWait, (LPVOID*)&pfnSetThreadpoolWait);
    InstallHookApiTracked(L"kernel32.dll", "ConvertThreadToFiberEx", Detour_ConvertThreadToFiberEx, (LPVOID*)&pfnConvertThreadToFiberEx);
    InstallHookApiTracked(L"kernel32.dll", "SwitchToFiber", Detour_SwitchToFiber, (LPVOID*)&pfnSwitchToFiber);
    InstallHookApiTracked(L"kernel32.dll", "RaiseException", Detour_RaiseException, (LPVOID*)&pfnRaiseException);
    InstallHookApiTracked(L"kernel32.dll", "CreateToolhelp32Snapshot", Detour_CreateToolhelp32Snapshot, (LPVOID*)&pfnCreateToolhelp32Snapshot);
    InstallHookApiTracked(L"kernel32.dll", "Process32FirstW", Detour_Process32FirstW, (LPVOID*)&pfnProcess32FirstW);
    InstallHookApiTracked(L"kernel32.dll", "Process32NextW", Detour_Process32NextW, (LPVOID*)&pfnProcess32NextW);
    InstallHookApiTracked(L"kernel32.dll", "QueueUserAPC", Detour_QueueUserAPC, (LPVOID*)&pfnQueueUserAPC);
    InstallHookApiTracked(L"kernel32.dll", "SuspendThread", Detour_SuspendThread, (LPVOID*)&pfnSuspendThread);
    InstallHookApiTracked(L"kernel32.dll", "ResumeThread", Detour_ResumeThread, (LPVOID*)&pfnResumeThread);
    InstallHookApiTracked(L"kernel32.dll", "GetThreadContext", Detour_GetThreadContext, (LPVOID*)&pfnGetThreadContext);
    InstallHookApiTracked(L"kernel32.dll", "OpenThread", Detour_OpenThread, (LPVOID*)&pfnOpenThread);
    InstallHookApiTracked(L"kernel32.dll", "DuplicateHandle", Detour_DuplicateHandle, (LPVOID*)&pfnDuplicateHandle);
    InstallHookApiTracked(L"kernel32.dll", "VirtualProtectEx", Detour_VirtualProtectEx, (LPVOID*)&pfnVirtualProtectEx);
    InstallHookApiTracked(L"kernel32.dll", "ReadProcessMemory", Detour_ReadProcessMemory, (LPVOID*)&pfnReadProcessMemory);
    InstallHookApiTracked(L"kernel32.dll", "MapViewOfFile", Detour_MapViewOfFile, (LPVOID*)&pfnMapViewOfFile);
    InstallHookApiTracked(L"kernel32.dll", "MapViewOfFileEx", Detour_MapViewOfFileEx, (LPVOID*)&pfnMapViewOfFileEx);
    InstallHookApiTracked(L"kernel32.dll", "CreateFileMappingW", Detour_CreateFileMappingW, (LPVOID*)&pfnCreateFileMappingW);
    InstallHookApiTracked(L"kernel32.dll", "CreateFileMappingA", Detour_CreateFileMappingA, (LPVOID*)&pfnCreateFileMappingA);
    InstallHookApiTracked(L"kernel32.dll", "OpenFileMappingW", Detour_OpenFileMappingW, (LPVOID*)&pfnOpenFileMappingW);
    InstallHookApiTracked(L"kernel32.dll", "OpenFileMappingA", Detour_OpenFileMappingA, (LPVOID*)&pfnOpenFileMappingA);
    InstallHookApiTracked(L"kernel32.dll", "CreateNamedPipeW", Detour_CreateNamedPipeW, (LPVOID*)&pfnCreateNamedPipeW);
    InstallHookApiTracked(L"kernel32.dll", "CreateNamedPipeA", Detour_CreateNamedPipeA, (LPVOID*)&pfnCreateNamedPipeA);
    InstallHookApiTracked(L"kernel32.dll", "ConnectNamedPipe", Detour_ConnectNamedPipe, (LPVOID*)&pfnConnectNamedPipe);
    InstallHookApiTracked(L"kernel32.dll", "CallNamedPipeW", Detour_CallNamedPipeW, (LPVOID*)&pfnCallNamedPipeW);
    InstallHookApiTracked(L"kernel32.dll", "CallNamedPipeA", Detour_CallNamedPipeA, (LPVOID*)&pfnCallNamedPipeA);
    InstallHookApiTracked(L"kernel32.dll", "WaitNamedPipeW", Detour_WaitNamedPipeW, (LPVOID*)&pfnWaitNamedPipeW);
    InstallHookApiTracked(L"kernel32.dll", "WaitNamedPipeA", Detour_WaitNamedPipeA, (LPVOID*)&pfnWaitNamedPipeA);
    InstallHookApiTracked(L"kernel32.dll", "CreatePipe", Detour_CreatePipe, (LPVOID*)&pfnCreatePipe);
    InstallHookApiTracked(L"kernel32.dll", "PeekNamedPipe", Detour_PeekNamedPipe, (LPVOID*)&pfnPeekNamedPipe);
    InstallHookApiTracked(L"kernel32.dll", "TransactNamedPipe", Detour_TransactNamedPipe, (LPVOID*)&pfnTransactNamedPipe);
    InstallHookApiTracked(L"kernel32.dll", "DisconnectNamedPipe", Detour_DisconnectNamedPipe, (LPVOID*)&pfnDisconnectNamedPipe);
    InstallHookApiTracked(L"kernel32.dll", "GetNamedPipeInfo", Detour_GetNamedPipeInfo, (LPVOID*)&pfnGetNamedPipeInfo);
    InstallHookApiTracked(L"kernel32.dll", "DeviceIoControl", Detour_DeviceIoControl, (LPVOID*)&pfnDeviceIoControl);
    InstallHookApiTracked(L"kernel32.dll", "SetThreadContext", Detour_SetThreadContext, (LPVOID*)&pfnSetThreadContext);

    // Kernel32 exports resolve to their KernelBase implementations on supported
    // Windows versions. Installing the same detour through both modules while
    // sharing one original-function pointer can overwrite the first trampoline
    // and recursively re-enter a detour. Hook each Win32 API once via Kernel32.

    // Avoid hooking allocator/loader-critical NT syscalls. These routines are
    // also used by MinHook and the C++ runtime; instrumenting them from inside
    // the injected DLL can corrupt the target before its entry point runs.
    // Their supported Win32 counterparts above provide the same UI coverage.
    // Read-only process discovery/query entry points are safe enough to monitor
    // and provide coverage when a sample bypasses the Toolhelp/Win32 wrappers.
    InstallHookApiTracked(L"ntdll.dll", "NtQuerySystemInformation", Detour_NtQuerySystemInformation, (LPVOID*)&pfnNtQuerySystemInformation);
    InstallHookApiTracked(L"ntdll.dll", "NtQueryInformationProcess", Detour_NtQueryInformationProcess, (LPVOID*)&pfnNtQueryInformationProcess);
    InstallHookApiTracked(L"ntdll.dll", "NtQueryInformationThread", Detour_NtQueryInformationThread, (LPVOID*)&pfnNtQueryInformationThread);
    InstallHookApiTracked(L"ntdll.dll", "NtOpenProcess", Detour_NtOpenProcess, (LPVOID*)&pfnNtOpenProcess);
    InstallHookApiTracked(L"ntdll.dll", "NtCreateKey", Detour_NtCreateKey, (LPVOID*)&pfnNtCreateKey);
    InstallHookApiTracked(L"ntdll.dll", "NtOpenKey", Detour_NtOpenKey, (LPVOID*)&pfnNtOpenKey);
    InstallHookApiTracked(L"ntdll.dll", "NtDeleteKey", Detour_NtDeleteKey, (LPVOID*)&pfnNtDeleteKey);
    InstallHookApiTracked(L"ntdll.dll", "NtSetValueKey", Detour_NtSetValueKey, (LPVOID*)&pfnNtSetValueKey);
    InstallHookApiTracked(L"ntdll.dll", "NtQueryValueKey", Detour_NtQueryValueKey, (LPVOID*)&pfnNtQueryValueKey);
    InstallHookApiTracked(L"ntdll.dll", "NtDeleteValueKey", Detour_NtDeleteValueKey, (LPVOID*)&pfnNtDeleteValueKey);
    InstallHookApiTracked(L"ntdll.dll", "NtOpenKeyEx", Detour_NtOpenKeyEx, (LPVOID*)&pfnNtOpenKeyEx);
    InstallHookApiTracked(L"ntdll.dll", "NtEnumerateKey", Detour_NtEnumerateKey, (LPVOID*)&pfnNtEnumerateKey);
    InstallHookApiTracked(L"ntdll.dll", "NtEnumerateValueKey", Detour_NtEnumerateValueKey, (LPVOID*)&pfnNtEnumerateValueKey);
    InstallHookApiTracked(L"ntdll.dll", "NtQueryKey", Detour_NtQueryKey, (LPVOID*)&pfnNtQueryKey);
    InstallHookApiTracked(L"ntdll.dll", "NtRenameKey", Detour_NtRenameKey, (LPVOID*)&pfnNtRenameKey);
    InstallHookApiTracked(L"ntdll.dll", "NtClose", Detour_NtCloseRegistryKey, (LPVOID*)&pfnNtCloseRegistryKey);
    InstallHookApiTracked(L"ntdll.dll", "NtCreateFile", Detour_NtCreateFile, (LPVOID*)&pfnNtCreateFile);
    InstallHookApiTracked(L"ntdll.dll", "NtOpenFile", Detour_NtOpenFile, (LPVOID*)&pfnNtOpenFile);
    InstallHookApiTracked(L"ntdll.dll", "NtReadFile", Detour_NtReadFile, (LPVOID*)&pfnNtReadFile);
    InstallHookApiTracked(L"ntdll.dll", "NtWriteFile", Detour_NtWriteFile, (LPVOID*)&pfnNtWriteFile);
    if (g_HookAdvancedNative) InstallHookApiTracked(L"ntdll.dll", "NtDeleteFile", Detour_NtDeleteFile, (LPVOID*)&pfnNtDeleteFile);
    else RecordHookStatus(L"ntdll.dll", "NtDeleteFile", "Skipped", "advanced native hooks disabled for target stability");
    RecordHookStatus(L"ntdll.dll", "NtOpenThread", "Skipped", "native thread-open detour destabilizes process startup; OpenThread telemetry remains active");
    RecordHookStatus(L"ntdll.dll", "NtCreateThreadEx", "Skipped", "native thread-creation detour destabilizes process startup; ETW thread correlation remains active");
    if (g_HookAdvancedNative) {
        InstallHookApiTracked(L"ntdll.dll", "RtlCreateUserThread", Detour_RtlCreateUserThread, (LPVOID*)&pfnRtlCreateUserThread);
        InstallHookApiTracked(L"ntdll.dll", "NtQueueApcThread", Detour_NtQueueApcThread, (LPVOID*)&pfnNtQueueApcThread);
        InstallHookApiTracked(L"ntdll.dll", "NtSetInformationThread", Detour_NtSetInformationThread, (LPVOID*)&pfnNtSetInformationThread);
        InstallHookApiTracked(L"ntdll.dll", "NtTestAlert", Detour_NtTestAlert, (LPVOID*)&pfnNtTestAlert);
    } else {
        RecordHookStatus(L"ntdll.dll", "RtlCreateUserThread/NtQueueApcThread/NtSetInformationThread/NtTestAlert", "Skipped", "advanced native hooks disabled; Win32 and ETW coverage remain active");
    }
    RecordHookStatus(L"ntdll.dll", "NtRaiseException", "Skipped", "native exception-dispatch detour is unsafe; RaiseException telemetry remains active");
    if (g_HookAdvancedNative) {
        InstallHookApiTracked(L"ntdll.dll", "NtAllocateVirtualMemory", Detour_NtAllocateVirtualMemory, (LPVOID*)&pfnNtAllocateVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtProtectVirtualMemory", Detour_NtProtectVirtualMemory, (LPVOID*)&pfnNtProtectVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtFreeVirtualMemory", Detour_NtFreeVirtualMemory, (LPVOID*)&pfnNtFreeVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtReadVirtualMemory", Detour_NtReadVirtualMemory, (LPVOID*)&pfnNtReadVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtWriteVirtualMemory", Detour_NtWriteVirtualMemory, (LPVOID*)&pfnNtWriteVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtQueryVirtualMemory", Detour_NtQueryVirtualMemory, (LPVOID*)&pfnNtQueryVirtualMemory);
        InstallHookApiTracked(L"ntdll.dll", "NtCreateSection", Detour_NtCreateSection, (LPVOID*)&pfnNtCreateSection);
        InstallHookApiTracked(L"ntdll.dll", "NtOpenSection", Detour_NtOpenSection, (LPVOID*)&pfnNtOpenSection);
        InstallHookApiTracked(L"ntdll.dll", "NtMapViewOfSection", Detour_NtMapViewOfSection, (LPVOID*)&pfnNtMapViewOfSection);
        InstallHookApiTracked(L"ntdll.dll", "NtUnmapViewOfSection", Detour_NtUnmapViewOfSection, (LPVOID*)&pfnNtUnmapViewOfSection);
        InstallHookApiTracked(L"ntdll.dll", "LdrLoadDll", Detour_LdrLoadDll, (LPVOID*)&pfnLdrLoadDll);
        InstallHookApiTracked(L"ntdll.dll", "LdrGetProcedureAddress", Detour_LdrGetProcedureAddress, (LPVOID*)&pfnLdrGetProcedureAddress);
        InstallHookApiTracked(L"ntdll.dll", "LdrUnloadDll", Detour_LdrUnloadDll, (LPVOID*)&pfnLdrUnloadDll);
    } else {
        RecordHookStatus(L"ntdll.dll", "Native memory/section/loader hooks", "Skipped", "advanced native hooks disabled; stable Win32 hooks and ETW remain active");
    }
    InstallHookApiTracked(L"ntdll.dll", "NtLoadDriver", Detour_NtLoadDriver, (LPVOID*)&pfnNtLoadDriver);
    InstallHookApiTracked(L"ntdll.dll", "NtUnloadDriver", Detour_NtUnloadDriver, (LPVOID*)&pfnNtUnloadDriver);
    InstallHookApiTracked(L"ntdll.dll", "NtDeviceIoControlFile", Detour_NtDeviceIoControlFile, (LPVOID*)&pfnNtDeviceIoControlFile);
    if (g_HookHeap) {
        InstallHookApiTracked(L"ntdll.dll", "RtlAllocateHeap", Detour_RtlAllocateHeap, (LPVOID*)&pfnRtlAllocateHeap);
        InstallHookApiTracked(L"ntdll.dll", "RtlFreeHeap", Detour_RtlFreeHeap, (LPVOID*)&pfnRtlFreeHeap);
    } else {
        RecordHookStatus(L"ntdll.dll", "RtlAllocateHeap/RtlFreeHeap", "Skipped", "disabled by default because allocator hooks can destabilize the target");
    }
    InstallHookApiTracked(L"ntdll.dll", "RtlCompressBuffer", Detour_RtlCompressBuffer, (LPVOID*)&pfnRtlCompressBuffer);
    InstallHookApiTracked(L"ntdll.dll", "RtlDecompressBuffer", Detour_RtlDecompressBuffer, (LPVOID*)&pfnRtlDecompressBuffer);
    InstallHookApiTracked(L"ntdll.dll", "RtlHashUnicodeString", Detour_RtlHashUnicodeString, (LPVOID*)&pfnRtlHashUnicodeString);
    if (g_HookMemoryCopies) {
        RecordHookStatus(L"ntdll.dll", "RtlMoveMemory", "Skipped", "RtlMoveMemory detour disabled because it destabilizes process startup");
        InstallHookApiTracked(L"ucrtbase.dll", "memcpy", Detour_UcrtMemcpy, (LPVOID*)&pfnUcrtMemcpy);
        RecordHookStatus(L"msvcrt.dll", "memcpy", "Skipped", "CRT memcpy detours disabled because they recursively destabilize the telemetry runtime");
    }

    HMODULE hShell32 = GetModuleHandleW(L"shell32.dll");
    if (!hShell32) hShell32 = LoadLibraryW(L"shell32.dll");
    if (hShell32) {
        InstallHookApiTracked(L"shell32.dll", "ShellExecuteW", Detour_ShellExecuteW, (LPVOID*)&pfnShellExecuteW);
        InstallHookApiTracked(L"shell32.dll", "ShellExecuteA", Detour_ShellExecuteA, (LPVOID*)&pfnShellExecuteA);
        InstallHookApiTracked(L"shell32.dll", "ShellExecuteExW", Detour_ShellExecuteExW, (LPVOID*)&pfnShellExecuteExW);
        InstallHookApiTracked(L"shell32.dll", "ShellExecuteExA", Detour_ShellExecuteExA, (LPVOID*)&pfnShellExecuteExA);
    } else {
        RecordHookStatus(L"shell32.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) hAdvapi32 = LoadLibraryW(L"advapi32.dll");

    InstallHookApiTracked(L"advapi32.dll", "CreateProcessAsUserW", Detour_CreateProcessAsUserW, (LPVOID*)&pfnCreateProcessAsUserW);
    InstallHookApiTracked(L"advapi32.dll", "CreateProcessAsUserA", Detour_CreateProcessAsUserA, (LPVOID*)&pfnCreateProcessAsUserA);
    InstallHookApiTracked(L"advapi32.dll", "OpenProcessToken", Detour_OpenProcessToken, (LPVOID*)&pfnOpenProcessToken);
    InstallHookApiTracked(L"advapi32.dll", "GetTokenInformation", Detour_GetTokenInformation, (LPVOID*)&pfnGetTokenInformation);
    InstallHookApiTracked(L"advapi32.dll", "AdjustTokenPrivileges", Detour_AdjustTokenPrivileges, (LPVOID*)&pfnAdjustTokenPrivileges);
    InstallHookApiTracked(L"advapi32.dll", "CryptAcquireContextW", Detour_CryptAcquireContextW, (LPVOID*)&pfnCryptAcquireContextW);
    InstallHookApiTracked(L"advapi32.dll", "CryptAcquireContextA", Detour_CryptAcquireContextA, (LPVOID*)&pfnCryptAcquireContextA);
    InstallHookApiTracked(L"advapi32.dll", "CryptCreateHash", Detour_CryptCreateHash, (LPVOID*)&pfnCryptCreateHash);
    InstallHookApiTracked(L"advapi32.dll", "CryptHashData", Detour_CryptHashData, (LPVOID*)&pfnCryptHashData);
    InstallHookApiTracked(L"advapi32.dll", "CryptDeriveKey", Detour_CryptDeriveKey, (LPVOID*)&pfnCryptDeriveKey);
    InstallHookApiTracked(L"advapi32.dll", "CryptGenKey", Detour_CryptGenKey, (LPVOID*)&pfnCryptGenKey);
    InstallHookApiTracked(L"advapi32.dll", "CryptGenRandom", Detour_CryptGenRandom, (LPVOID*)&pfnCryptGenRandom);
    InstallHookApiTracked(L"advapi32.dll", "CryptEncrypt", Detour_CryptEncrypt, (LPVOID*)&pfnCryptEncrypt);
    InstallHookApiTracked(L"advapi32.dll", "CryptDecrypt", Detour_CryptDecrypt, (LPVOID*)&pfnCryptDecrypt);
    InstallHookApiTracked(L"advapi32.dll", "CryptDestroyHash", Detour_CryptDestroyHash, (LPVOID*)&pfnCryptDestroyHash);
    InstallHookApiTracked(L"advapi32.dll", "CryptDestroyKey", Detour_CryptDestroyKey, (LPVOID*)&pfnCryptDestroyKey);
    InstallHookApiTracked(L"advapi32.dll", "GetUserNameW", Detour_GetUserNameW, (LPVOID*)&pfnGetUserNameW);
    InstallHookApiTracked(L"advapi32.dll", "GetUserNameA", Detour_GetUserNameA, (LPVOID*)&pfnGetUserNameA);
    InstallHookApiTracked(L"advapi32.dll", "RegOpenKeyW", Detour_RegOpenKeyW, (LPVOID*)&pfnRegOpenKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegOpenKeyA", Detour_RegOpenKeyA, (LPVOID*)&pfnRegOpenKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegOpenKeyExW", Detour_RegOpenKeyExW, (LPVOID*)&pfnRegOpenKeyExW);
    InstallHookApiTracked(L"advapi32.dll", "RegOpenKeyExA", Detour_RegOpenKeyExA, (LPVOID*)&pfnRegOpenKeyExA);
    InstallHookApiTracked(L"advapi32.dll", "RegCreateKeyW", Detour_RegCreateKeyW, (LPVOID*)&pfnRegCreateKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegCreateKeyA", Detour_RegCreateKeyA, (LPVOID*)&pfnRegCreateKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegCreateKeyExW", Detour_RegCreateKeyExW, (LPVOID*)&pfnRegCreateKeyExW);
    InstallHookApiTracked(L"advapi32.dll", "RegCreateKeyExA", Detour_RegCreateKeyExA, (LPVOID*)&pfnRegCreateKeyExA);
    InstallHookApiTracked(L"advapi32.dll", "RegSetValueW", Detour_RegSetValueW, (LPVOID*)&pfnRegSetValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegSetValueA", Detour_RegSetValueA, (LPVOID*)&pfnRegSetValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegSetValueExW", Detour_RegSetValueExW, (LPVOID*)&pfnRegSetValueExW);
    InstallHookApiTracked(L"advapi32.dll", "RegSetValueExA", Detour_RegSetValueExA, (LPVOID*)&pfnRegSetValueExA);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryValueW", Detour_RegQueryValueW, (LPVOID*)&pfnRegQueryValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryValueA", Detour_RegQueryValueA, (LPVOID*)&pfnRegQueryValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryValueExW", Detour_RegQueryValueExW, (LPVOID*)&pfnRegQueryValueExW);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryValueExA", Detour_RegQueryValueExA, (LPVOID*)&pfnRegQueryValueExA);
    InstallHookApiTracked(L"advapi32.dll", "RegGetValueW", Detour_RegGetValueW, (LPVOID*)&pfnRegGetValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegGetValueA", Detour_RegGetValueA, (LPVOID*)&pfnRegGetValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegEnumKeyExW", Detour_RegEnumKeyExW, (LPVOID*)&pfnRegEnumKeyExW);
    InstallHookApiTracked(L"advapi32.dll", "RegEnumKeyExA", Detour_RegEnumKeyExA, (LPVOID*)&pfnRegEnumKeyExA);
    InstallHookApiTracked(L"advapi32.dll", "RegEnumValueW", Detour_RegEnumValueW, (LPVOID*)&pfnRegEnumValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegEnumValueA", Detour_RegEnumValueA, (LPVOID*)&pfnRegEnumValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegRenameKey", Detour_RegRenameKey, (LPVOID*)&pfnRegRenameKey);
    InstallHookApiTracked(L"advapi32.dll", "RegNotifyChangeKeyValue", Detour_RegNotifyChangeKeyValue, (LPVOID*)&pfnRegNotifyChangeKeyValue);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryInfoKeyW", Detour_RegQueryInfoKeyW, (LPVOID*)&pfnRegQueryInfoKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegQueryInfoKeyA", Detour_RegQueryInfoKeyA, (LPVOID*)&pfnRegQueryInfoKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegLoadKeyW", Detour_RegLoadKeyW, (LPVOID*)&pfnRegLoadKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegLoadKeyA", Detour_RegLoadKeyA, (LPVOID*)&pfnRegLoadKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegRestoreKeyW", Detour_RegRestoreKeyW, (LPVOID*)&pfnRegRestoreKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegRestoreKeyA", Detour_RegRestoreKeyA, (LPVOID*)&pfnRegRestoreKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegCopyTreeW", Detour_RegCopyTreeW, (LPVOID*)&pfnRegCopyTreeW);
    InstallHookApiTracked(L"advapi32.dll", "RegCopyTreeA", Detour_RegCopyTreeA, (LPVOID*)&pfnRegCopyTreeA);
    InstallHookApiTracked(L"advapi32.dll", "RegSaveKeyExW", Detour_RegSaveKeyExW, (LPVOID*)&pfnRegSaveKeyExW);
    InstallHookApiTracked(L"advapi32.dll", "RegSaveKeyExA", Detour_RegSaveKeyExA, (LPVOID*)&pfnRegSaveKeyExA);
    InstallHookApiTracked(L"advapi32.dll", "RegUnLoadKeyW", Detour_RegUnLoadKeyW, (LPVOID*)&pfnRegUnLoadKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegUnLoadKeyA", Detour_RegUnLoadKeyA, (LPVOID*)&pfnRegUnLoadKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegFlushKey", Detour_RegFlushKey, (LPVOID*)&pfnRegFlushKey);
    InstallHookApiTracked(L"advapi32.dll", "RegSetKeySecurity", Detour_RegSetKeySecurity, (LPVOID*)&pfnRegSetKeySecurity);
    InstallHookApiTracked(L"advapi32.dll", "RegGetKeySecurity", Detour_RegGetKeySecurity, (LPVOID*)&pfnRegGetKeySecurity);
    InstallHookApiTracked(L"advapi32.dll", "RegCreateKeyTransactedW", Detour_RegCreateKeyTransactedW, (LPVOID*)&pfnRegCreateKeyTransactedW);
    InstallHookApiTracked(L"advapi32.dll", "RegOpenKeyTransactedW", Detour_RegOpenKeyTransactedW, (LPVOID*)&pfnRegOpenKeyTransactedW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyValueW", Detour_RegDeleteKeyValueW, (LPVOID*)&pfnRegDeleteKeyValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyValueA", Detour_RegDeleteKeyValueA, (LPVOID*)&pfnRegDeleteKeyValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegSetKeyValueW", Detour_RegSetKeyValueW, (LPVOID*)&pfnRegSetKeyValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegSetKeyValueA", Detour_RegSetKeyValueA, (LPVOID*)&pfnRegSetKeyValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyW", Detour_RegDeleteKeyW, (LPVOID*)&pfnRegDeleteKeyW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyA", Detour_RegDeleteKeyA, (LPVOID*)&pfnRegDeleteKeyA);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyExW", Detour_RegDeleteKeyExW, (LPVOID*)&pfnRegDeleteKeyExW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteKeyExA", Detour_RegDeleteKeyExA, (LPVOID*)&pfnRegDeleteKeyExA);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteTreeW", Detour_RegDeleteTreeW, (LPVOID*)&pfnRegDeleteTreeW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteTreeA", Detour_RegDeleteTreeA, (LPVOID*)&pfnRegDeleteTreeA);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteValueW", Detour_RegDeleteValueW, (LPVOID*)&pfnRegDeleteValueW);
    InstallHookApiTracked(L"advapi32.dll", "RegDeleteValueA", Detour_RegDeleteValueA, (LPVOID*)&pfnRegDeleteValueA);
    InstallHookApiTracked(L"advapi32.dll", "RegCloseKey", Detour_RegCloseKey, (LPVOID*)&pfnRegCloseKey);
    InstallHookApiTracked(L"advapi32.dll", "OpenSCManagerW", Detour_OpenSCManagerW, (LPVOID*)&pfnOpenSCManagerW);
    InstallHookApiTracked(L"advapi32.dll", "OpenSCManagerA", Detour_OpenSCManagerA, (LPVOID*)&pfnOpenSCManagerA);
    InstallHookApiTracked(L"advapi32.dll", "OpenServiceW", Detour_OpenServiceW, (LPVOID*)&pfnOpenServiceW);
    InstallHookApiTracked(L"advapi32.dll", "OpenServiceA", Detour_OpenServiceA, (LPVOID*)&pfnOpenServiceA);
    InstallHookApiTracked(L"advapi32.dll", "CreateServiceW", Detour_CreateServiceW, (LPVOID*)&pfnCreateServiceW);
    InstallHookApiTracked(L"advapi32.dll", "CreateServiceA", Detour_CreateServiceA, (LPVOID*)&pfnCreateServiceA);
    InstallHookApiTracked(L"advapi32.dll", "ChangeServiceConfigW", Detour_ChangeServiceConfigW, (LPVOID*)&pfnChangeServiceConfigW);
    InstallHookApiTracked(L"advapi32.dll", "ChangeServiceConfigA", Detour_ChangeServiceConfigA, (LPVOID*)&pfnChangeServiceConfigA);
    InstallHookApiTracked(L"advapi32.dll", "ChangeServiceConfig2W", Detour_ChangeServiceConfig2W, (LPVOID*)&pfnChangeServiceConfig2W);
    InstallHookApiTracked(L"advapi32.dll", "ChangeServiceConfig2A", Detour_ChangeServiceConfig2A, (LPVOID*)&pfnChangeServiceConfig2A);
    InstallHookApiTracked(L"advapi32.dll", "StartServiceW", Detour_StartServiceW, (LPVOID*)&pfnStartServiceW);
    InstallHookApiTracked(L"advapi32.dll", "StartServiceA", Detour_StartServiceA, (LPVOID*)&pfnStartServiceA);
    InstallHookApiTracked(L"advapi32.dll", "ControlService", Detour_ControlService, (LPVOID*)&pfnControlService);
    InstallHookApiTracked(L"advapi32.dll", "DeleteService", Detour_DeleteService, (LPVOID*)&pfnDeleteService);
    InstallHookApiTracked(L"advapi32.dll", "CloseServiceHandle", Detour_CloseServiceHandle, (LPVOID*)&pfnCloseServiceHandle);

    // Network hooks are opt-in through TraceConfig so analysts can disable the
    // additional interception surface for samples that are sensitive to hooks.
    if (g_HookNetwork) {
    // Socket Hooks (try loading module if not already loaded)
    HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryW(L"ws2_32.dll");
    if (hWs2) {
        InstallHookApiTracked(L"ws2_32.dll", "socket", Detour_socket, (LPVOID*)&pfnsocket);
        InstallHookApiTracked(L"ws2_32.dll", "bind", Detour_bind, (LPVOID*)&pfnbind);
        InstallHookApiTracked(L"ws2_32.dll", "listen", Detour_listen, (LPVOID*)&pfnlisten);
        InstallHookApiTracked(L"ws2_32.dll", "accept", Detour_accept, (LPVOID*)&pfnaccept);
        InstallHookApiTracked(L"ws2_32.dll", "WSASocketA", Detour_WSASocketA, (LPVOID*)&pfnWSASocketA);
        InstallHookApiTracked(L"ws2_32.dll", "WSASocketW", Detour_WSASocketW, (LPVOID*)&pfnWSASocketW);
        InstallHookApiTracked(L"ws2_32.dll", "WSAConnect", Detour_WSAConnect, (LPVOID*)&pfnWSAConnect);
        InstallHookApiTracked(L"ws2_32.dll", "connect", Detour_connect, (LPVOID*)&pfnconnect);
        InstallHookApiTracked(L"ws2_32.dll", "send", Detour_send, (LPVOID*)&pfnsend);
        InstallHookApiTracked(L"ws2_32.dll", "recv", Detour_recv, (LPVOID*)&pfnrecv);
        InstallHookApiTracked(L"ws2_32.dll", "sendto", Detour_sendto, (LPVOID*)&pfnsendto);
        InstallHookApiTracked(L"ws2_32.dll", "recvfrom", Detour_recvfrom, (LPVOID*)&pfnrecvfrom);
        InstallHookApiTracked(L"ws2_32.dll", "closesocket", Detour_closesocket, (LPVOID*)&pfnclosesocket);
        InstallHookApiTracked(L"ws2_32.dll", "WSASend", Detour_WSASend, (LPVOID*)&pfnWSASend);
        InstallHookApiTracked(L"ws2_32.dll", "WSARecv", Detour_WSARecv, (LPVOID*)&pfnWSARecv);
        InstallHookApiTracked(L"ws2_32.dll", "WSASendTo", Detour_WSASendTo, (LPVOID*)&pfnWSASendTo);
        InstallHookApiTracked(L"ws2_32.dll", "WSARecvFrom", Detour_WSARecvFrom, (LPVOID*)&pfnWSARecvFrom);
        InstallHookApiTracked(L"ws2_32.dll", "getaddrinfo", Detour_getaddrinfo, (LPVOID*)&pfngetaddrinfo);
        InstallHookApiTracked(L"ws2_32.dll", "GetAddrInfoW", Detour_GetAddrInfoW, (LPVOID*)&pfnGetAddrInfoW);
        InstallHookApiTracked(L"ws2_32.dll", "getnameinfo", Detour_getnameinfo, (LPVOID*)&pfngetnameinfo);
        InstallHookApiTracked(L"ws2_32.dll", "GetNameInfoW", Detour_GetNameInfoW, (LPVOID*)&pfnGetNameInfoW);
        InstallHookApiTracked(L"ws2_32.dll", "gethostbyname", Detour_gethostbyname, (LPVOID*)&pfngethostbyname);
        InstallHookApiTracked(L"ws2_32.dll", "inet_addr", Detour_inet_addr, (LPVOID*)&pfninet_addr);
    } else {
        RecordHookStatus(L"ws2_32.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hDns = GetModuleHandleW(L"dnsapi.dll");
    if (!hDns) hDns = LoadLibraryW(L"dnsapi.dll");
    if (hDns) {
        InstallHookApiTracked(L"dnsapi.dll", "DnsQuery_W", Detour_DnsQuery_W, (LPVOID*)&pfnDnsQuery_W);
        InstallHookApiTracked(L"dnsapi.dll", "DnsQuery_A", Detour_DnsQuery_A, (LPVOID*)&pfnDnsQuery_A);
    } else {
        RecordHookStatus(L"dnsapi.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    // WinINet Hooks
    HMODULE hWininet = GetModuleHandleW(L"wininet.dll");
    if (!hWininet) hWininet = LoadLibraryW(L"wininet.dll");
    if (hWininet) {
        InstallHookApiTracked(L"wininet.dll", "InternetOpenW", Detour_InternetOpenW, (LPVOID*)&pfnInternetOpenW);
        InstallHookApiTracked(L"wininet.dll", "InternetOpenA", Detour_InternetOpenA, (LPVOID*)&pfnInternetOpenA);
        InstallHookApiTracked(L"wininet.dll", "InternetConnectW", Detour_InternetConnectW, (LPVOID*)&pfnInternetConnectW);
        InstallHookApiTracked(L"wininet.dll", "InternetConnectA", Detour_InternetConnectA, (LPVOID*)&pfnInternetConnectA);
        InstallHookApiTracked(L"wininet.dll", "HttpOpenRequestW", Detour_HttpOpenRequestW, (LPVOID*)&pfnHttpOpenRequestW);
        InstallHookApiTracked(L"wininet.dll", "HttpOpenRequestA", Detour_HttpOpenRequestA, (LPVOID*)&pfnHttpOpenRequestA);
        InstallHookApiTracked(L"wininet.dll", "InternetOpenUrlW", Detour_InternetOpenUrlW, (LPVOID*)&pfnInternetOpenUrlW);
        InstallHookApiTracked(L"wininet.dll", "InternetOpenUrlA", Detour_InternetOpenUrlA, (LPVOID*)&pfnInternetOpenUrlA);
        InstallHookApiTracked(L"wininet.dll", "HttpSendRequestW", Detour_HttpSendRequestW, (LPVOID*)&pfnHttpSendRequestW);
        InstallHookApiTracked(L"wininet.dll", "HttpSendRequestA", Detour_HttpSendRequestA, (LPVOID*)&pfnHttpSendRequestA);
        InstallHookApiTracked(L"wininet.dll", "InternetReadFile", Detour_InternetReadFile, (LPVOID*)&pfnInternetReadFile);
        InstallHookApiTracked(L"wininet.dll", "InternetWriteFile", Detour_InternetWriteFile, (LPVOID*)&pfnInternetWriteFile);
    } else {
        RecordHookStatus(L"wininet.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hWinhttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinhttp) hWinhttp = LoadLibraryW(L"winhttp.dll");
    if (hWinhttp) {
        InstallHookApiTracked(L"winhttp.dll", "WinHttpOpen", Detour_WinHttpOpen, (LPVOID*)&pfnWinHttpOpen);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpConnect", Detour_WinHttpConnect, (LPVOID*)&pfnWinHttpConnect);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpOpenRequest", Detour_WinHttpOpenRequest, (LPVOID*)&pfnWinHttpOpenRequest);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpSendRequest", Detour_WinHttpSendRequest, (LPVOID*)&pfnWinHttpSendRequest);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpReceiveResponse", Detour_WinHttpReceiveResponse, (LPVOID*)&pfnWinHttpReceiveResponse);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpReadData", Detour_WinHttpReadData, (LPVOID*)&pfnWinHttpReadData);
        InstallHookApiTracked(L"winhttp.dll", "WinHttpWriteData", Detour_WinHttpWriteData, (LPVOID*)&pfnWinHttpWriteData);
    } else {
        RecordHookStatus(L"winhttp.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hSecur32 = GetModuleHandleW(L"secur32.dll");
    if (!hSecur32) hSecur32 = LoadLibraryW(L"secur32.dll");
    if (hSecur32) {
        InstallHookApiTracked(L"secur32.dll", "EncryptMessage", Detour_EncryptMessage, (LPVOID*)&pfnEncryptMessage);
        InstallHookApiTracked(L"secur32.dll", "DecryptMessage", Detour_DecryptMessage, (LPVOID*)&pfnDecryptMessage);
    } else {
        RecordHookStatus(L"secur32.dll", "*", "Module Not Loaded", "Schannel/SSPI plaintext hooks unavailable");
    }
    InstallLoadedOpenSslHooks();
    } else {
        RecordHookStatus(L"Network", "*", "Disabled", "Hook Network was disabled by the analyst");
    }

    HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
    if (!hOle32) hOle32 = LoadLibraryW(L"ole32.dll");
    if (hOle32) {
        InstallHookApiTracked(L"ole32.dll", "CoInitialize", Detour_CoInitialize, (LPVOID*)&pfnCoInitialize);
        InstallHookApiTracked(L"ole32.dll", "CoInitializeEx", Detour_CoInitializeEx, (LPVOID*)&pfnCoInitializeEx);
        InstallHookApiTracked(L"ole32.dll", "CoUninitialize", Detour_CoUninitialize, (LPVOID*)&pfnCoUninitialize);
        InstallHookApiTracked(L"ole32.dll", "CoCreateInstance", Detour_CoCreateInstance, (LPVOID*)&pfnCoCreateInstance);
        InstallHookApiTracked(L"ole32.dll", "CoCreateInstanceEx", Detour_CoCreateInstanceEx, (LPVOID*)&pfnCoCreateInstanceEx);
        InstallHookApiTracked(L"ole32.dll", "CoGetClassObject", Detour_CoGetClassObject, (LPVOID*)&pfnCoGetClassObject);
        InstallHookApiTracked(L"ole32.dll", "CLSIDFromString", Detour_CLSIDFromString, (LPVOID*)&pfnCLSIDFromString);
        InstallHookApiTracked(L"ole32.dll", "CLSIDFromProgID", Detour_CLSIDFromProgID, (LPVOID*)&pfnCLSIDFromProgID);
    } else {
        RecordHookStatus(L"ole32.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32) {
        InstallHookApiTracked(L"user32.dll", "GetCursorPos", Detour_GetCursorPos, (LPVOID*)&pfnGetCursorPos);
        InstallHookApiTracked(L"user32.dll", "EnumWindows", Detour_EnumWindows, (LPVOID*)&pfnEnumWindows);
        InstallHookApiTracked(L"user32.dll", "EnumChildWindows", Detour_EnumChildWindows, (LPVOID*)&pfnEnumChildWindows);
        InstallHookApiTracked(L"user32.dll", "SetTimer", Detour_SetTimer, (LPVOID*)&pfnSetTimer);
        InstallHookApiTracked(L"user32.dll", "SetWindowsHookExW", Detour_SetWindowsHookExW, (LPVOID*)&pfnSetWindowsHookExW);
        InstallHookApiTracked(L"user32.dll", "SetWindowsHookExA", Detour_SetWindowsHookExA, (LPVOID*)&pfnSetWindowsHookExA);
        InstallHookApiTracked(L"user32.dll", "EnumThreadWindows", Detour_EnumThreadWindows, (LPVOID*)&pfnEnumThreadWindows);
        InstallHookApiTracked(L"user32.dll", "EnumDesktopWindows", Detour_EnumDesktopWindows, (LPVOID*)&pfnEnumDesktopWindows);
        InstallHookApiTracked(L"user32.dll", "CallWindowProcW", Detour_CallWindowProcW, (LPVOID*)&pfnCallWindowProcW);
    } else {
        RecordHookStatus(L"user32.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hWinmm = GetModuleHandleW(L"winmm.dll");
    if (!hWinmm) hWinmm = LoadLibraryW(L"winmm.dll");
    if (hWinmm) {
        InstallHookApiTracked(L"winmm.dll", "timeGetTime", Detour_timeGetTime, (LPVOID*)&pfnTimeGetTime);
    } else {
        RecordHookStatus(L"winmm.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hBcrypt = GetModuleHandleW(L"bcrypt.dll");
    if (!hBcrypt) hBcrypt = LoadLibraryW(L"bcrypt.dll");
    if (hBcrypt) {
        InstallHookApiTracked(L"bcrypt.dll", "BCryptOpenAlgorithmProvider", Detour_BCryptOpenAlgorithmProvider, (LPVOID*)&pfnBCryptOpenAlgorithmProvider);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptGenerateSymmetricKey", Detour_BCryptGenerateSymmetricKey, (LPVOID*)&pfnBCryptGenerateSymmetricKey);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptCreateHash", Detour_BCryptCreateHash, (LPVOID*)&pfnBCryptCreateHash);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptHashData", Detour_BCryptHashData, (LPVOID*)&pfnBCryptHashData);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptFinishHash", Detour_BCryptFinishHash, (LPVOID*)&pfnBCryptFinishHash);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptEncrypt", Detour_BCryptEncrypt, (LPVOID*)&pfnBCryptEncrypt);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptDecrypt", Detour_BCryptDecrypt, (LPVOID*)&pfnBCryptDecrypt);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptGenRandom", Detour_BCryptGenRandom, (LPVOID*)&pfnBCryptGenRandom);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptDeriveKeyPBKDF2", Detour_BCryptDeriveKeyPBKDF2, (LPVOID*)&pfnBCryptDeriveKeyPBKDF2);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptImportKey", Detour_BCryptImportKey, (LPVOID*)&pfnBCryptImportKey);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptImportKeyPair", Detour_BCryptImportKeyPair, (LPVOID*)&pfnBCryptImportKeyPair);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptSignHash", Detour_BCryptSignHash, (LPVOID*)&pfnBCryptSignHash);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptVerifySignature", Detour_BCryptVerifySignature, (LPVOID*)&pfnBCryptVerifySignature);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptDeriveKey", Detour_BCryptDeriveKey, (LPVOID*)&pfnBCryptDeriveKey);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptDestroyKey", Detour_BCryptDestroyKey, (LPVOID*)&pfnBCryptDestroyKey);
        InstallHookApiTracked(L"bcrypt.dll", "BCryptDestroyHash", Detour_BCryptDestroyHash, (LPVOID*)&pfnBCryptDestroyHash);
    } else {
        RecordHookStatus(L"bcrypt.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hNcrypt = GetModuleHandleW(L"ncrypt.dll");
    if (!hNcrypt) hNcrypt = LoadLibraryW(L"ncrypt.dll");
    if (hNcrypt) {
        InstallHookApiTracked(L"ncrypt.dll", "NCryptOpenStorageProvider", Detour_NCryptOpenStorageProvider, (LPVOID*)&pfnNCryptOpenStorageProvider);
        InstallHookApiTracked(L"ncrypt.dll", "NCryptCreatePersistedKey", Detour_NCryptCreatePersistedKey, (LPVOID*)&pfnNCryptCreatePersistedKey);
        InstallHookApiTracked(L"ncrypt.dll", "NCryptEncrypt", Detour_NCryptEncrypt, (LPVOID*)&pfnNCryptEncrypt);
        InstallHookApiTracked(L"ncrypt.dll", "NCryptDecrypt", Detour_NCryptDecrypt, (LPVOID*)&pfnNCryptDecrypt);
    } else {
        RecordHookStatus(L"ncrypt.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
    if (!hCrypt32) hCrypt32 = LoadLibraryW(L"crypt32.dll");
    if (hCrypt32) {
        InstallHookApiTracked(L"crypt32.dll", "CertOpenStore", Detour_CertOpenStore, (LPVOID*)&pfnCertOpenStore);
        InstallHookApiTracked(L"crypt32.dll", "CertFindCertificateInStore", Detour_CertFindCertificateInStore, (LPVOID*)&pfnCertFindCertificateInStore);
        InstallHookApiTracked(L"crypt32.dll", "PFXImportCertStore", Detour_PFXImportCertStore, (LPVOID*)&pfnPFXImportCertStore);
        InstallHookApiTracked(L"crypt32.dll", "CryptProtectData", Detour_CryptProtectData, (LPVOID*)&pfnCryptProtectData);
        InstallHookApiTracked(L"crypt32.dll", "CryptUnprotectData", Detour_CryptUnprotectData, (LPVOID*)&pfnCryptUnprotectData);
    } else {
        RecordHookStatus(L"crypt32.dll", "*", "Module Not Loaded", "LoadLibraryW failed");
    }

    MH_STATUS enableStatus = MH_EnableHook(MH_ALL_HOOKS);
    if (enableStatus != MH_OK) {
        const char* reason = MH_StatusToString(enableStatus);
        RecordHookStatus(L"MinHook", "MH_EnableHook", "Failed", reason ? reason : "MH_EnableHook failed");
        return false;
    }

    g_HooksActivated.store(true);

    // Do not claim the agent is ready if MinHook succeeded globally but every
    // individual API hook failed. This was previously indistinguishable from
    // a healthy session in the controller.
    size_t hookedCount = 0;
    for (const auto& status : GetHookStatuses()) {
        if (status.status == "Hooked") ++hookedCount;
    }
    if (hookedCount == 0) {
        RecordHookStatus(L"InspecthorAgent", "HookReadiness", "Failed", "no API hooks became active");
        g_HooksActivated.store(false);
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return false;
    }

    return true;
}

void RemoveHooks() {
    g_HooksActivated.store(false);
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

} // namespace Inspecthor
