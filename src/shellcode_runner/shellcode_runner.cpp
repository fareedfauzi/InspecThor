#include <windows.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

using ReportShellcodeEventFn = void(WINAPI*)(const char*, const void*, size_t, DWORD, DWORD);

struct PayloadContext {
    void* entry = nullptr;
    size_t size = 0;
    DWORD threadId = 0;
    DWORD exceptionCode = 0;
    ReportShellcodeEventFn report = nullptr;
};

static LONG ShellcodeExceptionFilter(EXCEPTION_POINTERS* exceptionInfo, PayloadContext* context) {
    if (context && exceptionInfo && exceptionInfo->ExceptionRecord) {
        context->exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI ExecutePayload(LPVOID parameter) {
    auto* context = static_cast<PayloadContext*>(parameter);
    if (!context || !context->entry) return ERROR_INVALID_PARAMETER;
    if (context->report) context->report("ThreadEntered", context->entry, context->size, GetCurrentThreadId(), 0);

    DWORD result = 0;
    __try {
        // Preserve the Windows thread-entry contract used by the previous
        // direct CreateThread implementation. Calling it also leaves return
        // addresses for hooked WinAPI calls inside the shellcode allocation.
        result = reinterpret_cast<DWORD(WINAPI*)(LPVOID)>(context->entry)(nullptr);
    } __except (ShellcodeExceptionFilter(GetExceptionInformation(), context)) {
        result = context->exceptionCode ? context->exceptionCode : ERROR_UNHANDLED_EXCEPTION;
        if (context->report) context->report("Exception", context->entry, context->size, GetCurrentThreadId(), result);
        return result;
    }

    if (context->report) context->report("Returned", context->entry, context->size, GetCurrentThreadId(), 0);
    return result;
}

static ReportShellcodeEventFn ResolveReporter() {
    HMODULE agent = GetModuleHandleW(L"InspecthorAgent.dll");
    if (!agent) agent = GetModuleHandleW(L"InspecthorAgent32.dll");
    if (!agent) return nullptr;
    FARPROC reporter = GetProcAddress(agent, "InspecthorReportShellcodeEvent");
#ifdef _M_IX86
    if (!reporter) reporter = GetProcAddress(agent, "_InspecthorReportShellcodeEvent@20");
#endif
    return reinterpret_cast<ReportShellcodeEventFn>(reporter);
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::wcerr << L"Usage: InspecthorShellcodeRunner.exe <shellcode.bin>\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary | std::ios::ate);
    if (!input) { std::wcerr << L"Could not open shellcode file.\n"; return 3; }
    std::streamsize length = input.tellg();
    if (length <= 0 || length > 64ll * 1024ll * 1024ll) {
        std::wcerr << L"Shellcode must be between 1 byte and 64 MiB.\n";
        return 4;
    }
    input.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    if (!input.read(reinterpret_cast<char*>(bytes.data()), length)) return 5;

    void* region = VirtualAlloc(nullptr, bytes.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!region) return 6;
    memcpy(region, bytes.data(), bytes.size());
    DWORD oldProtect = 0;
    // Keep the payload writable only while copying it.  Executing from an RWX
    // allocation creates an avoidable security and analysis blind spot.
    if (!VirtualProtect(region, bytes.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(region, 0, MEM_RELEASE); return 7;
    }
    FlushInstructionCache(GetCurrentProcess(), region, bytes.size());
    PayloadContext context;
    context.entry = region;
    context.size = bytes.size();
    context.report = ResolveReporter();
    if (context.report) context.report("Prepared", region, bytes.size(), 0, 0);

    std::cout << "[shellcode] prepared " << bytes.size() << " bytes at " << region << std::endl;
    DWORD threadId = 0;
    HANDLE thread = CreateThread(nullptr, 0, ExecutePayload, &context, CREATE_SUSPENDED, &threadId);
    if (!thread) { VirtualFree(region, 0, MEM_RELEASE); return 8; }
    context.threadId = threadId;
    if (context.report) context.report("ThreadCreated", region, bytes.size(), threadId, 0);
    std::cout << "[shellcode] payload thread created suspended (TID " << threadId << ")" << std::endl;
    if (ResumeThread(thread) == static_cast<DWORD>(-1)) {
        DWORD error = GetLastError();
        if (context.report) context.report("ResumeFailed", region, bytes.size(), threadId, error);
        TerminateThread(thread, error);
        CloseHandle(thread);
        VirtualFree(region, 0, MEM_RELEASE);
        return 9;
    }
    if (context.report) context.report("ThreadResumed", region, bytes.size(), threadId, 0);
    std::cout << "[shellcode] payload thread resumed" << std::endl;

    const DWORD waitResult = WaitForSingleObject(thread, INFINITE);
    DWORD exitCode = 0;
    if (waitResult != WAIT_OBJECT_0 || !GetExitCodeThread(thread, &exitCode)) {
        exitCode = GetLastError();
        if (context.report) context.report("WaitFailed", region, bytes.size(), threadId, exitCode);
    } else if (context.report) {
        context.report("ThreadExited", region, bytes.size(), threadId, exitCode);
    }
    std::cout << "[shellcode] payload thread exited with status 0x" << std::hex << exitCode << std::dec << std::endl;
    CloseHandle(thread);
    VirtualFree(region, 0, MEM_RELEASE);
    return static_cast<int>(exitCode);
}
