#pragma once
#include <windows.h>
#include "telemetry.h"
#include <string>

namespace Inspecthor {

struct TargetProcessInfo {
    DWORD dwProcessId = 0;
    DWORD dwThreadId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hOutputRead = NULL;
    bool is32Bit = false;
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;
    std::string launcherOutput;
};

class Injector {
public:
    Injector() = default;
    ~Injector() = default;

    // Launches an executable target suspended, injects the Agent DLL, and completes the pipe handshake.
    bool LaunchAndInject(
        const std::wstring& exePath,
        const std::wstring& cmdLine,
        TargetProcessInfo& outInfo,
        HANDLE& outPipeHandle,
        const TraceConfig& traceConfig,
        const std::wstring& workingDirectory = L""
    );

    // Launches a target suspended without loading the hook agent. Used for
    // noisy launcher hosts that are tracked through ETW while descendants are
    // selectively instrumented by the session policy.
    bool LaunchSuspended(
        const std::wstring& exePath,
        const std::wstring& cmdLine,
        TargetProcessInfo& outInfo,
        const std::wstring& workingDirectory = L""
    );

    // Launches a DLL target suspended, performs injection, and completes the pipe handshake.
    bool LaunchDll(
        const std::wstring& dllPath,
        const std::wstring& mode, // dllmain | rundll32
        const std::string& exportName,
        bool is32Bit,
        TargetProcessInfo& outInfo,
        HANDLE& outPipeHandle,
        const TraceConfig& traceConfig
    );

    // Injects the matching monitoring agent into an already-running descendant.
    // The controller's additional pipe listener performs the agent handshake.
    bool InjectAgentIntoProcess(
        DWORD processId,
        std::string* diagnosticOutput = nullptr,
        std::wstring* resolvedProcessPath = nullptr
    );

    // Dynamic architecture detector using PE headers
    static bool IsFile32Bit(const std::wstring& filePath);
};

} // namespace Inspecthor
