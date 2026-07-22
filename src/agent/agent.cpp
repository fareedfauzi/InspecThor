#include <windows.h>
#include <string>
#include <thread>
#include <mutex>
#include <sstream>
#include <chrono>
#include "hooks.h"
#include "pipe_io.h"
#include "telemetry.h"

namespace Inspecthor {

static HANDLE g_PipeHandle = INVALID_HANDLE_VALUE;
static std::mutex g_PipeMutex;
static HMODULE g_AgentModule = NULL;

static std::string EscapeJsonString(const std::string& s) {
    std::string res;
    for (char c : s) {
        if (c == '"') res += "\\\"";
        else if (c == '\\') res += "\\\\";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else if (c == '\t') res += "\\t";
        else if (c >= 0 && c < 32) {
        } else {
            res += c;
        }
    }
    return res;
}

static void SendJsonPayload(const std::string& json) {
    HookGuard guard;

    PipeHeader header;
    header.type = MessageType::TelemetryData;
    header.payloadLength = (uint32_t)json.size();

    std::lock_guard<std::mutex> lock(g_PipeMutex);
    if (g_PipeHandle != INVALID_HANDLE_VALUE) {
        if (!WritePipeExact(g_PipeHandle, &header, sizeof(header)) ||
            !WritePipeExact(g_PipeHandle, json.data(), json.size())) {
            OutputDebugStringA("[InspecthorAgent] telemetry pipe write failed\n");
        }
    }
}

static void SendAgentDiagnostic(const char* stage, const std::string& message, DWORD errorCode = 0) {
    std::stringstream ss;
    ss << "{"
       << "\"event\":\"agent_diagnostic\","
       << "\"stage\":\"" << EscapeJsonString(stage ? stage : "unknown") << "\","
       << "\"message\":\"" << EscapeJsonString(message) << "\","
       << "\"errorCode\":" << errorCode
       << "}";
    SendJsonPayload(ss.str());
}

static void SendHookStatuses() {
    for (const auto& status : GetHookStatuses()) {
        std::stringstream ss;
        ss << "{"
           << "\"event\":\"hook_status\","
           << "\"apiName\":\"" << EscapeJsonString(status.apiName) << "\","
           << "\"dllName\":\"" << EscapeJsonString(status.moduleName) << "\","
           << "\"status\":\"" << EscapeJsonString(status.status) << "\","
           << "\"reason\":\"" << EscapeJsonString(status.reason) << "\""
           << "}";
        SendJsonPayload(ss.str());
    }
}

static void SendAgentReadyStatus() {
    size_t hookedCount = 0;
    size_t unavailableCount = 0;
    size_t skippedCount = 0;
    size_t failedCount = 0;
    for (const auto& status : GetHookStatuses()) {
        if (status.status == "Hooked") {
            ++hookedCount;
        } else if (status.status == "Skipped" || status.status == "Module Not Loaded") {
            ++unavailableCount;
            if (status.status == "Skipped") ++skippedCount;
        } else if (status.status == "Failed") {
            ++failedCount;
        }
    }

    std::stringstream ss;
    ss << "{"
       << "\"event\":\"agent_status\","
       << "\"status\":\"ready\","
       << "\"hookedCount\":" << hookedCount << ","
       << "\"unavailableCount\":" << unavailableCount << ","
       << "\"skippedCount\":" << skippedCount << ","
       << "\"failedCount\":" << failedCount
       << "}";
    SendJsonPayload(ss.str());
}

// Global callback for telemetry events
static void OnTelemetry(const TelemetryEvent& ev) {
    SendJsonPayload(ev.ToJson());
}

static void ReportShellcodeLifecycle(const char* phase, const void* baseAddress, size_t regionSize,
    DWORD payloadThreadId, DWORD status) {
    TelemetryEvent event = {};
    event.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    event.processId = GetCurrentProcessId();
    event.threadId = payloadThreadId ? payloadThreadId : GetCurrentThreadId();
    event.apiName = std::string("Shellcode") + (phase && *phase ? phase : "State");
    event.dllName = "InspecthorShellcodeRunner";
    event.callerAddress = reinterpret_cast<uint64_t>(baseAddress);
    event.callerModule = "Unknown (Shellcode/Mapped)";
    event.returnValue = status;
    event.parameters = {
        {"BaseAddress", "LPVOID", reinterpret_cast<uint64_t>(baseAddress), {}, "Executable payload base"},
        {"RegionSize", "SIZE_T", static_cast<uint64_t>(regionSize), {}, "Raw payload size"},
        {"PayloadThreadId", "DWORD", payloadThreadId, {}, "Shellcode execution thread"},
        {"Status", "DWORD", status, {}, phase ? phase : "State"}
    };
    SendJsonPayload(event.ToJson());
}

// Background thread for Pipe connection and handshake
static DWORD WINAPI AgentThread(LPVOID lpParam) {
    // Wait for the loader lock to be fully released and process to stabilize
    Sleep(100);

    std::wstring pipePath = L"\\\\.\\pipe\\InspecthorTelemetry";
    wchar_t envBuf[32] = {};
    DWORD envLen = GetEnvironmentVariableW(L"INSPECTHOR_SESSION_PID", envBuf, 32);
    if (envLen > 0 && envLen < 32) {
        pipePath += L"_" + std::wstring(envBuf);
    } else {
        std::wstring currentPidStr = std::to_wstring(GetCurrentProcessId());
        SetEnvironmentVariableW(L"INSPECTHOR_SESSION_PID", currentPidStr.c_str());
        pipePath += L"_" + currentPidStr;
    }
    
    // Attempt to connect to the Controller's Named Pipe
    for (int retry = 0; retry < 15; ++retry) {
        g_PipeHandle = CreateFileW(
            pipePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (g_PipeHandle != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(200);
    }

    if (g_PipeHandle == INVALID_HANDLE_VALUE) {
        // Failed to connect to controller pipe, abort injection trace
        return 0;
    }

    // Step 1: Register client with Controller
    PipeHeader regHeader;
    regHeader.type = MessageType::RegisterClient;
    regHeader.payloadLength = 0;
    
    if (!WritePipeExact(g_PipeHandle, &regHeader, sizeof(regHeader))) {
        CloseHandle(g_PipeHandle);
        g_PipeHandle = INVALID_HANDLE_VALUE;
        return 0;
    }

    // Step 2: Read hook configuration from Controller
    PipeHeader configHeader;
    TraceConfig traceConfig = {};
    if (ReadPipeExact(g_PipeHandle, &configHeader, sizeof(configHeader))) {
        if (configHeader.type == MessageType::SendConfig) {
            if (configHeader.payloadLength == sizeof(TraceConfig)) {
                ReadPipeExact(g_PipeHandle, &traceConfig, sizeof(TraceConfig));
            } else if (configHeader.payloadLength == 4) {
                // Backward compatibility (old 4-byte filter mode)
                uint32_t filterMode = 1;
                ReadPipeExact(g_PipeHandle, &filterMode, sizeof(filterMode));
                traceConfig.traceMode = filterMode == 1
                    ? TraceMode::UserModulesOnly
                    : TraceMode::ApiCallerFunctions;
            } else {
                std::vector<uint8_t> payload(configHeader.payloadLength);
                if (configHeader.payloadLength > 0) {
                    ReadPipeExact(g_PipeHandle, payload.data(), configHeader.payloadLength);
                }
            }
        }
    }

    ConfigureFilter(traceConfig);

    // Step 3: Install API hooks
    bool hooked = InstallHooks();

    if (hooked) {
        RegisterTelemetryCallback(OnTelemetry);
    }

    // Step 4: Notify Controller only after hooks are active.
    PipeHeader readyHeader;
    std::string readyPayload;
    if (!hooked) {
        readyPayload = "API hook installation failed";
        for (const auto& status : GetHookStatuses()) {
            if (status.status == "Failed") {
                readyPayload += ": " + status.moduleName + "!" + status.apiName;
                if (!status.reason.empty()) readyPayload += " (" + status.reason + ")";
                break;
            }
        }
    }
    readyHeader.type = hooked ? MessageType::ReadyToTrace : MessageType::AgentError;
    readyHeader.payloadLength = (uint32_t)readyPayload.size();
    if (!WritePipeExact(g_PipeHandle, &readyHeader, sizeof(readyHeader))) {
        RemoveHooks();
        CloseHandle(g_PipeHandle);
        g_PipeHandle = INVALID_HANDLE_VALUE;
        return 0;
    }
    if (!readyPayload.empty() && !WritePipeExact(g_PipeHandle, readyPayload.data(), readyPayload.size())) {
        RemoveHooks();
        CloseHandle(g_PipeHandle);
        g_PipeHandle = INVALID_HANDLE_VALUE;
        return 0;
    }

    if (!hooked) {
        CloseHandle(g_PipeHandle);
        g_PipeHandle = INVALID_HANDLE_VALUE;
        RemoveHooks();
        return 0;
    }

    SendAgentReadyStatus();
    SendAgentDiagnostic("transport", "named pipe connected; telemetry reader can receive API events");
    SendAgentDiagnostic("hooks", "stable hook profile enabled; experimental heap and advanced native hooks are disabled unless selected");
    SendHookStatuses();

    // Enter simple loop to monitor pipe connection status
    // If the pipe closes or is disconnected, we remove hooks and unload the DLL
    while (true) {
        Sleep(500);
        std::lock_guard<std::mutex> lock(g_PipeMutex);
        if (g_PipeHandle != INVALID_HANDLE_VALUE) {
            // Check if pipe is still alive by doing a peek or zero-byte write
            DWORD avail = 0;
            if (!PeekNamedPipe(g_PipeHandle, NULL, 0, NULL, &avail, NULL)) {
                // Pipe disconnected!
                CloseHandle(g_PipeHandle);
                g_PipeHandle = INVALID_HANDLE_VALUE;
                break;
            }
        } else {
            break;
        }
    }

    // Clean up
    RemoveHooks();
    FreeLibraryAndExitThread(g_AgentModule, 0);
    return 0;
}

} // namespace Inspecthor

// The runner resolves this optional export after the monitoring agent handshake.
// It gives the controller explicit payload-thread state even when shellcode uses
// direct syscalls, returns without calling an API, or faults before its first hook.
extern "C" __declspec(dllexport) void WINAPI InspecthorReportShellcodeEvent(
    const char* phase, const void* baseAddress, size_t regionSize, DWORD payloadThreadId, DWORD status) {
    Inspecthor::ReportShellcodeLifecycle(phase, baseAddress, regionSize, payloadThreadId, status);
}

// DLL Entrypoint
BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Inspecthor::g_AgentModule = hModule;
        DisableThreadLibraryCalls(hModule);
        {
            wchar_t modulePath[MAX_PATH] = {};
            if (GetModuleFileNameW(hModule, modulePath, MAX_PATH)) {
                Inspecthor::SetAgentModulePath(modulePath);
            }
        }
        CreateThread(NULL, 0, Inspecthor::AgentThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
