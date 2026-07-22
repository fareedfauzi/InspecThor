#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <unordered_set>
#include "gui.h"
#include "injector.h"
#include "telemetry.h"
#include "pipe_io.h"

namespace Inspecthor {

// Global context accessible by gui.cpp
TraceConfig g_ActiveTraceConfig;
Injector g_Injector;
std::mutex g_PipeThreadsMutex;
std::vector<std::thread> g_PipeThreads;
static std::atomic<bool> g_AdditionalPipeListenerRunning{ false };
static std::mutex g_AdditionalPipePidMutex;
static std::unordered_set<DWORD> g_AdditionalPipePids;

static bool PerformAdditionalPipeHandshake(HANDLE hPipe) {
    const ULONGLONG deadline = GetTickCount64() + 10000;
    bool connected = false;
    while (g_AdditionalPipeListenerRunning.load() && GetTickCount64() < deadline) {
        if (ConnectNamedPipe(hPipe, NULL)) { connected = true; break; }
        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) { connected = true; break; }
        if (error != ERROR_PIPE_LISTENING && error != ERROR_NO_DATA) return false;
        Sleep(10);
    }
    if (!connected) return false;
    DWORD blockingMode = PIPE_READMODE_BYTE | PIPE_WAIT;
    SetNamedPipeHandleState(hPipe, &blockingMode, nullptr, nullptr);

    PipeHeader regHeader = {};
    if (!ReadPipeExact(hPipe, &regHeader, sizeof(regHeader))) {
        return false;
    }

    if (regHeader.type != MessageType::RegisterClient) {
        return false;
    }

    PipeHeader configHeader = {};
    configHeader.type = MessageType::SendConfig;
    configHeader.payloadLength = sizeof(TraceConfig);

    if (!WritePipeExact(hPipe, &configHeader, sizeof(configHeader)) ||
        !WritePipeExact(hPipe, &g_ActiveTraceConfig, sizeof(TraceConfig))) {
        return false;
    }

    PipeHeader readyHeader = {};
    if (!ReadPipeExact(hPipe, &readyHeader, sizeof(readyHeader))) {
        return false;
    }

    return readyHeader.type == MessageType::ReadyToTrace;
}

// Pipe Reader thread loop
void PipeReaderThread(HANDLE hPipe, bool updateTargetStatus) {
    constexpr uint32_t kMaxTelemetryPayload = 16 * 1024 * 1024;
    size_t receivedMessages = 0;
    AddLog("[verbose] telemetry pipe reader started.");
    while (true) {
        PipeHeader header = {};
        if (!ReadPipeExact(hPipe, &header, sizeof(header))) {
            break;
        }

        if (header.payloadLength > kMaxTelemetryPayload) {
            AddLog("[error] telemetry pipe rejected an oversized payload.");
            break;
        }

        if (header.payloadLength > 0) {
            std::vector<char> payload(header.payloadLength + 1);
            if (ReadPipeExact(hPipe, payload.data(), header.payloadLength)) {
                payload[header.payloadLength] = '\0';
                std::string jsonEvent(payload.data(), header.payloadLength);
                
                // Push telemetry event directly to the ImGui GUI
                PushTelemetryEvent(jsonEvent);
                ++receivedMessages;
            } else {
                AddLog("[error] telemetry pipe closed before a complete event was received.");
                break;
            }
        }
    }
    CloseHandle(hPipe);
    AddLog("[verbose] telemetry pipe reader stopped after " + std::to_string(receivedMessages) + " messages.");

    if (updateTargetStatus) {
        TargetInfo terminated = {};
        terminated.active = false;
        SetTargetProcess(terminated);
    }
}

static void AdditionalPipeListenerThread(DWORD targetPid) {
    while (g_AdditionalPipeListenerRunning.load()) {
        std::wstring pipePath = L"\\\\.\\pipe\\InspecthorTelemetry_" + std::to_wstring(targetPid);
        HANDLE hPipe = CreateNamedPipeW(
            pipePath.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }

        if (PerformAdditionalPipeHandshake(hPipe)) {
            std::lock_guard<std::mutex> threadLock(g_PipeThreadsMutex);
            g_PipeThreads.push_back(std::thread(PipeReaderThread, hPipe, false));
        } else {
            CloseHandle(hPipe);
        }
    }
    std::lock_guard<std::mutex> lock(g_AdditionalPipePidMutex);
    g_AdditionalPipePids.erase(targetPid);
}

void StartAdditionalPipeListenerForPid(DWORD processId) {
    if (!processId || !g_AdditionalPipeListenerRunning.load()) return;
    {
        std::lock_guard<std::mutex> lock(g_AdditionalPipePidMutex);
        if (!g_AdditionalPipePids.insert(processId).second) return;
    }
    std::lock_guard<std::mutex> threadLock(g_PipeThreadsMutex);
    g_PipeThreads.push_back(std::thread(AdditionalPipeListenerThread, processId));
}

void StartAdditionalPipeListener() {
    bool expected = false;
    if (!g_AdditionalPipeListenerRunning.compare_exchange_strong(expected, true)) {
        return;
    }

    StartAdditionalPipeListenerForPid(GetTargetProcess().pid);
}

void StopAdditionalPipeListener() {
    if (!g_AdditionalPipeListenerRunning.exchange(false)) {
        return;
    }

    std::vector<DWORD> pids;
    {
        std::lock_guard<std::mutex> lock(g_AdditionalPipePidMutex);
        pids.assign(g_AdditionalPipePids.begin(), g_AdditionalPipePids.end());
    }
    for (DWORD pid : pids) {
        const std::wstring pipePath = L"\\\\.\\pipe\\InspecthorTelemetry_" + std::to_wstring(pid);
        HANDLE pipe = CreateFileW(pipePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    }
}

} // namespace Inspecthor

int main() {
    std::cout << "=== InspecThor - Malware Behaviour Analysis Tool ===" << std::endl;
    std::cout << "[ui] initializing analysis workspace..." << std::endl;

    // Get module handle for HINSTANCE
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    
    // Initialize the ImGui + DirectX 11 + Win32 GUI
    if (!Inspecthor::InitGui(hInstance, SW_SHOW)) {
        std::cout << "[ui] failed to initialize analysis workspace. exiting." << std::endl;
        return 1;
    }

    std::cout << "[ui] analysis workspace active." << std::endl;

    // Run the frame loop until the window is closed
    while (Inspecthor::RenderGuiFrame()) {
        // Yield thread slightly to avoid 100% CPU usage on idle
        Sleep(5);
    }

    std::cout << "[ui] analysis workspace closed. cleaning up..." << std::endl;
    Inspecthor::ShutdownGui();

    // Detach all reader threads to prevent UI hangs on exit
    std::lock_guard<std::mutex> lock(Inspecthor::g_PipeThreadsMutex);
    for (auto& t : Inspecthor::g_PipeThreads) {
        if (t.joinable()) {
            t.detach();
        }
    }

    std::cout << "[ui] shutdown complete." << std::endl;
    return 0;
}
