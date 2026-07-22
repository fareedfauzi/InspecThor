#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace Inspecthor {

struct TargetInfo {
    bool active = false;
    DWORD pid = 0;
    std::wstring path;
    bool is32Bit = false;
    std::string launchMode;
};

// Initializes the Win32 window, DirectX 11 device, swap chain, and Dear ImGui contexts.
bool InitGui(HINSTANCE hInstance, int nCmdShow);

// Renders a single frame of the ImGui interface. Returns false if the window is closed.
bool RenderGuiFrame();

// Cleans up ImGui, DirectX 11, and Win32 window resources.
void ShutdownGui();

// Thread-safe callback to push incoming telemetry JSON strings into the UI's event queue.
void PushTelemetryEvent(const std::string& jsonStr);

// Thread-safe operational logging for controller worker threads.
void AddLog(const std::string& msg);

// Sets the active target process info directly from the loader injector.
void SetTargetProcess(const TargetInfo& info);

// Gets the active target process info.
TargetInfo GetTargetProcess();

// Thread-safe callback to handle child process spawns detected by ETW.
void OnChildProcessSpawned(uint32_t childPid, uint32_t parentPid, const std::string& imagePath, const std::string& commandLine);
void OnProcessExited(uint32_t pid, uint32_t exitCode);

} // namespace Inspecthor
