#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "telemetry.h"

namespace Inspecthor {

// Initializes and installs all target hooks using MinHook
bool InstallHooks();

// Removes all installed hooks
void RemoveHooks();
void SetAgentModulePath(const std::wstring& modulePath);
void ConfigureFilter(const TraceConfig& config);

struct HookStatusInfo {
    std::string apiName;
    std::string moduleName;
    std::string status;
    std::string reason;
};

std::vector<HookStatusInfo> GetHookStatuses();

// Helper to check if current thread is already processing a hook (reentrancy check)
bool IsInsideHook();
void SetInsideHook(bool value);

class HookGuard {
public:
    HookGuard() {
        m_wasInside = IsInsideHook();
        SetInsideHook(true);
    }
    ~HookGuard() {
        SetInsideHook(m_wasInside);
    }
    bool WasInside() const { return m_wasInside; }
private:
    bool m_wasInside;
};

// Callback to send telemetry events to the main Agent communication thread
typedef void (*TelemetryCallback)(const TelemetryEvent& event);
void RegisterTelemetryCallback(TelemetryCallback cb);

} // namespace Inspecthor
