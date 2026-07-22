#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <windows.h>
#include "telemetry.h"

namespace Inspecthor {

class CallerFilter {
public:
    CallerFilter();
    ~CallerFilter() = default;

    void Configure(const TraceConfig& config);
    void SetMainModuleName(const std::wstring& name);
    
    // Checks if the caller at the given return address should be monitored
    bool ShouldTrace(void* callerAddress, std::string& outModuleName);

private:
    TraceConfig m_config;
    std::wstring m_mainModuleName;
    std::wstring m_mainModulePath;
    
    // Cache resolved module names for fast lookups
    std::mutex m_cacheMutex;
    std::unordered_map<HMODULE, std::wstring> m_moduleCache;
    std::vector<HMODULE> m_suppressedModules;

    bool IsWindowsSystemLibrary(const std::wstring& modulePath);
};

} // namespace Inspecthor
