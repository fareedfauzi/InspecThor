#pragma once

#include "analysis_session.h"

#include <mutex>
#include <optional>
#include <unordered_map>

namespace Inspecthor {

class ProcessTreeManager {
public:
    static ProcessTreeManager& Instance();

    AnalysisSession BeginSession(const std::wstring& originalPath, const std::string& targetType, const TargetProfile& profile);
    void Reset();
    void StopSession(uint64_t endTime);
    void RegisterRoot(uint32_t pid, const std::wstring& imagePath, const std::wstring& commandLine, uint64_t startTime,
        bool launcherOnly = false, bool instrumented = true);
    ChildObservationResult ObserveChild(uint32_t childPid, uint32_t parentPid, const std::string& imagePath,
        const std::string& commandLine, uint64_t startTime, ChildMonitoringMode mode);
    void MarkInjectionResult(uint32_t pid, bool injected, const std::string& diagnostic);
    void MarkExited(uint32_t pid, uint64_t exitTime, DWORD exitCode);
    void MarkExitWatchStarted(uint32_t pid);
    bool BelongsToSession(uint32_t pid) const;
    bool HasLiveProcesses() const;
    bool IsInjectionPendingOrComplete(uint32_t pid) const;
    AnalysisSession Snapshot() const;
    std::vector<ProcessNode> ProcessSnapshot() const;
    std::unordered_map<uint32_t, std::string> ObservedProcessPaths() const;
    void Restore(const AnalysisSession& session);

private:
    mutable std::mutex mutex_;
    AnalysisSession session_;
    uint64_t generation_ = 0;
};

} // namespace Inspecthor
