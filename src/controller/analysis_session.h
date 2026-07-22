#pragma once

#include "target_resolver.h"

#include <Windows.h>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace Inspecthor {

enum class ChildMonitoringMode { Smart = 0, Aggressive, CommandOnly };
enum class ChildInstrumentationDecision { InjectAndMonitor, LogCommandOnly, IgnoreSystemNoise };

struct ProcessNode {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::wstring imagePath;
    std::wstring processName;
    std::wstring commandLine;
    uint64_t timestamp = 0;
    uint64_t startTime = 0;
    uint64_t exitTime = 0;
    std::string relationship;
    std::string instrumentationStatus;
    std::string decision;
    std::string reason;
    bool isLauncher = false;
    bool isRootTarget = false;
    bool monitored = false;
    bool exited = false;
    bool exitWatchStarted = false;
    DWORD exitCode = STILL_ACTIVE;
};

struct AnalysisSession {
    std::string sessionId;
    std::wstring originalTargetPath;
    std::string targetType;
    TargetProfile targetProfile;
    uint32_t rootPid = 0;
    uint32_t launcherPid = 0;
    uint32_t primaryPid = 0;
    uint64_t startTime = 0;
    uint64_t endTime = 0;
    bool active = false;
    std::unordered_set<uint32_t> monitoredPids;
    std::unordered_set<uint32_t> commandOnlyPids;
    std::unordered_set<uint32_t> skippedPids;
    std::unordered_set<uint32_t> exitedPids;
    std::vector<ProcessNode> processTreeNodes;
};

struct ChildObservationResult {
    bool belongsToSession = false;
    bool isNew = false;
    bool queueInjection = false;
    bool startExitWatch = false;
    ChildInstrumentationDecision decision = ChildInstrumentationDecision::IgnoreSystemNoise;
    std::string reason;
};

} // namespace Inspecthor
