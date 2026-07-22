#include "process_tree_manager.h"
#include "child_instrumentation_policy.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <sstream>

namespace Inspecthor {

static std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    if (size) WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

static std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    if (size) MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

ProcessTreeManager& ProcessTreeManager::Instance() {
    static ProcessTreeManager instance;
    return instance;
}

AnalysisSession ProcessTreeManager::BeginSession(const std::wstring& originalPath, const std::string& targetType, const TargetProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = {};
    session_.originalTargetPath = originalPath;
    session_.targetType = targetType;
    session_.targetProfile = profile;
    session_.startTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    session_.active = true;
    std::ostringstream id;
    id << std::hex << session_.startTime << '-' << ++generation_;
    session_.sessionId = id.str();
    return session_;
}

void ProcessTreeManager::Reset() { std::lock_guard<std::mutex> lock(mutex_); session_ = {}; }
void ProcessTreeManager::StopSession(uint64_t endTime) { std::lock_guard<std::mutex> lock(mutex_); session_.active = false; session_.endTime = endTime; }

void ProcessTreeManager::RegisterRoot(uint32_t pid, const std::wstring& imagePath, const std::wstring& commandLine, uint64_t startTime,
    bool launcherOnly, bool instrumented) {
    if (!pid) return;
    std::lock_guard<std::mutex> lock(mutex_);
    session_.rootPid = pid;
    session_.launcherPid = launcherOnly ? pid : 0;
    session_.primaryPid = launcherOnly ? 0 : pid;
    if (instrumented) session_.monitoredPids.insert(pid); else session_.commandOnlyPids.insert(pid);
    ProcessNode node;
    node.pid = pid; node.imagePath = imagePath; node.processName = std::filesystem::path(imagePath).filename().wstring();
    node.commandLine = commandLine; node.timestamp = node.startTime = startTime;
    node.relationship = launcherOnly ? "launcher" : "root"; node.instrumentationStatus = instrumented ? "injected" : "command-only";
    node.decision = instrumented ? "Instrumented" : "ETW-only host";
    node.reason = instrumented ? (launcherOnly ? "launcher host registered" : "root process registered") : "noisy launcher baseline suppressed";
    node.isLauncher = launcherOnly; node.isRootTarget = !launcherOnly; node.monitored = instrumented;
    session_.processTreeNodes.push_back(std::move(node));
}

ChildObservationResult ProcessTreeManager::ObserveChild(uint32_t childPid, uint32_t parentPid, const std::string& imagePath,
    const std::string& commandLine, uint64_t startTime, ChildMonitoringMode mode) {
    ChildObservationResult result;
    if (!childPid || !parentPid || childPid == GetCurrentProcessId()) return result;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!session_.active && session_.sessionId.empty()) return result;
    const auto parent = std::find_if(session_.processTreeNodes.begin(), session_.processTreeNodes.end(),
        [parentPid](const ProcessNode& node) { return node.pid == parentPid; });
    if (parent == session_.processTreeNodes.end()) return result;
    result.belongsToSession = true;
    auto existing = std::find_if(session_.processTreeNodes.begin(), session_.processTreeNodes.end(),
        [childPid](const ProcessNode& node) { return node.pid == childPid && !node.exited; });
    ChildPolicyContext context;
    context.imagePath = imagePath; context.commandLine = commandLine;
    context.parentProcessName = Utf8(parent->processName);
    context.parentPid = parentPid; context.targetType = session_.targetType; context.mode = mode;
    context.originalSampleDirectory = std::filesystem::path(session_.originalTargetPath).parent_path().wstring();
    context.sandboxHostedTarget = session_.targetProfile.isLauncherBased || session_.targetProfile.isOffice ||
        session_.targetProfile.requiresShellExecute;
    result.decision = DecideChildInstrumentation(context, result.reason);
    if (existing != session_.processTreeNodes.end()) {
        if (existing->imagePath.empty()) existing->imagePath = Wide(imagePath);
        if (existing->processName.empty()) existing->processName = std::filesystem::path(existing->imagePath).filename().wstring();
        if (existing->commandLine.empty()) existing->commandLine = Wide(commandLine);
        result.startExitWatch = !existing->exitWatchStarted;
        if (result.startExitWatch) existing->exitWatchStarted = true;
        result.queueInjection = result.decision == ChildInstrumentationDecision::InjectAndMonitor &&
            existing->instrumentationStatus != "pending" && existing->instrumentationStatus != "injected";
        if (result.queueInjection) existing->instrumentationStatus = "pending";
        return result;
    }
    result.isNew = true; result.startExitWatch = true;
    ProcessNode node;
    node.pid = childPid; node.parentPid = parentPid;
    node.imagePath = Wide(imagePath);
    node.processName = std::filesystem::path(node.imagePath).filename().wstring();
    node.commandLine = Wide(commandLine); node.timestamp = node.startTime = startTime;
    node.reason = result.reason; node.exitWatchStarted = true;
    if (result.decision == ChildInstrumentationDecision::InjectAndMonitor) {
        node.relationship = "monitored-child"; node.instrumentationStatus = "pending"; node.decision = "Injection queued";
        session_.monitoredPids.insert(childPid); result.queueInjection = true;
    } else if (result.decision == ChildInstrumentationDecision::LogCommandOnly) {
        node.relationship = "command-only"; node.instrumentationStatus = "command-only"; node.decision = "Command only";
        session_.commandOnlyPids.insert(childPid);
    } else {
        node.relationship = "skipped"; node.instrumentationStatus = "skipped"; node.decision = "Skipped";
        session_.skippedPids.insert(childPid);
    }
    if (!session_.primaryPid && session_.launcherPid) {
        session_.primaryPid = childPid;
        node.relationship = "primary";
    }
    session_.processTreeNodes.push_back(std::move(node));
    return result;
}

void ProcessTreeManager::MarkInjectionResult(uint32_t pid, bool injected, const std::string& diagnostic) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto node = std::find_if(session_.processTreeNodes.rbegin(), session_.processTreeNodes.rend(), [pid](const ProcessNode& row) { return row.pid == pid; });
    if (node == session_.processTreeNodes.rend()) return;
    node->monitored = injected;
    if (injected) { node->instrumentationStatus = "injected"; node->decision = "Instrumented"; session_.monitoredPids.insert(pid); }
    else if (node->exited) { node->instrumentationStatus = "exited-before-injection"; node->decision = "Exited before injection"; }
    else { node->instrumentationStatus = "failed"; node->decision = "Failed to inject"; }
    if (!diagnostic.empty()) node->reason = diagnostic;
}

void ProcessTreeManager::MarkExited(uint32_t pid, uint64_t exitTime, DWORD exitCode) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = session_.processTreeNodes.rbegin(); it != session_.processTreeNodes.rend(); ++it) if (it->pid == pid && !it->exited) {
        it->exited = true; it->exitTime = exitTime; it->exitCode = exitCode;
        if (it->instrumentationStatus == "pending") it->instrumentationStatus = "exited-before-injection";
        session_.exitedPids.insert(pid); break;
    }
}

void ProcessTreeManager::MarkExitWatchStarted(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& node : session_.processTreeNodes) if (node.pid == pid) { node.exitWatchStarted = true; break; }
}

bool ProcessTreeManager::BelongsToSession(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(session_.processTreeNodes.begin(), session_.processTreeNodes.end(), [pid](const ProcessNode& node) { return node.pid == pid; });
}
bool ProcessTreeManager::HasLiveProcesses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(session_.processTreeNodes.begin(), session_.processTreeNodes.end(), [](const ProcessNode& node) { return node.pid && !node.exited; });
}
bool ProcessTreeManager::IsInjectionPendingOrComplete(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(session_.processTreeNodes.begin(), session_.processTreeNodes.end(), [pid](const ProcessNode& node) {
        return node.pid == pid && (node.instrumentationStatus == "pending" || node.instrumentationStatus == "injected");
    });
}
AnalysisSession ProcessTreeManager::Snapshot() const { std::lock_guard<std::mutex> lock(mutex_); return session_; }
std::vector<ProcessNode> ProcessTreeManager::ProcessSnapshot() const { std::lock_guard<std::mutex> lock(mutex_); return session_.processTreeNodes; }
std::unordered_map<uint32_t, std::string> ProcessTreeManager::ObservedProcessPaths() const {
    std::lock_guard<std::mutex> lock(mutex_); std::unordered_map<uint32_t, std::string> result;
    for (const auto& node : session_.processTreeNodes) if (node.pid && !node.imagePath.empty()) result[node.pid] = Utf8(node.imagePath);
    return result;
}
void ProcessTreeManager::Restore(const AnalysisSession& session) { std::lock_guard<std::mutex> lock(mutex_); session_ = session; session_.active = false; }

} // namespace Inspecthor
