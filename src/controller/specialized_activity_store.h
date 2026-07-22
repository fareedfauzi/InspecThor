#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace Inspecthor {

struct SpecializedBehaviorRecord {
    uint64_t timestamp = 0;
    uint32_t pid = 0;
    std::string behavior;
    std::string evidence;
    std::string source;
    uint32_t observations = 0;
    uint64_t firstSeen = 0;
    uint64_t lastSeen = 0;
};

class SpecializedActivityStore {
public:
    static SpecializedActivityStore& Instance();
    void ResetPowerShell();
    void ResetOffice();
    void ResetBatch();
    void AddPowerShell(SpecializedBehaviorRecord record, bool deduplicateLast = true);
    void AddOffice(SpecializedBehaviorRecord record);
    void AddBatch(SpecializedBehaviorRecord record);
    void MarkBatchExecuted(const std::string& lineLabel, uint64_t timestamp);
    std::vector<SpecializedBehaviorRecord> PowerShellSnapshot() const;
    std::vector<SpecializedBehaviorRecord> OfficeSnapshot() const;
    std::vector<SpecializedBehaviorRecord> BatchSnapshot() const;
    void RestorePowerShell(std::vector<SpecializedBehaviorRecord> records);
    void RestoreOffice(std::vector<SpecializedBehaviorRecord> records);
    void RestoreBatch(std::vector<SpecializedBehaviorRecord> records);

private:
    mutable std::mutex mutex_;
    std::vector<SpecializedBehaviorRecord> powershell_;
    std::vector<SpecializedBehaviorRecord> office_;
    std::vector<SpecializedBehaviorRecord> batch_;
};

} // namespace Inspecthor
