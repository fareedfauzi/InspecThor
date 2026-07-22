#include "specialized_activity_store.h"
#include <algorithm>

namespace Inspecthor {

SpecializedActivityStore& SpecializedActivityStore::Instance() { static SpecializedActivityStore store; return store; }
void SpecializedActivityStore::ResetPowerShell() { std::lock_guard<std::mutex> lock(mutex_); powershell_.clear(); }
void SpecializedActivityStore::ResetOffice() { std::lock_guard<std::mutex> lock(mutex_); office_.clear(); }
void SpecializedActivityStore::ResetBatch() { std::lock_guard<std::mutex> lock(mutex_); batch_.clear(); }
void SpecializedActivityStore::AddPowerShell(SpecializedBehaviorRecord record, bool deduplicateLast) {
    std::lock_guard<std::mutex> lock(mutex_); if (powershell_.size() >= 1000) return;
    if (deduplicateLast && !powershell_.empty()) { const auto& last = powershell_.back();
        if (last.pid == record.pid && last.behavior == record.behavior && last.evidence == record.evidence) return; }
    powershell_.push_back(std::move(record));
}
void SpecializedActivityStore::AddOffice(SpecializedBehaviorRecord record) { std::lock_guard<std::mutex> lock(mutex_); if (office_.size() < 1000) office_.push_back(std::move(record)); }
void SpecializedActivityStore::AddBatch(SpecializedBehaviorRecord record) { std::lock_guard<std::mutex> lock(mutex_); if (batch_.size() < 5000) batch_.push_back(std::move(record)); }
void SpecializedActivityStore::MarkBatchExecuted(const std::string& lineLabel, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = std::find_if(batch_.begin(), batch_.end(), [&](const SpecializedBehaviorRecord& row) { return row.behavior == lineLabel; });
    if (found == batch_.end()) return;
    ++found->observations;
    if (!found->firstSeen) found->firstSeen = timestamp;
    found->lastSeen = timestamp;
}
std::vector<SpecializedBehaviorRecord> SpecializedActivityStore::PowerShellSnapshot() const { std::lock_guard<std::mutex> lock(mutex_); return powershell_; }
std::vector<SpecializedBehaviorRecord> SpecializedActivityStore::OfficeSnapshot() const { std::lock_guard<std::mutex> lock(mutex_); return office_; }
std::vector<SpecializedBehaviorRecord> SpecializedActivityStore::BatchSnapshot() const { std::lock_guard<std::mutex> lock(mutex_); return batch_; }
void SpecializedActivityStore::RestorePowerShell(std::vector<SpecializedBehaviorRecord> records) { std::lock_guard<std::mutex> lock(mutex_); powershell_ = std::move(records); }
void SpecializedActivityStore::RestoreOffice(std::vector<SpecializedBehaviorRecord> records) { std::lock_guard<std::mutex> lock(mutex_); office_ = std::move(records); }
void SpecializedActivityStore::RestoreBatch(std::vector<SpecializedBehaviorRecord> records) { std::lock_guard<std::mutex> lock(mutex_); batch_ = std::move(records); }

} // namespace Inspecthor
