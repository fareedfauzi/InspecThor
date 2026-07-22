#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Inspecthor {

struct EtwKernelProperty {
    std::string name;
    std::string value;
};

struct EtwKernelEvent {
    uint64_t timestamp = 0;
    uint32_t processId = 0;
    uint32_t threadId = 0;
    std::string provider;
    std::string task;
    std::string opcode;
    std::string category;
    std::string action;
    std::string details;
    std::string summary;
    std::vector<EtwKernelProperty> properties;
    uint16_t eventId = 0;
};

bool StartEtwKernelTelemetry();
void StopEtwKernelTelemetry();
bool IsEtwKernelTelemetryRunning();
std::string GetEtwKernelTelemetryStatus();
std::vector<EtwKernelEvent> SnapshotEtwKernelEvents();
void ReplaceEtwKernelEvents(std::vector<EtwKernelEvent> events);
void ClearEtwKernelEvents();
void BeginEtwKernelTargetSession(bool keepEventsUntilTarget = false);
void AddEtwKernelTargetProcess(uint32_t pid);
void AddEtwKernelTargetProcesses(const std::vector<uint32_t>& pids);
size_t GetEtwKernelTargetProcessCount();

} // namespace Inspecthor
