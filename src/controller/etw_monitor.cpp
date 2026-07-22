#include "etw_monitor.h"

#include <evntrace.h>
#include <tdh.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

namespace Inspecthor {
void OnChildProcessSpawned(uint32_t childPid, uint32_t parentPid, const std::string& imagePath, const std::string& commandLine);
void OnProcessExited(uint32_t pid, uint32_t exitCode);

namespace {

std::mutex g_EtwMutex;
std::vector<EtwKernelEvent> g_EtwEvents;
std::unordered_set<uint32_t> g_EtwTargetPids;
std::thread g_EtwThread;
std::atomic<bool> g_EtwRunning{ false };
TRACEHANDLE g_SessionHandle = 0;
TRACEHANDLE g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
std::string g_EtwStatus = "Stopped";
bool g_EtwKeepEventsUntilTarget = false;
const std::wstring g_EtwSessionName = L"InspecThor Kernel Telemetry " + std::to_wstring(GetCurrentProcessId());
const GUID g_EtwSessionGuid = {
    0x871b8647 ^ GetCurrentProcessId(),
    0x9d73,
    0x4cd9,
    { 0x82, 0xb8, 0x40, 0xf2, 0x17, 0xdc, 0xd8, 0x24 }
};

static std::string WideToUtf8(const wchar_t* value) {
    if (!value || !value[0]) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return "";
    std::string result(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), needed, nullptr, nullptr);
    return result;
}

static std::string WideBufferToUtf8(const wchar_t* value, int charCount) {
    if (!value || charCount <= 0) return "";
    while (charCount > 0 && value[charCount - 1] == L'\0') {
        --charCount;
    }
    if (charCount <= 0) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, value, charCount, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "";
    std::string result(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, charCount, result.data(), needed, nullptr, nullptr);
    return result;
}

static std::string AnsiBufferToString(const char* value, size_t charCount) {
    if (!value || charCount == 0) return "";
    while (charCount > 0 && value[charCount - 1] == '\0') {
        --charCount;
    }
    return std::string(value, value + charCount);
}

static std::string GuidToString(const GUID& guid) {
    wchar_t buffer[64] = {};
    swprintf_s(
        buffer,
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]
    );
    return WideToUtf8(buffer);
}

static bool IsGuid(const GUID& left, const GUID& right) {
    return IsEqualGUID(left, right) != FALSE;
}

static uint64_t FileTimeToEpochMs(const FILETIME& ft) {
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    if (value.QuadPart < 116444736000000000ULL) {
        return 0;
    }
    return (value.QuadPart - 116444736000000000ULL) / 10000ULL;
}

static void SetEtwStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwStatus = status;
}

static std::string BuildRunningStatusLocked() {
    if (g_EtwTargetPids.empty()) {
        return "Running (waiting for target PID)";
    }
    if (g_EtwTargetPids.size() == 1) {
        return "Running (target PID " + std::to_string(*g_EtwTargetPids.begin()) + ")";
    }
    return "Running (" + std::to_string(g_EtwTargetPids.size()) + " target PIDs)";
}

static bool ShouldRetainEventLocked(uint32_t processId) {
    if (!g_EtwTargetPids.empty()) {
        return g_EtwTargetPids.find(processId) != g_EtwTargetPids.end();
    }
    return g_EtwKeepEventsUntilTarget && processId != 0;
}

static void PruneEventsForTargetsLocked() {
    if (g_EtwTargetPids.empty()) {
        return;
    }
    g_EtwEvents.erase(
        std::remove_if(
            g_EtwEvents.begin(),
            g_EtwEvents.end(),
            [](const EtwKernelEvent& ev) {
                return g_EtwTargetPids.find(ev.processId) == g_EtwTargetPids.end();
            }
        ),
        g_EtwEvents.end()
    );
}

static std::string ReadTraceInfoString(PTRACE_EVENT_INFO info, ULONG infoSize, ULONG nameOffset) {
    if (!info || !nameOffset || nameOffset >= infoSize) {
        return "";
    }
    const wchar_t* value = reinterpret_cast<const wchar_t*>(reinterpret_cast<const BYTE*>(info) + nameOffset);
    return WideToUtf8(value);
}

static std::string BytesToHex(const BYTE* data, ULONG size) {
    std::ostringstream ss;
    ss << "0x";
    ULONG limit = min(size, 16UL);
    for (ULONG i = 0; i < limit; ++i) {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(data[i]);
    }
    if (size > limit) {
        ss << "...";
    }
    return ss.str();
}

static uint64_t ReadUnsignedValue(const BYTE* data, ULONG size) {
    uint64_t value = 0;
    memcpy(&value, data, min(size, static_cast<ULONG>(sizeof(value))));
    return value;
}

static int64_t ReadSignedValue(const BYTE* data, ULONG size) {
    int64_t value = 0;
    if (size == 1) {
        int8_t v = 0;
        memcpy(&v, data, sizeof(v));
        return v;
    }
    if (size == 2) {
        int16_t v = 0;
        memcpy(&v, data, sizeof(v));
        return v;
    }
    if (size == 4) {
        int32_t v = 0;
        memcpy(&v, data, sizeof(v));
        return v;
    }
    memcpy(&value, data, min(size, static_cast<ULONG>(sizeof(value))));
    return value;
}

static std::string FormatEtwPropertyValue(USHORT inType, USHORT outType, const BYTE* data, ULONG size) {
    if (!data || size == 0) {
        return "";
    }

    if (outType == TDH_OUTTYPE_IPV4 && size >= 4) {
        char address[32] = {};
        sprintf_s(address, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
        return address;
    }
    if (outType == TDH_OUTTYPE_IPV6 && size >= 16) {
        std::ostringstream address;
        address << std::hex;
        for (int group = 0; group < 8; ++group) {
            if (group) address << ':';
            address << ((static_cast<unsigned>(data[group * 2]) << 8) | data[group * 2 + 1]);
        }
        return address.str();
    }
    if (outType == TDH_OUTTYPE_PORT && size >= 2) {
        return std::to_string((static_cast<unsigned>(data[0]) << 8) | data[1]);
    }

    switch (inType) {
    case TDH_INTYPE_UNICODESTRING:
        return WideBufferToUtf8(reinterpret_cast<const wchar_t*>(data), static_cast<int>(size / sizeof(wchar_t)));
    case TDH_INTYPE_ANSISTRING:
        return AnsiBufferToString(reinterpret_cast<const char*>(data), size);
    case TDH_INTYPE_BOOLEAN:
        return ReadUnsignedValue(data, size) ? "true" : "false";
    case TDH_INTYPE_INT8:
    case TDH_INTYPE_INT16:
    case TDH_INTYPE_INT32:
    case TDH_INTYPE_INT64:
        return std::to_string(ReadSignedValue(data, size));
    case TDH_INTYPE_UINT8:
    case TDH_INTYPE_UINT16:
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_UINT64:
        if (outType == TDH_OUTTYPE_HEXINT32 || outType == TDH_OUTTYPE_HEXINT64) {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::uppercase << ReadUnsignedValue(data, size);
            return ss.str();
        }
        return std::to_string(ReadUnsignedValue(data, size));
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_HEXINT32:
    case TDH_INTYPE_HEXINT64: {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << ReadUnsignedValue(data, size);
        return ss.str();
    }
    case TDH_INTYPE_GUID:
        if (size >= sizeof(GUID)) {
            return GuidToString(*reinterpret_cast<const GUID*>(data));
        }
        break;
    default:
        break;
    }

    return BytesToHex(data, size);
}

static std::vector<EtwKernelProperty> ReadEventProperties(PEVENT_RECORD record, PTRACE_EVENT_INFO info, ULONG infoSize) {
    std::vector<EtwKernelProperty> properties;
    if (!record || !info) {
        return properties;
    }

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& propInfo = info->EventPropertyInfoArray[i];
        if ((propInfo.Flags & PropertyStruct) != 0) {
            continue;
        }

        std::string name = ReadTraceInfoString(info, infoSize, propInfo.NameOffset);
        if (name.empty()) {
            continue;
        }

        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(reinterpret_cast<const BYTE*>(info) + propInfo.NameOffset);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        ULONG status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > 64 * 1024) {
            continue;
        }

        std::vector<BYTE> propertyBuffer(propertySize);
        status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, propertySize, propertyBuffer.data());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        USHORT inType = propInfo.nonStructType.InType;
        USHORT outType = propInfo.nonStructType.OutType;
        std::string value = FormatEtwPropertyValue(inType, outType, propertyBuffer.data(), propertySize);
        if (!value.empty()) {
            properties.push_back({ name, value });
        }
    }

    return properties;
}

static std::string FindPropertyValue(const EtwKernelEvent& ev, const char* name) {
    for (const auto& prop : ev.properties) {
        if (prop.name == name) {
            return prop.value;
        }
    }
    return "";
}

static std::string FirstMatchingPropertyValue(const EtwKernelEvent& ev, const std::vector<const char*>& names) {
    for (const char* name : names) {
        std::string value = FindPropertyValue(ev, name);
        if (!value.empty()) {
            return value;
        }
    }
    return "";
}

static std::string FirstPropertyNameContains(const EtwKernelEvent& ev, const char* text) {
    for (const auto& prop : ev.properties) {
        if (prop.name.find(text) != std::string::npos && !prop.value.empty()) {
            return prop.value;
        }
    }
    return "";
}

static std::string FriendlyKernelProviderName(const GUID& providerId) {
    static constexpr GUID kProcessGuid = { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
    static constexpr GUID kThreadGuid = { 0x3d6fa8d1, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
    static constexpr GUID kImageLoadGuid = { 0x2cb15d1d, 0x5fc1, 0x11d2, { 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18 } };
    static constexpr GUID kDiskIoGuid = { 0x3d6fa8d4, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
    static constexpr GUID kFileIoGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
    static constexpr GUID kTcpIpGuid = { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
    static constexpr GUID kRegistryGuid = { 0xae53722e, 0xc863, 0x11d2, { 0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 } };

    if (IsGuid(providerId, kProcessGuid)) return "Process";
    if (IsGuid(providerId, kThreadGuid)) return "Thread";
    if (IsGuid(providerId, kImageLoadGuid)) return "Image Load";
    if (IsGuid(providerId, kDiskIoGuid)) return "Disk I/O";
    if (IsGuid(providerId, kFileIoGuid)) return "File I/O";
    if (IsGuid(providerId, kTcpIpGuid)) return "Network TCP/IP";
    if (IsGuid(providerId, kRegistryGuid)) return "Registry";
    return "";
}

static bool ContainsText(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

static std::string FriendlyCategory(const EtwKernelEvent& ev) {
    if (ContainsText(ev.provider, "Process")) return "Process";
    if (ContainsText(ev.provider, "Thread")) return "Thread";
    if (ContainsText(ev.provider, "Image")) return "Module";
    if (ContainsText(ev.provider, "File") || ContainsText(ev.provider, "Disk")) return "File";
    if (ContainsText(ev.provider, "Registry")) return "Registry";
    if (ContainsText(ev.provider, "TCP") || ContainsText(ev.provider, "Network")) return "Network";
    return "Kernel";
}

static std::string FriendlyAction(const EtwKernelEvent& ev) {
    if (!ev.opcode.empty() && ev.opcode != "Event") {
        return ev.opcode;
    }

    if (ev.category == "Module") return "Module load/unload";
    if (ev.category == "Registry") return "Registry access";
    if (ev.category == "File") return "File or disk access";
    if (ev.category == "Network") return "Network activity";
    if (ev.category == "Process") return "Process activity";
    if (ev.category == "Thread") return "Thread activity";
    return ev.task.empty() || ev.task == "Kernel" ? "Kernel event" : ev.task;
}

static std::string BuildFriendlySummary(const EtwKernelEvent& ev) {
    std::ostringstream ss;
    if (ev.category == "Module") {
        ss << "Target process loaded or unloaded executable code";
    } else if (ev.category == "Registry") {
        ss << "Target process touched the Windows registry";
    } else if (ev.category == "File") {
        ss << "Target process performed file or disk I/O";
    } else if (ev.category == "Network") {
        ss << "Target process used network TCP/IP";
    } else if (ev.category == "Process") {
        ss << "Target process lifecycle event";
    } else if (ev.category == "Thread") {
        ss << "Thread activity inside the target process";
    } else {
        ss << "Kernel event from the target process";
    }

    if (!ev.task.empty() && ev.task != "Kernel") {
        ss << " (" << ev.task;
        if (!ev.opcode.empty() && ev.opcode != "Event") {
            ss << " / " << ev.opcode;
        }
        ss << ")";
    }
    return ss.str();
}

static std::string BuildFriendlyDetails(const EtwKernelEvent& ev) {
    if (ev.category == "Module") {
        std::string image = FirstMatchingPropertyValue(ev, { "ImageName", "FileName", "ImageFileName", "ModuleName" });
        if (!image.empty()) return "Image: " + image;
    }

    if (ev.category == "Registry") {
        std::string key = FirstMatchingPropertyValue(ev, { "KeyName", "RelativeName", "ObjectName" });
        std::string value = FirstMatchingPropertyValue(ev, { "ValueName", "ValueKeyName" });
        if (!key.empty() && !value.empty()) return "Key: " + key + " | Value: " + value;
        if (!key.empty()) return "Key: " + key;
        if (!value.empty()) return "Value: " + value;
    }

    if (ev.category == "Process") {
        std::string image = FirstMatchingPropertyValue(ev, { "ImageFileName", "ProcessName", "ImageName", "FileName" });
        std::string commandLine = FirstMatchingPropertyValue(ev, { "CommandLine" });
        std::string parentPid = FirstMatchingPropertyValue(ev, { "ParentID", "ParentProcessID", "ParentProcessId" });
        std::string detail;
        if (!image.empty()) detail = "Image: " + image;
        if (!commandLine.empty()) detail += (detail.empty() ? "" : " | ") + std::string("Command: ") + commandLine;
        if (!parentPid.empty()) detail += (detail.empty() ? "" : " | ") + std::string("Parent PID: ") + parentPid;
        if (!detail.empty()) return detail;
    }

    if (ev.category == "File") {
        std::string file = FirstMatchingPropertyValue(ev, { "FileName", "OpenPath", "Path", "FilePath" });
        if (!file.empty()) return "File: " + file;
    }

    if (ev.category == "Network") {
        std::string sourceAddress = FirstMatchingPropertyValue(ev, { "saddr", "SourceAddress", "LocalAddress" });
        std::string sourcePort = FirstMatchingPropertyValue(ev, { "sport", "SourcePort", "LocalPort" });
        std::string destAddress = FirstMatchingPropertyValue(ev, { "daddr", "DestinationAddress", "RemoteAddress" });
        std::string destPort = FirstMatchingPropertyValue(ev, { "dport", "DestinationPort", "RemotePort" });
        std::string source = sourceAddress;
        if (!sourcePort.empty()) source += ":" + sourcePort;
        std::string dest = destAddress;
        if (!destPort.empty()) dest += ":" + destPort;
        if (!source.empty() && !dest.empty()) return "Connection: " + source + " -> " + dest;
        if (!dest.empty()) return "Remote: " + dest;
    }

    std::string namedObject = FirstPropertyNameContains(ev, "Name");
    if (!namedObject.empty()) {
        return "Object: " + namedObject;
    }

    return "";
}

static EtwKernelEvent BuildEvent(PEVENT_RECORD record) {
    EtwKernelEvent ev;
    FILETIME ft;
    ULARGE_INTEGER ts;
    ts.QuadPart = static_cast<ULONGLONG>(record->EventHeader.TimeStamp.QuadPart);
    ft.dwLowDateTime = ts.LowPart;
    ft.dwHighDateTime = ts.HighPart;

    ev.timestamp = FileTimeToEpochMs(ft);
    ev.processId = record->EventHeader.ProcessId;
    ev.threadId = record->EventHeader.ThreadId;
    ev.eventId = record->EventHeader.EventDescriptor.Id;
    ev.provider = GuidToString(record->EventHeader.ProviderId);

    DWORD bufferSize = 0;
    ULONG status = TdhGetEventInformation(record, 0, nullptr, nullptr, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0 && bufferSize < 64 * 1024) {
        std::vector<BYTE> buffer(bufferSize);
        auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
        status = TdhGetEventInformation(record, 0, nullptr, info, &bufferSize);
        if (status == ERROR_SUCCESS) {
            std::string provider = ReadTraceInfoString(info, bufferSize, info->ProviderNameOffset);
            std::string task = ReadTraceInfoString(info, bufferSize, info->TaskNameOffset);
            std::string opcode = ReadTraceInfoString(info, bufferSize, info->OpcodeNameOffset);
            if (!provider.empty()) ev.provider = provider;
            ev.task = task;
            ev.opcode = opcode;
            ev.properties = ReadEventProperties(record, info, bufferSize);
        }
    }

    std::string friendlyProvider = FriendlyKernelProviderName(record->EventHeader.ProviderId);
    if (!friendlyProvider.empty()) {
        ev.provider = friendlyProvider;
    }

    if (ev.task.empty()) {
        ev.task = ev.provider.empty() ? "Kernel" : ev.provider;
    }
    if (ev.opcode.empty()) {
        ev.opcode = "Event";
    }
    ev.category = FriendlyCategory(ev);
    ev.action = FriendlyAction(ev);
    ev.details = BuildFriendlyDetails(ev);
    ev.summary = BuildFriendlySummary(ev);

    return ev;
}


static VOID WINAPI EtwRecordCallback(PEVENT_RECORD record) {
    if (!record) return;

    uint32_t processId = record->EventHeader.ProcessId;
    bool isProcessStart = false;
    bool isProcessExit = false;
    static constexpr GUID kProcessGuid = { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
    static constexpr GUID kTcpIpGuid = { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
    const bool isNetworkEvent = IsGuid(record->EventHeader.ProviderId, kTcpIpGuid);
    if (IsGuid(record->EventHeader.ProviderId, kProcessGuid) && record->EventHeader.EventDescriptor.Opcode == 1) { // 1 = Start
        isProcessStart = true;
    }
    if (IsGuid(record->EventHeader.ProviderId, kProcessGuid) && record->EventHeader.EventDescriptor.Opcode == 2) { // 2 = End
        isProcessExit = true;
    }

    EtwKernelEvent ev;
    if (isNetworkEvent) {
        ev = BuildEvent(record);
        std::string eventPid = FirstMatchingPropertyValue(ev, { "PID", "ProcessId", "ProcessID" });
        if (!eventPid.empty()) {
            try {
                const uint64_t parsed = std::stoull(eventPid, nullptr, 0);
                if (parsed <= UINT32_MAX) processId = static_cast<uint32_t>(parsed);
            } catch (...) {}
        }
        ev.processId = processId;
        ev.details = BuildFriendlyDetails(ev);
    }
    if (isProcessExit) {
        ev = BuildEvent(record);
        const std::string exitingPid = FirstMatchingPropertyValue(ev, { "ProcessId", "ProcessID", "PID" });
        try { if (!exitingPid.empty()) processId = static_cast<uint32_t>(std::stoul(exitingPid, nullptr, 0)); } catch (...) {}
    }

    {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        if (!isProcessStart && !ShouldRetainEventLocked(processId)) {
            return;
        }
    }

    if (!isNetworkEvent && !isProcessExit) ev = BuildEvent(record);

    if (isProcessExit) {
        uint32_t exitCode = 0;
        const std::string value = FirstMatchingPropertyValue(ev, { "ExitStatus", "ExitCode", "Status" });
        try { if (!value.empty()) exitCode = static_cast<uint32_t>(std::stoul(value, nullptr, 0)); } catch (...) {}
        OnProcessExited(processId, exitCode);
    }
    
    uint32_t parentPid = 0;
    uint32_t childPid = 0;
    if (isProcessStart) {
        std::string parentPidStr = FindPropertyValue(ev, "ParentId");
        if (parentPidStr.empty()) parentPidStr = FindPropertyValue(ev, "ParentProcessId");
        if (parentPidStr.empty()) parentPidStr = FindPropertyValue(ev, "ParentProcessID");
        if (parentPidStr.empty()) parentPidStr = FindPropertyValue(ev, "ParentID");
        
        std::string childPidStr = FindPropertyValue(ev, "ProcessId");
        if (childPidStr.empty()) childPidStr = FindPropertyValue(ev, "ProcessID");
        
        std::string imagePathStr = FindPropertyValue(ev, "ImageFileName");
        if (imagePathStr.empty()) imagePathStr = FindPropertyValue(ev, "ImageName");
        
        std::string commandLineStr = FindPropertyValue(ev, "CommandLine");
        
        try {
            parentPid = parentPidStr.empty() ? 0 : static_cast<uint32_t>(std::stoul(parentPidStr, nullptr, 0));
            childPid = childPidStr.empty() ? 0 : static_cast<uint32_t>(std::stoul(childPidStr, nullptr, 0));
        } catch (...) {}
        
        if (childPid != 0 && parentPid != 0) {
            OnChildProcessSpawned(childPid, parentPid, imagePathStr, commandLineStr);
        }
    }

    bool keepEvent = false;
    {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        if (ShouldRetainEventLocked(ev.processId) || (isProcessStart && (g_EtwTargetPids.find(parentPid) != g_EtwTargetPids.end() || g_EtwTargetPids.find(childPid) != g_EtwTargetPids.end()))) {
            keepEvent = true;
        }
    }

    if (keepEvent) {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        g_EtwEvents.push_back(ev);
        if (g_EtwEvents.size() > 10000) {
            g_EtwEvents.erase(g_EtwEvents.begin(), g_EtwEvents.begin() + 1000);
        }
    }
}

static PEVENT_TRACE_PROPERTIES AllocateKernelTraceProperties();

static void EtwThreadMain() {
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = const_cast<LPWSTR>(g_EtwSessionName.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EtwRecordCallback;

    g_TraceHandle = OpenTraceW(&logfile);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        SetEtwStatus("OpenTrace failed: " + std::to_string(GetLastError()));
        auto props = AllocateKernelTraceProperties();
        if (props) {
            ControlTraceW(g_SessionHandle, g_EtwSessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        g_SessionHandle = 0;
        g_EtwRunning = false;
        return;
    }

    TRACEHANDLE handles[] = { g_TraceHandle };
    ULONG status = ProcessTrace(handles, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        SetEtwStatus("ProcessTrace stopped: " + std::to_string(status));
    }

    if (g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
        g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    g_EtwRunning = false;
}

static PEVENT_TRACE_PROPERTIES AllocateKernelTraceProperties() {
    const size_t loggerNameBytes = (g_EtwSessionName.size() + 1) * sizeof(wchar_t);
    const size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + loggerNameBytes;
    auto props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(calloc(1, bufferSize));
    if (!props) return nullptr;

    props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->Wnode.Guid = g_EtwSessionGuid;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->EnableFlags =
        EVENT_TRACE_FLAG_PROCESS |
        EVENT_TRACE_FLAG_THREAD |
        EVENT_TRACE_FLAG_IMAGE_LOAD |
        EVENT_TRACE_FLAG_DISK_FILE_IO |
        EVENT_TRACE_FLAG_FILE_IO |
        EVENT_TRACE_FLAG_FILE_IO_INIT |
        EVENT_TRACE_FLAG_NETWORK_TCPIP |
        EVENT_TRACE_FLAG_REGISTRY;

    return props;
}

} // namespace

bool StartEtwKernelTelemetry() {
    bool expected = false;
    if (!g_EtwRunning.compare_exchange_strong(expected, true)) {
        return true;
    }

    auto props = AllocateKernelTraceProperties();
    if (!props) {
        g_EtwRunning = false;
        SetEtwStatus("Allocation failed");
        return false;
    }

    ULONG status = StartTraceW(&g_SessionHandle, g_EtwSessionName.c_str(), props);
    free(props);

    if (status != ERROR_SUCCESS) {
        g_EtwRunning = false;
        g_SessionHandle = 0;
        if (status == ERROR_ALREADY_EXISTS) {
            SetEtwStatus("InspecThor ETW session already active");
        } else if (status == ERROR_ACCESS_DENIED) {
            SetEtwStatus("Administrator required");
        } else {
            SetEtwStatus("StartTrace failed: " + std::to_string(status));
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        g_EtwStatus = BuildRunningStatusLocked();
    }
    g_EtwThread = std::thread(EtwThreadMain);
    return true;
}

void StopEtwKernelTelemetry() {
    if (!g_EtwRunning.load() && g_SessionHandle == 0) {
        return;
    }

    TRACEHANDLE traceHandle = g_TraceHandle;
    if (traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(traceHandle);
    }

    auto props = AllocateKernelTraceProperties();
    if (props) {
        ControlTraceW(g_SessionHandle, g_EtwSessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
        free(props);
    }
    g_SessionHandle = 0;

    if (g_EtwThread.joinable()) {
        g_EtwThread.join();
    }

    g_EtwRunning = false;
    {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        g_EtwKeepEventsUntilTarget = false;
        g_EtwStatus = "Stopped";
    }
}

bool IsEtwKernelTelemetryRunning() {
    return g_EtwRunning.load();
}

std::string GetEtwKernelTelemetryStatus() {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    return g_EtwStatus;
}

std::vector<EtwKernelEvent> SnapshotEtwKernelEvents() {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    return g_EtwEvents;
}

void ReplaceEtwKernelEvents(std::vector<EtwKernelEvent> events) {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwEvents = std::move(events);
}

void ClearEtwKernelEvents() {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwEvents.clear();
}

void BeginEtwKernelTargetSession(bool keepEventsUntilTarget) {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwEvents.clear();
    g_EtwTargetPids.clear();
    g_EtwKeepEventsUntilTarget = keepEventsUntilTarget;
    g_EtwStatus = g_EtwRunning.load() ? BuildRunningStatusLocked() : "Waiting for target PID";
}

void AddEtwKernelTargetProcess(uint32_t pid) {
    if (pid == 0) {
        return;
    }

    AddEtwKernelTargetProcesses({ pid });
}

void AddEtwKernelTargetProcesses(const std::vector<uint32_t>& pids) {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    bool addedAny = false;
    for (uint32_t pid : pids) {
        if (pid == 0) {
            continue;
        }
        addedAny = g_EtwTargetPids.insert(pid).second || addedAny;
    }

    if (!addedAny) {
        return;
    }

    g_EtwKeepEventsUntilTarget = false;
    PruneEventsForTargetsLocked();
    if (g_EtwRunning.load()) {
        g_EtwStatus = BuildRunningStatusLocked();
    }
}

size_t GetEtwKernelTargetProcessCount() {
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    return g_EtwTargetPids.size();
}

} // namespace Inspecthor
