#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace Inspecthor {

struct ParameterCapture {
    std::string name;
    std::string type;
    uint64_t value;
    std::vector<uint8_t> memory;
    std::string decoded;

    std::string ToJson() const {
        std::stringstream ss;
        ss << "{\n"
           << "  \"name\": \"" << EscapeJson(name) << "\",\n"
           << "  \"type\": \"" << EscapeJson(type) << "\",\n"
           << "  \"value\": " << value << ",\n"
           << "  \"decoded\": \"" << EscapeJson(decoded) << "\",\n"
           << "  \"memory\": [";
        for (size_t i = 0; i < memory.size(); ++i) {
            ss << (int)memory[i];
            if (i + 1 < memory.size()) ss << ",";
        }
        ss << "]\n"
           << "}";
        return ss.str();
    }

private:
    static std::string EscapeJson(const std::string& s) {
        std::string res;
        for (char c : s) {
            if (c == '"') res += "\\\"";
            else if (c == '\\') res += "\\\\";
            else if (c == '\n') res += "\\n";
            else if (c == '\r') res += "\\r";
            else if (c == '\t') res += "\\t";
            else if (c >= 0 && c < 32) {
                // Ignore other control codes
            } else {
                res += c;
            }
        }
        return res;
    }
};

struct TelemetryEvent {
    uint64_t timestamp; // epoch ms or timestamp counter
    uint32_t processId;
    uint32_t threadId;
    std::string apiName;
    std::string dllName;
    uint64_t callerAddress;
    std::string callerModule;
    uint64_t callerModuleBase;
    uint64_t returnValue;
    std::vector<ParameterCapture> parameters;
    std::vector<uint64_t> callStack;
    // Controller-side correlation tags. Agents may omit these fields; the
    // active AnalysisSession enriches them during ingestion.
    std::string sessionId;
    std::string processRelationship;
    std::string processName;
    std::string processPath;
    bool monitoredProcess = false;

    std::string ToJson() const {
        std::stringstream ss;
        ss << "{\n"
           << "  \"timestamp\": " << timestamp << ",\n"
           << "  \"processId\": " << processId << ",\n"
           << "  \"threadId\": " << threadId << ",\n"
           << "  \"apiName\": \"" << EscapeJson(apiName) << "\",\n"
           << "  \"dllName\": \"" << EscapeJson(dllName) << "\",\n"
           << "  \"callerAddress\": " << callerAddress << ",\n"
           << "  \"callerModule\": \"" << EscapeJson(callerModule) << "\",\n"
           << "  \"callerModuleBase\": " << callerModuleBase << ",\n"
           << "  \"returnValue\": " << returnValue << ",\n"
           << "  \"parameters\": [\n";
        for (size_t i = 0; i < parameters.size(); ++i) {
            ss << parameters[i].ToJson();
            if (i + 1 < parameters.size()) ss << ",\n";
        }
        ss << "\n  ],\n"
           << "  \"callStack\": [";
        for (size_t i = 0; i < callStack.size(); ++i) {
            ss << callStack[i];
            if (i + 1 < callStack.size()) ss << ",";
        }
        ss << "],\n"
           << "  \"sessionId\": \"" << EscapeJson(sessionId) << "\",\n"
           << "  \"processRelationship\": \"" << EscapeJson(processRelationship) << "\",\n"
           << "  \"processName\": \"" << EscapeJson(processName) << "\",\n"
           << "  \"processPath\": \"" << EscapeJson(processPath) << "\",\n"
           << "  \"monitoredProcess\": " << (monitoredProcess ? "true" : "false") << "\n"
           << "}";
        return ss.str();
    }

private:
    static std::string EscapeJson(const std::string& s) {
        std::string res;
        for (char c : s) {
            if (c == '"') res += "\\\"";
            else if (c == '\\') res += "\\\\";
            else if (c == '\n') res += "\\n";
            else if (c == '\r') res += "\\r";
            else if (c == '\t') res += "\\t";
            else if (c >= 0 && c < 32) {
                // Ignore
            } else {
                res += c;
            }
        }
        return res;
    }
};

enum class TraceMode : uint32_t {
    ApiCallerFunctions = 0,
    UserModulesOnly = 1
};

enum TraceConfigFlags : uint32_t {
    TraceConfigHookNetwork = 1u << 0,
    TraceConfigHookMemoryCopies = 1u << 1,
    TraceConfigHookHeap = 1u << 2,
    TraceConfigHookAdvancedNative = 1u << 3
};

#pragma pack(push, 1)
struct TraceConfig {
    TraceMode traceMode = TraceMode::ApiCallerFunctions;
    uint64_t reservedAddress = 0;
    uint32_t flags = TraceConfigHookNetwork;
};
#pragma pack(pop)

// Message structure for named pipe commands
enum class MessageType : uint32_t {
    RegisterClient = 1,
    SendConfig = 2,
    ReadyToTrace = 3,
    TelemetryData = 4,
    AgentError = 5
};

struct PipeHeader {
    MessageType type;
    uint32_t payloadLength; // Length of the trailing payload data
};

} // namespace Inspecthor
