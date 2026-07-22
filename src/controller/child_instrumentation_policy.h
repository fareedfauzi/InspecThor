#pragma once

#include "analysis_session.h"

namespace Inspecthor {

struct ChildPolicyContext {
    std::string imagePath;
    std::string commandLine;
    std::string parentProcessName;
    uint32_t parentPid = 0;
    std::string targetType;
    std::wstring originalSampleDirectory;
    bool sandboxHostedTarget = false;
    ChildMonitoringMode mode = ChildMonitoringMode::Smart;
};

ChildInstrumentationDecision DecideChildInstrumentation(const ChildPolicyContext& context, std::string& reason);
std::string ProcessImageName(const std::string& imagePath, const std::string& commandLine);

} // namespace Inspecthor
