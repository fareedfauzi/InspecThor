#pragma once

#include <string>

namespace Inspecthor {

enum class OtherTargetType {
    Auto = 0,
    Batch,
    Script,
    Hta,
    Msi,
    Cpl,
    Scr,
    Shortcut,
    InternetShortcut,
    PowerShell,
    Office
};

struct TargetProfile {
    std::wstring originalPath;
    std::wstring detectedType;
    std::wstring launcherPath;
    std::wstring launcherArguments;
    std::wstring workingDirectory;
    std::wstring executionMode;
    std::wstring powerShellVersion;
    std::wstring executionPolicy;
    std::wstring officeHost;
    bool isOffice = false;
    bool isLauncherBased = false;
    bool requiresShellExecute = false;
    std::wstring notes;
    std::wstring error;

    bool IsValid() const { return error.empty(); }
};

TargetProfile ResolveTargetProfile(
    const std::wstring& targetPath,
    const std::wstring& userArguments,
    OtherTargetType overrideType = OtherTargetType::Auto);

const wchar_t* OtherTargetTypeName(OtherTargetType type);

} // namespace Inspecthor
