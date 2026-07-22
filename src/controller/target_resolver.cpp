#include "target_resolver.h"
#include "office_target_resolver.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>

namespace Inspecthor {
namespace {

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
    return value;
}

std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
        } else if (ch == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            slashes = 0;
        } else {
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(ch);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring NativeSystemPath(const wchar_t* executable) {
    wchar_t windowsDir[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) return {};
#if defined(_WIN64)
    std::filesystem::path base = std::filesystem::path(windowsDir) / L"System32";
#else
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    std::filesystem::path base = std::filesystem::path(windowsDir) / (wow64 ? L"Sysnative" : L"System32");
#endif
    std::filesystem::path result = base / executable;
    if (std::filesystem::exists(result)) return result.wstring();
    wchar_t systemDir[MAX_PATH] = {};
    if (GetSystemDirectoryW(systemDir, MAX_PATH)) return (std::filesystem::path(systemDir) / executable).wstring();
    return result.wstring();
}

std::wstring NativePowerShellPath() {
    wchar_t windowsDir[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) return L"powershell.exe";
#if defined(_WIN64)
    std::filesystem::path system = std::filesystem::path(windowsDir) / L"System32";
#else
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    std::filesystem::path system = std::filesystem::path(windowsDir) / (wow64 ? L"Sysnative" : L"System32");
#endif
    return (system / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe").wstring();
}

std::wstring InstalledPowerShellVersion() {
    wchar_t version[128] = {};
    DWORD bytes = sizeof(version);
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", L"PowerShellVersion",
        RRF_RT_REG_SZ, nullptr, version, &bytes);
    if (status != ERROR_SUCCESS) {
        bytes = sizeof(version);
        status = RegGetValueW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", L"PowerShellVersion",
            RRF_RT_REG_SZ, nullptr, version, &bytes);
    }
    return status == ERROR_SUCCESS ? std::wstring(version) : L"Windows PowerShell (version unavailable)";
}

std::wstring WindowsPath(const wchar_t* executable) {
    wchar_t windowsDir[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) return {};
    return (std::filesystem::path(windowsDir) / executable).wstring();
}

OtherTargetType Detect(const std::wstring& path) {
    const std::wstring ext = Lower(std::filesystem::path(path).extension().wstring());
    if (ext == L".bat" || ext == L".cmd") return OtherTargetType::Batch;
    if (ext == L".vbs" || ext == L".vbe" || ext == L".js" || ext == L".jse" || ext == L".wsf") return OtherTargetType::Script;
    if (ext == L".hta") return OtherTargetType::Hta;
    if (ext == L".msi") return OtherTargetType::Msi;
    if (ext == L".cpl") return OtherTargetType::Cpl;
    if (ext == L".scr") return OtherTargetType::Scr;
    if (ext == L".lnk") return OtherTargetType::Shortcut;
    if (ext == L".url") return OtherTargetType::InternetShortcut;
    if (ext == L".ps1") return OtherTargetType::PowerShell;
    if (IsSupportedOfficeTarget(path)) return OtherTargetType::Office;
    return OtherTargetType::Auto;
}

void AppendUserArguments(std::wstring& arguments, const std::wstring& userArguments) {
    if (!userArguments.empty()) {
        if (!arguments.empty()) arguments.push_back(L' ');
        arguments += userArguments;
    }
}

} // namespace

const wchar_t* OtherTargetTypeName(OtherTargetType type) {
    switch (type) {
    case OtherTargetType::Batch: return L"BAT / CMD";
    case OtherTargetType::Script: return L"VBS / VBE / JS / JSE / WSF";
    case OtherTargetType::Hta: return L"HTA";
    case OtherTargetType::Msi: return L"MSI";
    case OtherTargetType::Cpl: return L"CPL";
    case OtherTargetType::Scr: return L"SCR";
    case OtherTargetType::Shortcut: return L"LNK";
    case OtherTargetType::InternetShortcut: return L"URL";
    case OtherTargetType::PowerShell: return L"PowerShell Script (.ps1)";
    case OtherTargetType::Office: return L"Office Document";
    default: return L"Unsupported";
    }
}

TargetProfile ResolveTargetProfile(const std::wstring& targetPath, const std::wstring& userArguments, OtherTargetType overrideType) {
    TargetProfile profile;
    std::error_code ec;
    std::filesystem::path absolute = std::filesystem::absolute(targetPath, ec);
    profile.originalPath = ec ? targetPath : absolute.lexically_normal().wstring();
    if (targetPath.empty()) {
        profile.error = L"Select a target file.";
        return profile;
    }
    if (!std::filesystem::is_regular_file(profile.originalPath, ec)) {
        profile.error = L"Target file does not exist or is not a regular file: " + profile.originalPath;
        return profile;
    }

    const OtherTargetType detected = Detect(profile.originalPath);
    const OtherTargetType type = overrideType == OtherTargetType::Auto ? detected : overrideType;
    if (type == OtherTargetType::Auto) {
        profile.error = L"Unsupported file type. Supported launcher files are PS1, BAT, CMD, VBS, VBE, JS, JSE, WSF, HTA, MSI, CPL, SCR, LNK, URL, DOC/DOCM, XLS/XLSM/XLL, PPT/PPTM, and ONE.";
        return profile;
    }

    profile.detectedType = OtherTargetTypeName(detected == OtherTargetType::Auto ? type : detected);
    profile.workingDirectory = std::filesystem::path(profile.originalPath).parent_path().wstring();
    const std::wstring quotedTarget = Quote(profile.originalPath);
    switch (type) {
    case OtherTargetType::Batch:
        profile.launcherPath = NativeSystemPath(L"cmd.exe");
        profile.launcherArguments = L"/d /s /c \"" + quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.launcherArguments += L"\"";
        profile.executionMode = L"Launcher-based (Command Processor)";
        profile.notes = L"cmd.exe is monitored with ETW only by default; parsed source commands and selectively instrumented descendants provide the primary findings.";
        break;
    case OtherTargetType::Script:
        profile.launcherPath = NativeSystemPath(L"cscript.exe");
        profile.launcherArguments = L"//nologo " + quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"Launcher-based (Windows Script Host)";
        profile.notes = L"cscript.exe remains ETW-only; source statements, console output, and selectively instrumented descendants are correlated in Scripts, PS.";
        break;
    case OtherTargetType::Hta:
        profile.launcherPath = NativeSystemPath(L"mshta.exe");
        profile.launcherArguments = quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"Launcher-based (MSHTA)";
        profile.notes = L"mshta.exe remains ETW-only; child processes and system effects are monitored by the sandbox telemetry layers.";
        break;
    case OtherTargetType::Msi:
        profile.launcherPath = NativeSystemPath(L"msiexec.exe");
        profile.launcherArguments = L"/i " + quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"Launcher-based (Windows Installer)";
        profile.notes = L"msiexec.exe remains ETW-only; installer child processes and resulting system changes are correlated across the session.";
        break;
    case OtherTargetType::Cpl:
        profile.launcherPath = NativeSystemPath(L"control.exe");
        profile.launcherArguments = quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"Launcher-based (Control Panel)";
        profile.notes = L"control.exe remains ETW-only; spawned processes and system effects are monitored across the session.";
        break;
    case OtherTargetType::Scr:
        profile.launcherPath = profile.originalPath;
        profile.launcherArguments = userArguments;
        profile.executionMode = L"Direct executable";
        profile.notes = L"Screen saver files are PE executables and run through the normal injected launch path.";
        break;
    case OtherTargetType::Shortcut:
    case OtherTargetType::InternetShortcut:
        profile.launcherPath = WindowsPath(L"explorer.exe");
        profile.launcherArguments = quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"ShellExecute-based (Explorer host)";
        profile.requiresShellExecute = true;
        profile.notes = L"Explorer is used as the instrumentable ShellExecute host; spawned descendants remain tracked.";
        break;
    case OtherTargetType::PowerShell:
        profile.launcherPath = NativePowerShellPath();
        profile.launcherArguments = L"-NoProfile -ExecutionPolicy Bypass -File " + quotedTarget;
        AppendUserArguments(profile.launcherArguments, userArguments);
        profile.executionMode = L"PowerShell Script Analysis";
        profile.powerShellVersion = InstalledPowerShellVersion();
        profile.executionPolicy = L"Bypass (process scope)";
        profile.notes = L"powershell.exe remains ETW-only by default; PowerShell trace output, source intelligence, and selectively instrumented descendants provide the script findings.";
        break;
    case OtherTargetType::Office:
        return ResolveOfficeTargetProfile(profile.originalPath, userArguments);
    default:
        profile.error = L"Unable to resolve the selected target type.";
        return profile;
    }
    profile.isLauncherBased = profile.launcherPath != profile.originalPath;
    if (!std::filesystem::is_regular_file(profile.launcherPath, ec)) {
        profile.error = L"Required Windows launcher was not found: " + profile.launcherPath;
    }
    return profile;
}

} // namespace Inspecthor
