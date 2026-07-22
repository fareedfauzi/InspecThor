#include "child_instrumentation_policy.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <unordered_set>

namespace Inspecthor {
namespace {

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value;
}

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

bool StartsWithPath(const std::wstring& path, const std::wstring& root) {
    if (path.empty() || root.empty()) return false;
    std::error_code ec;
    std::wstring p = std::filesystem::weakly_canonical(path, ec).wstring();
    if (ec) p = path;
    ec.clear();
    std::wstring r = std::filesystem::weakly_canonical(root, ec).wstring();
    if (ec) r = root;
    p = Lower(p); r = Lower(r);
    while (!r.empty() && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
    return p == r || (p.size() > r.size() && p.compare(0, r.size(), r) == 0 && (p[r.size()] == L'\\' || p[r.size()] == L'/'));
}

bool IsUserWritable(const std::wstring& imagePath, const std::wstring& sampleDirectory) {
    std::vector<std::wstring> roots;
    auto addEnvironment = [&](const wchar_t* name) {
        wchar_t value[32768] = {};
        const DWORD length = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
        if (length && length < std::size(value)) roots.emplace_back(value);
    };
    addEnvironment(L"TEMP"); addEnvironment(L"TMP"); addEnvironment(L"APPDATA");
    addEnvironment(L"LOCALAPPDATA"); addEnvironment(L"ProgramData"); addEnvironment(L"PUBLIC");
    wchar_t profile[32768] = {};
    const DWORD length = GetEnvironmentVariableW(L"USERPROFILE", profile, static_cast<DWORD>(std::size(profile)));
    if (length && length < std::size(profile)) {
        const std::filesystem::path user(profile);
        roots.push_back((user / L"Desktop").wstring());
        roots.push_back((user / L"Downloads").wstring());
    }
    if (!sampleDirectory.empty()) roots.push_back(sampleDirectory);
    for (const auto& root : roots) if (StartsWithPath(imagePath, root)) return true;
    return false;
}

bool IsWindowsSystemDirectory(const std::wstring& imagePath) {
    if (imagePath.empty()) return false;
    wchar_t windowsDirectory[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(windowsDirectory, MAX_PATH)) return false;
    const std::filesystem::path windows(windowsDirectory);
    for (const wchar_t* directory : {L"System32", L"SysWOW64", L"Sysnative", L"WinSxS"}) {
        if (StartsWithPath(imagePath, (windows / directory).wstring())) return true;
    }
    return false;
}

std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    if (size) MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

} // namespace

std::string ProcessImageName(const std::string& imagePath, const std::string& commandLine) {
    std::string candidate = imagePath;
    if (candidate.empty()) {
        if (!commandLine.empty() && commandLine.front() == '"') {
            const size_t close = commandLine.find('"', 1);
            candidate = close == std::string::npos ? commandLine.substr(1) : commandLine.substr(1, close - 1);
        } else {
            candidate = commandLine.substr(0, commandLine.find_first_of(" \t"));
        }
    }
    return Lower(std::filesystem::path(candidate).filename().string());
}

ChildInstrumentationDecision DecideChildInstrumentation(const ChildPolicyContext& context, std::string& reason) {
    if (context.mode == ChildMonitoringMode::CommandOnly) {
        reason = "command-only child monitoring mode";
        return ChildInstrumentationDecision::LogCommandOnly;
    }
    const std::wstring widePath = Wide(context.imagePath);
    if (context.sandboxHostedTarget) {
        if (widePath.empty() || !std::filesystem::path(widePath).is_absolute()) {
            reason = "sandbox-hosted target; child path unavailable or unresolved, retained as ETW/command-only";
            return ChildInstrumentationDecision::LogCommandOnly;
        }
        if (IsWindowsSystemDirectory(widePath)) {
            reason = "sandbox-hosted target; Windows system-directory child remains ETW/command-only";
            return ChildInstrumentationDecision::LogCommandOnly;
        }
        reason = "sandbox-hosted target spawned a non-system-directory executable";
        return ChildInstrumentationDecision::InjectAndMonitor;
    }
    if (context.mode == ChildMonitoringMode::Aggressive) {
        reason = "aggressive child monitoring mode";
        return ChildInstrumentationDecision::InjectAndMonitor;
    }
    static const std::unordered_set<std::string> inject = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "msiexec.exe", "control.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "msbuild.exe", "csc.exe", "vbc.exe", "certutil.exe", "bitsadmin.exe",
        "curl.exe", "wget.exe", "python.exe", "node.exe", "java.exe"
    };
    static const std::unordered_set<std::string> commandOnly = {
        "whoami.exe", "hostname.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "net.exe",
        "net1.exe", "reg.exe", "sc.exe", "schtasks.exe", "ping.exe", "findstr.exe", "query.exe",
        "quser.exe", "qwinsta.exe", "nslookup.exe", "arp.exe", "route.exe", "cmdkey.exe", "nltest.exe"
    };
    const std::string name = ProcessImageName(context.imagePath, context.commandLine);
    if (inject.count(name)) {
        reason = "high-value descendant executable";
        return ChildInstrumentationDecision::InjectAndMonitor;
    }
    if (commandOnly.count(name)) {
        reason = "noisy system utility; command and exit status only";
        return ChildInstrumentationDecision::LogCommandOnly;
    }
    if (IsUserWritable(widePath, context.originalSampleDirectory)) {
        reason = "executable launched from a user-writable or original sample directory";
        return ChildInstrumentationDecision::InjectAndMonitor;
    }
    if (name.empty()) {
        reason = "process path unavailable; retained without injection";
        return ChildInstrumentationDecision::LogCommandOnly;
    }
    reason = "unlisted descendant outside monitored user-writable locations";
    return ChildInstrumentationDecision::LogCommandOnly;
}

} // namespace Inspecthor
