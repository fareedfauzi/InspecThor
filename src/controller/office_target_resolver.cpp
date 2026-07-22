#include "office_target_resolver.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>

namespace Inspecthor {
namespace {

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

std::wstring Quote(const std::wstring& value) { return L"\"" + value + L"\""; }

std::wstring RegisteredApplicationPath(const std::wstring& executable) {
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + executable;
    for (HKEY hive : { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE }) {
        for (DWORD view : { RRF_SUBKEY_WOW6464KEY, RRF_SUBKEY_WOW6432KEY }) {
            wchar_t value[32768] = {};
            DWORD bytes = sizeof(value);
            if (RegGetValueW(hive, subkey.c_str(), nullptr, RRF_RT_REG_SZ | view, nullptr, value, &bytes) == ERROR_SUCCESS &&
                std::filesystem::is_regular_file(value)) return value;
        }
    }
    wchar_t found[32768] = {};
    if (SearchPathW(nullptr, executable.c_str(), nullptr, static_cast<DWORD>(std::size(found)), found, nullptr) &&
        std::filesystem::is_regular_file(found)) return found;
    return {};
}

std::wstring ExplorerPath() {
    wchar_t windows[MAX_PATH] = {};
    return GetWindowsDirectoryW(windows, MAX_PATH) ? (std::filesystem::path(windows) / L"explorer.exe").wstring() : L"explorer.exe";
}

} // namespace

bool IsSupportedOfficeTarget(const std::wstring& path) {
    const std::wstring ext = Lower(std::filesystem::path(path).extension().wstring());
    return ext == L".docm" || ext == L".xlsm" || ext == L".pptm" || ext == L".doc" ||
        ext == L".xls" || ext == L".ppt" || ext == L".xll" || ext == L".one";
}

TargetProfile ResolveOfficeTargetProfile(const std::wstring& targetPath, const std::wstring& userArguments) {
    TargetProfile profile;
    std::error_code ec;
    profile.originalPath = std::filesystem::absolute(targetPath, ec).lexically_normal().wstring();
    if (ec) profile.originalPath = targetPath;
    if (!std::filesystem::is_regular_file(profile.originalPath)) {
        profile.error = L"Office target does not exist: " + profile.originalPath;
        return profile;
    }
    const std::wstring ext = Lower(std::filesystem::path(profile.originalPath).extension().wstring());
    std::wstring host;
    if (ext == L".doc" || ext == L".docm") host = L"WINWORD.EXE";
    else if (ext == L".xls" || ext == L".xlsm" || ext == L".xll") host = L"EXCEL.EXE";
    else if (ext == L".ppt" || ext == L".pptm") host = L"POWERPNT.EXE";
    else if (ext == L".one") host = L"ONENOTE.EXE";
    else { profile.error = L"Unsupported Office target type."; return profile; }
    profile.detectedType = L"Office " + ext.substr(1);
    profile.workingDirectory = std::filesystem::path(profile.originalPath).parent_path().wstring();
    profile.launcherPath = RegisteredApplicationPath(host);
    profile.launcherArguments = Quote(profile.originalPath);
    if (!userArguments.empty()) profile.launcherArguments += L" " + userArguments;
    profile.executionMode = L"Office Document Analysis";
    profile.isLauncherBased = true;
    profile.officeHost = host;
    profile.isOffice = true;
    if (profile.launcherPath.empty()) {
        profile.launcherPath = ExplorerPath();
        profile.requiresShellExecute = true;
        profile.notes = host + L" was not resolved through App Paths or PATH. Explorer ShellExecute fallback will track the first meaningful descendant as primary.";
    } else if (ext == L".xll") {
        profile.notes = L"XLL loaded by Excel; the module is suspicious by default and will be highlighted in DLL Activity.";
    }
    if (!std::filesystem::is_regular_file(profile.launcherPath)) profile.error = L"Office host and ShellExecute fallback could not be resolved.";
    return profile;
}

} // namespace Inspecthor
