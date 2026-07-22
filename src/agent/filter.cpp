#include "filter.h"
#include <algorithm>
#include <cwctype>

namespace Inspecthor {

// Helper to convert wstring to string
static std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

CallerFilter::CallerFilter() {
    m_config.traceMode = TraceMode::ApiCallerFunctions;
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        m_mainModulePath = path;
        std::wstring wpath(path);
        size_t lastSlash = wpath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            m_mainModuleName = wpath.substr(lastSlash + 1);
        } else {
            m_mainModuleName = wpath;
        }
    }
}

void CallerFilter::Configure(const TraceConfig& config) {
    m_config = config;
}

void CallerFilter::SetMainModuleName(const std::wstring& name) {
    m_mainModuleName = name;
}

bool CallerFilter::ShouldTrace(void* callerAddress, std::string& outModuleName) {
    HMODULE hMod = NULL;
    
    // Resolve address to a loaded module handle
    BOOL success = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)callerAddress,
        &hMod
    );

    if (!success || hMod == NULL) {
        // Unknown memory region check (Shellcode / Reflective / Manual mapped)
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(callerAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
            if (isExecutable) {
                outModuleName = "Unknown (Shellcode/Mapped)";
                return true; // Always allow unknown executable regions
            }
        }
        outModuleName = "Unknown (Non-Executable)";
        return false;
    }

    std::wstring modulePath;
    std::wstring moduleName;

    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_moduleCache.find(hMod);
        if (it != m_moduleCache.end()) {
            modulePath = it->second;
        } else {
            wchar_t path[MAX_PATH];
            if (GetModuleFileNameW(hMod, path, MAX_PATH)) {
                modulePath = path;
                m_moduleCache[hMod] = path;
            } else {
                modulePath = L"";
            }
        }
    }

    if (modulePath.empty()) {
        outModuleName = "Unknown Module";
        return false;
    }

    size_t lastSlash = modulePath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        moduleName = modulePath.substr(lastSlash + 1);
    } else {
        moduleName = modulePath;
    }

    outModuleName = WStringToString(moduleName);

    // Always exclude our agent's own DLLs
    std::string lowerName = outModuleName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    if (lowerName == "inspecthoragent.dll" || lowerName == "inspecthoragent32.dll") {
        return false;
    }

    // Apply filtering modes
    // Check if it is the main executable
    bool isMain = (hMod == GetModuleHandleW(NULL));

    if (m_config.traceMode == TraceMode::UserModulesOnly || m_config.traceMode == TraceMode::ApiCallerFunctions) {
        if (isMain) {
            return true;
        }
        // Suppress Windows system libraries
        return !IsWindowsSystemLibrary(modulePath);
    }

    return true;
}

bool CallerFilter::IsWindowsSystemLibrary(const std::wstring& modulePath) {
    // Convert to lowercase for comparison
    std::wstring pathLower = modulePath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);

    // System directories check
    if (pathLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
        pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
        pathLower.find(L"\\windows\\winsxs\\") != std::wstring::npos) {
        return true;
    }

    // Direct library list check
    std::wstring nameLower = pathLower;
    size_t lastSlash = pathLower.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        nameLower = pathLower.substr(lastSlash + 1);
    }

    static const std::vector<std::wstring> systemLibs = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
        L"gdi32.dll", L"advapi32.dll", L"comcb.dll", L"combase.dll",
        L"rpcrt4.dll", L"sechost.dll", L"ws2_32.dll", L"wininet.dll",
        L"shlwapi.dll", L"shell32.dll", L"ole32.dll", L"oleaut32.dll",
        L"bcrypt.dll", L"crypt32.dll", L"msvcrt.dll", L"ucrtbase.dll",
        L"vcruntime140.dll"
    };

    for (const auto& lib : systemLibs) {
        if (nameLower == lib) {
            return true;
        }
    }

    return false;
}

} // namespace Inspecthor
