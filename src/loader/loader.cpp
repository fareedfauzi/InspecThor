#include <windows.h>
#include <iostream>
#include <string>

// Helper to convert wstring to string
static std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Function signature for standard DLL export calls with no arguments
typedef void (WINAPI *ExportFunc_t)();

int wmain(int argc, wchar_t* argv[]) {
    // Expected arguments: InspecthorLoader.exe <dll_path> <mode: dllmain | export> [export_name]
    // Or: InspecthorLoader.exe <pid> inject_pid <dll_path>
    if (argc < 3) {
        std::wcout << L"Usage: " << argv[0] << L" <dll_path> <mode: dllmain|export> [export_name]\n";
        std::wcout << L"Usage for injection: " << argv[0] << L" <pid> inject_pid <dll_path>\n";
        return 1;
    }

    std::wstring arg1 = argv[1];
    std::wstring mode = argv[2];

    if (mode == L"inject_pid") {
        if (argc < 4) {
            std::wcout << L"Usage for injection: " << argv[0] << L" <pid> inject_pid <dll_path>\n";
            return 1;
        }
        DWORD pid = _wtoi(arg1.c_str());
        std::wstring dllToInject = argv[3];

        std::wcout << L"[loader] Injecting DLL: " << dllToInject << L" into PID: " << pid << std::endl;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::wcout << L"[loader] Failed to open process. Error: " << GetLastError() << std::endl;
            return 1;
        }

        size_t size = (dllToInject.size() + 1) * sizeof(wchar_t);
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            std::wcout << L"[loader] VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        if (!WriteProcessMemory(hProcess, remoteMem, dllToInject.c_str(), size, NULL)) {
            std::wcout << L"[loader] WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return 1;
        }

        LPVOID loadLibraryWAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryWAddr, remoteMem, 0, NULL);
        if (!hThread) {
            std::wcout << L"[loader] CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return 1;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        std::wcout << L"[loader] Injection successful." << std::endl;
        return 0;
    }

    std::wstring dllPath = arg1;
    std::string exportName = "";
    if (argc >= 4) {
        exportName = WStringToString(argv[3]);
    }

    std::wcout << L"[loader] Loading DLL: " << dllPath << L" in mode: " << mode << std::endl;

    // Load target DLL
    HMODULE hMod = LoadLibraryW(dllPath.c_str());
    if (!hMod) {
        std::wcout << L"[loader] Failed to load DLL. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"[loader] DLL loaded successfully. HMODULE: 0x" << std::hex << hMod << std::endl;

    if (mode == L"export" && !exportName.empty()) {
        std::wcout << L"[loader] Locating export: " << argv[3] << std::endl;
        ExportFunc_t func = (ExportFunc_t)GetProcAddress(hMod, exportName.c_str());
        if (!func) {
            std::wcout << L"[loader] Export not found in DLL via GetProcAddress." << std::endl;
            FreeLibrary(hMod);
            return 1;
        }

        std::wcout << L"[loader] Executing export..." << std::endl;
        // Call the export
        func();
        std::wcout << L"[loader] Export execution completed." << std::endl;
    } else {
        std::wcout << L"[loader] DLL initialized via DllMain only. Keeping loaded." << std::endl;
    }

    // Keep loader alive for a bit or wait for user to let the trace finish
    std::wcout << L"[loader] Execution complete. Waiting 2 seconds before termination..." << std::endl;
    Sleep(2000);

    FreeLibrary(hMod);
    std::wcout << L"[loader] Exiting." << std::endl;
    return 0;
}
