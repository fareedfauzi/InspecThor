#include "injector.h"
#include "telemetry.h"
#include "pipe_io.h"
#include <iostream>
#include <vector>
#include <string>

namespace Inspecthor {

static std::wstring GetModuleDir() {
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring pathStr(modulePath);
    size_t lastSlash = pathStr.find_last_of(L"\\/");
    return (lastSlash == std::wstring::npos) ? L"" : pathStr.substr(0, lastSlash + 1);
}

static bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::wstring GetRundll32Path(bool is32Bit) {
    wchar_t windowsDir[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(windowsDir, MAX_PATH)) {
        return L"rundll32.exe";
    }

    std::wstring base(windowsDir);
    std::wstring path = base + (is32Bit ? L"\\SysWOW64\\rundll32.exe" : L"\\System32\\rundll32.exe");
    if (!FileExists(path)) {
        path = base + L"\\System32\\rundll32.exe";
    }
    return path;
}

static bool TryGetPeMachine(const std::wstring& filePath, WORD& machine, WORD* characteristics = nullptr) {
    machine = 0;
    if (characteristics) *characteristics = 0;
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <
        static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))) {
        CloseHandle(hFile);
        return false;
    }

    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS32 ntHeaders = {};
    DWORD read = 0;

    bool valid = false;
    if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &read, NULL) && read == sizeof(dosHeader)) {
        if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE && dosHeader.e_lfanew >= sizeof(IMAGE_DOS_HEADER) &&
            static_cast<LONGLONG>(dosHeader.e_lfanew) <= fileSize.QuadPart - static_cast<LONGLONG>(sizeof(ntHeaders))) {
            LARGE_INTEGER ntOffset = {};
            ntOffset.QuadPart = dosHeader.e_lfanew;
            if (SetFilePointerEx(hFile, ntOffset, nullptr, FILE_BEGIN)) {
                if (ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &read, NULL) && read == sizeof(ntHeaders)) {
                    if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                        machine = ntHeaders.FileHeader.Machine;
                        if (characteristics) *characteristics = ntHeaders.FileHeader.Characteristics;
                        valid = machine == IMAGE_FILE_MACHINE_I386 || machine == IMAGE_FILE_MACHINE_AMD64;
                    }
                }
            }
        }
    }

    CloseHandle(hFile);
    return valid;
}

// Parses PE headers of a file to check if it is 32-bit (x86).
bool Injector::IsFile32Bit(const std::wstring& filePath) {
    WORD machine = 0;
    return TryGetPeMachine(filePath, machine) && machine == IMAGE_FILE_MACHINE_I386;
}

static bool WaitForPipeBytes(HANDLE pipe, DWORD requiredBytes, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline) {
        DWORD available = 0;
        const BOOL peeked = PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr);
        if (peeked && available >= requiredBytes) return true;
        if (!peeked) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) return false;
        }
        Sleep(10);
    }
    return false;
}

// Named Pipe handshake helper
static bool PerformPipeHandshake(HANDLE hPipe, DWORD targetPid, const TraceConfig& traceConfig, std::string* diagnosticOutput) {
    const ULONGLONG connectDeadline = GetTickCount64() + 10000;
    bool connected = false;
    while (GetTickCount64() < connectDeadline) {
        if (ConnectNamedPipe(hPipe, nullptr)) { connected = true; break; }
        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) { connected = true; break; }
        if (error != ERROR_PIPE_LISTENING && error != ERROR_NO_DATA) break;
        Sleep(10);
    }
    if (!connected) {
        if (diagnosticOutput) *diagnosticOutput += "[agent] timed out waiting for telemetry pipe connection.\n";
        return false;
    }
    DWORD blockingMode = PIPE_READMODE_BYTE | PIPE_WAIT;
    SetNamedPipeHandleState(hPipe, &blockingMode, nullptr, nullptr);

    // Read MessageType::RegisterClient
    PipeHeader regHeader = {};
    if (!WaitForPipeBytes(hPipe, sizeof(regHeader), 10000) || !ReadPipeExact(hPipe, &regHeader, sizeof(regHeader))) {
        return false;
    }

    if (regHeader.type != MessageType::RegisterClient) {
        return false;
    }

    // Write MessageType::SendConfig (Sends trace mode and settings)
    PipeHeader configHeader = {};
    configHeader.type = MessageType::SendConfig;
    configHeader.payloadLength = sizeof(TraceConfig);
    
    if (!WritePipeExact(hPipe, &configHeader, sizeof(configHeader)) ||
        !WritePipeExact(hPipe, &traceConfig, sizeof(traceConfig))) {
        return false;
    }

    // Read MessageType::ReadyToTrace
    PipeHeader readyHeader = {};
    if (!WaitForPipeBytes(hPipe, sizeof(readyHeader), 15000) || !ReadPipeExact(hPipe, &readyHeader, sizeof(readyHeader))) {
        if (diagnosticOutput) *diagnosticOutput += "[agent] handshake ended before readiness response.\n";
        return false;
    }
    std::string readyPayload;
    if (readyHeader.payloadLength > 0 && readyHeader.payloadLength <= 64 * 1024) {
        readyPayload.resize(readyHeader.payloadLength);
        if (!WaitForPipeBytes(hPipe, readyHeader.payloadLength, 5000) || !ReadPipeExact(hPipe, readyPayload.data(), readyPayload.size())) {
            if (diagnosticOutput) *diagnosticOutput += "[agent] incomplete readiness diagnostic.\n";
            return false;
        }
    }
    if (readyHeader.type != MessageType::ReadyToTrace && diagnosticOutput) {
        *diagnosticOutput += "[agent] " + (readyPayload.empty() ? std::string("hook installation failed") : readyPayload) + ".\n";
    }
    return (readyHeader.type == MessageType::ReadyToTrace);
}

static bool DirectInject(HANDLE hProcess, const std::wstring& dllPath) {
    if (!FileExists(dllPath)) return false;
    size_t size = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;
    
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    LPVOID loadLibraryWAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryWAddr, remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    DWORD res = WaitForSingleObject(hThread, 5000);
    if (res != WAIT_OBJECT_0) {
        CloseHandle(hThread);
        return false;
    }
    DWORD remoteModule = 0;
    const bool loaded = GetExitCodeThread(hThread, &remoteModule) && remoteModule != 0;
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return loaded;
}

static bool CreateHiddenOutputPipe(HANDLE& readPipe, HANDLE& writePipe) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        readPipe = NULL;
        writePipe = NULL;
        return false;
    }

    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    return true;
}

static void CloseIfValid(HANDLE& handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
        handle = NULL;
    }
}

static std::string ReadPipeToString(HANDLE pipe) {
    std::string output;
    if (!pipe || pipe == INVALID_HANDLE_VALUE) {
        return output;
    }

    char buffer[512];
    DWORD read = 0;
    while (ReadFile(pipe, buffer, sizeof(buffer) - 1, &read, NULL) && read > 0) {
        buffer[read] = '\0';
        output.append(buffer, read);
    }
    return output;
}

static bool HelperInject(DWORD pid, const std::wstring& loaderExePath, const std::wstring& dllPath, std::string* capturedOutput) {
    if (!FileExists(loaderExePath) || !FileExists(dllPath)) {
        if (capturedOutput) *capturedOutput += "[loader] helper executable or agent DLL is missing.\n";
        return false;
    }
    std::wstring cmdLine = L"\"" + loaderExePath + L"\" " + std::to_wstring(pid) + L" inject_pid \"" + dllPath + L"\"";

    HANDLE outputRead = NULL;
    HANDLE outputWrite = NULL;
    CreateHiddenOutputPipe(outputRead, outputWrite);

    STARTUPINFOW si = { sizeof(si) };
    if (outputWrite) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = outputWrite;
        si.hStdError = outputWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi = {};
    
    BOOL success = CreateProcessW(
        loaderExePath.c_str(),
        &cmdLine[0],
        NULL,
        NULL,
        outputWrite ? TRUE : FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    CloseIfValid(outputWrite);

    if (!success) {
        CloseIfValid(outputRead);
        return false;
    }
    
    const DWORD waitResult = WaitForSingleObject(pi.hProcess, 15000);
    if (waitResult != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 1000);
        if (capturedOutput) *capturedOutput += "[loader] helper injection timed out.\n";
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    if (capturedOutput) {
        *capturedOutput += ReadPipeToString(outputRead);
    }
    
    CloseIfValid(outputRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return waitResult == WAIT_OBJECT_0 && exitCode == 0;
}

bool Injector::InjectAgentIntoProcess(DWORD processId, std::string* diagnosticOutput, std::wstring* resolvedProcessPath) {
    if (processId == 0) return false;

    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId
    );
    if (!process) {
        if (diagnosticOutput) *diagnosticOutput = "OpenProcess failed: " + std::to_string(GetLastError());
        return false;
    }

    std::vector<wchar_t> pathBuffer(32768);
    DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
    if (!QueryFullProcessImageNameW(process, 0, pathBuffer.data(), &pathLength) || pathLength == 0) {
        if (diagnosticOutput) *diagnosticOutput = "QueryFullProcessImageNameW failed: " + std::to_string(GetLastError());
        CloseHandle(process);
        return false;
    }

    std::wstring processPath(pathBuffer.data(), pathLength);
    if (resolvedProcessPath) *resolvedProcessPath = processPath;
    WORD machine = 0;
    if (!TryGetPeMachine(processPath, machine)) {
        if (diagnosticOutput) *diagnosticOutput = "process image is not a supported x86/x64 PE executable";
        CloseHandle(process);
        return false;
    }
    bool target32 = machine == IMAGE_FILE_MACHINE_I386;
    std::wstring moduleDir = GetModuleDir();
    bool injected = false;

#ifdef _WIN64
    constexpr bool controller64 = true;
#else
    constexpr bool controller64 = false;
#endif

    if (controller64 == !target32) {
        std::wstring agentPath = moduleDir + (target32 ? L"InspecthorAgent32.dll" : L"InspecthorAgent.dll");
        injected = DirectInject(process, agentPath);
    } else {
        std::wstring loaderPath = moduleDir + (target32 ? L"InspecthorLoader32.exe" : L"InspecthorLoader.exe");
        std::wstring agentPath = moduleDir + (target32 ? L"InspecthorAgent32.dll" : L"InspecthorAgent.dll");
        injected = HelperInject(processId, loaderPath, agentPath, diagnosticOutput);
    }

    CloseHandle(process);
    if (!injected && diagnosticOutput && diagnosticOutput->empty()) {
        *diagnosticOutput = "agent injection failed";
    }
    return injected;
}

bool Injector::LaunchSuspended(const std::wstring& exePath, const std::wstring& cmdLine,
    TargetProcessInfo& outInfo, const std::wstring& workingDirectory) {
    outInfo = {};
    WORD machine = 0;
    WORD characteristics = 0;
    if (!TryGetPeMachine(exePath, machine, &characteristics) || (characteristics & IMAGE_FILE_DLL) != 0) {
        outInfo.launcherOutput = "[launch] target is missing or is not a supported x86/x64 PE executable.";
        return false;
    }
    outInfo.is32Bit = machine == IMAGE_FILE_MACHINE_I386;
    outInfo.processName = exePath;
    outInfo.processPath = exePath;
    outInfo.commandLine = L"\"" + exePath + L"\"";
    if (!cmdLine.empty()) outInfo.commandLine += L" " + cmdLine;

    STARTUPINFOW si = { sizeof(si) };
    HANDLE outputRead = NULL;
    HANDLE outputWrite = NULL;
    if (CreateHiddenOutputPipe(outputRead, outputWrite)) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = outputWrite;
        si.hStdError = outputWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi = {};
    std::wstring writableCommand = outInfo.commandLine;
    const BOOL created = CreateProcessW(exePath.c_str(), writableCommand.data(), nullptr, nullptr, outputWrite ? TRUE : FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr,
        workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &si, &pi);
    CloseIfValid(outputWrite);
    if (!created) {
        outInfo.launcherOutput = "[launch] CreateProcessW failed with error " + std::to_string(GetLastError()) + ".";
        CloseIfValid(outputRead);
        return false;
    }
    outInfo.dwProcessId = pi.dwProcessId;
    outInfo.dwThreadId = pi.dwThreadId;
    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.hOutputRead = outputRead;
    outInfo.launcherOutput = "[session] launcher host started without WinAPI injection (ETW-only).";
    return true;
}

bool Injector::LaunchAndInject(
    const std::wstring& exePath,
    const std::wstring& cmdLine,
    TargetProcessInfo& outInfo,
    HANDLE& outPipeHandle,
    const TraceConfig& traceConfig,
    const std::wstring& workingDirectory
) {
    outInfo = {};
    outPipeHandle = INVALID_HANDLE_VALUE;
    WORD machine = 0;
    WORD characteristics = 0;
    if (!TryGetPeMachine(exePath, machine, &characteristics) || (characteristics & IMAGE_FILE_DLL) != 0) {
        outInfo.launcherOutput = "[launch] target is missing or is not a supported x86/x64 PE executable.";
        return false;
    }
    bool target32 = machine == IMAGE_FILE_MACHINE_I386;
    outInfo.is32Bit = target32;
    outInfo.processName = exePath;
    outInfo.processPath = exePath;
    outInfo.commandLine = L"\"" + exePath + L"\"";
    if (!cmdLine.empty()) outInfo.commandLine += L" " + cmdLine;

    STARTUPINFOW si = { sizeof(si) };
    HANDLE outputRead = NULL;
    HANDLE outputWrite = NULL;
    if (CreateHiddenOutputPipe(outputRead, outputWrite)) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = outputWrite;
        si.hStdError = outputWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi = {};
    
    // Launch target suspended
    // CreateProcess expects a complete command line. Callers pass only target
    // arguments, so always retain argv[0] as the executable path.
    std::wstring writableCmd = outInfo.commandLine;
    BOOL success = CreateProcessW(
        exePath.c_str(),
        &writableCmd[0],
        NULL,
        NULL,
        outputWrite ? TRUE : FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        workingDirectory.empty() ? NULL : workingDirectory.c_str(),
        &si,
        &pi
    );

    CloseIfValid(outputWrite);

    if (!success) {
        outInfo.launcherOutput = "[launch] CreateProcessW failed with error " + std::to_string(GetLastError()) + ".";
        CloseIfValid(outputRead);
        return false;
    }

    // Create named pipe for agent telemetry + handshake dynamically using target PID
    std::wstring pipeName = L"\\\\.\\pipe\\InspecthorTelemetry_" + std::to_wstring(pi.dwProcessId);
    HANDLE hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        outInfo.launcherOutput = "[launch] telemetry pipe creation failed with error " + std::to_string(GetLastError()) + ".";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outputRead);
        return false;
    }

    outInfo.dwProcessId = pi.dwProcessId;
    outInfo.dwThreadId = pi.dwThreadId;
    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.hOutputRead = outputRead;

    bool injectSuccess = false;
    std::wstring moduleDir = GetModuleDir();
    
#ifdef _WIN64
    bool controller64 = true;
#else
    bool controller64 = false;
#endif

    if (controller64) {
        if (!target32) {
            std::wstring dllPath = moduleDir + L"InspecthorAgent.dll";
            injectSuccess = DirectInject(pi.hProcess, dllPath);
        } else {
            std::wstring loaderExePath = moduleDir + L"InspecthorLoader32.exe";
            std::wstring dllPath = moduleDir + L"InspecthorAgent32.dll";
            injectSuccess = HelperInject(pi.dwProcessId, loaderExePath, dllPath, &outInfo.launcherOutput);
        }
    } else {
        if (target32) {
            std::wstring dllPath = moduleDir + L"InspecthorAgent32.dll";
            injectSuccess = DirectInject(pi.hProcess, dllPath);
        } else {
            std::wstring loaderExePath = moduleDir + L"InspecthorLoader.exe";
            std::wstring dllPath = moduleDir + L"InspecthorAgent.dll";
            injectSuccess = HelperInject(pi.dwProcessId, loaderExePath, dllPath, &outInfo.launcherOutput);
        }
    }

    if (!injectSuccess) {
        outInfo.launcherOutput += "[agent] matching monitoring agent could not be loaded.\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outInfo.hOutputRead);
        CloseHandle(hPipe);
        return false;
    }

    // Perform Named Pipe Handshake
    if (!PerformPipeHandshake(hPipe, pi.dwProcessId, traceConfig, &outInfo.launcherOutput)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outInfo.hOutputRead);
        CloseHandle(hPipe);
        return false;
    }

    outPipeHandle = hPipe;
    return true;
}

bool Injector::LaunchDll(
    const std::wstring& dllPath,
    const std::wstring& mode,
    const std::string& exportName,
    bool is32Bit,
    TargetProcessInfo& outInfo,
    HANDLE& outPipeHandle,
    const TraceConfig& traceConfig
) {
    outInfo = {};
    outPipeHandle = INVALID_HANDLE_VALUE;
    std::wstring dir = GetModuleDir();
    std::wstring agentDllPath = dir + (is32Bit ? L"InspecthorAgent32.dll" : L"InspecthorAgent.dll");
    bool useRundll32 = (mode == L"rundll32");

    if (useRundll32 && exportName.empty()) {
        outInfo.launcherOutput = "[launch] rundll32 mode requires an exported function name.";
        return false;
    }
    WORD dllMachine = 0;
    WORD dllCharacteristics = 0;
    if (!TryGetPeMachine(dllPath, dllMachine, &dllCharacteristics) ||
        (dllCharacteristics & IMAGE_FILE_DLL) == 0) {
        outInfo.launcherOutput = "[launch] selected DLL is missing or is not a supported x86/x64 PE image.";
        return false;
    }
    const bool dllIs32Bit = dllMachine == IMAGE_FILE_MACHINE_I386;
    if (dllIs32Bit != is32Bit) {
        outInfo.launcherOutput = "[launch] selected DLL architecture does not match the chosen host architecture.";
        return false;
    }

    std::wstring targetExePath;
    std::wstring processName;
    std::wstring cmdLine;

    if (useRundll32) {
        targetExePath = GetRundll32Path(is32Bit);
        std::wstring wexport(exportName.begin(), exportName.end());
        cmdLine = L"\"" + targetExePath + L"\" \"" + dllPath + L"\"," + wexport;
        processName = L"rundll32.exe";
    } else {
        targetExePath = dir + (is32Bit ? L"InspecthorLoader32.exe" : L"InspecthorLoader.exe");
        processName = is32Bit ? L"InspecthorLoader32.exe" : L"InspecthorLoader.exe";

        // Command: Loader.exe "<dllPath>" <mode> [exportName]
        cmdLine = L"\"" + targetExePath + L"\" \"" + dllPath + L"\" " + mode;
        if (!exportName.empty()) {
            std::wstring wexport(exportName.begin(), exportName.end());
            cmdLine += L" " + wexport;
        }
    }

    if (!FileExists(targetExePath) || !FileExists(agentDllPath)) {
        outInfo.launcherOutput = "[launch] matching DLL host or monitoring agent is missing from the application folder.";
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    HANDLE outputRead = NULL;
    HANDLE outputWrite = NULL;
    if (CreateHiddenOutputPipe(outputRead, outputWrite)) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = outputWrite;
        si.hStdError = outputWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi = {};

    // Launch DLL host suspended
    BOOL success = CreateProcessW(
        targetExePath.c_str(),
        &cmdLine[0],
        NULL,
        NULL,
        outputWrite ? TRUE : FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    CloseIfValid(outputWrite);

    if (!success) {
        outInfo.launcherOutput = "[launch] DLL host CreateProcessW failed with error " + std::to_string(GetLastError()) + ".";
        CloseIfValid(outputRead);
        return false;
    }

    // Create named pipe for agent telemetry + handshake dynamically using target PID
    std::wstring pipeName = L"\\\\.\\pipe\\InspecthorTelemetry_" + std::to_wstring(pi.dwProcessId);
    HANDLE hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        outInfo.launcherOutput = "[launch] DLL-host telemetry pipe creation failed with error " + std::to_string(GetLastError()) + ".";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outputRead);
        return false;
    }

    outInfo.dwProcessId = pi.dwProcessId;
    outInfo.dwThreadId = pi.dwThreadId;
    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.hOutputRead = outputRead;
    outInfo.is32Bit = is32Bit;
    outInfo.processName = processName;
    outInfo.processPath = targetExePath;
    outInfo.commandLine = cmdLine;

    bool injectSuccess = false;
    
#ifdef _WIN64
    bool controller64 = true;
#else
    bool controller64 = false;
#endif

    if (controller64) {
        if (!is32Bit) {
            injectSuccess = DirectInject(pi.hProcess, agentDllPath);
        } else {
            std::wstring helperExePath = dir + L"InspecthorLoader32.exe";
            injectSuccess = HelperInject(pi.dwProcessId, helperExePath, agentDllPath, &outInfo.launcherOutput);
        }
    } else {
        if (is32Bit) {
            injectSuccess = DirectInject(pi.hProcess, agentDllPath);
        } else {
            std::wstring helperExePath = dir + L"InspecthorLoader.exe";
            injectSuccess = HelperInject(pi.dwProcessId, helperExePath, agentDllPath, &outInfo.launcherOutput);
        }
    }

    if (!injectSuccess) {
        outInfo.launcherOutput += "[agent] matching monitoring agent could not be loaded into the DLL host.\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outInfo.hOutputRead);
        CloseHandle(hPipe);
        return false;
    }

    // Perform handshake
    if (!PerformPipeHandshake(hPipe, pi.dwProcessId, traceConfig, &outInfo.launcherOutput)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseIfValid(outInfo.hOutputRead);
        CloseHandle(hPipe);
        return false;
    }

    outPipeHandle = hPipe;
    return true;
}

} // namespace Inspecthor
