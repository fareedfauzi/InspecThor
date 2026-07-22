# Inspecthor

All-in-one behavior malware analysis tool for Windows.

Inspecthor is a small research tool I built for observing what a suspicious program does at runtime. The goal is simple: run a target, collect behavior, and make the findings easier to read without jumping between too many tools.

It focuses on dynamic behavior such as process creation, file activity, registry changes, network activity, memory activity, DLL loading, process injection indicators, IPC, services/drivers, crypto usage, anti-analysis behavior, WinAPI calls, ETW telemetry, and Sysmon events.

This project is still evolving, so expect rough edges here and there. The UI is designed around malware triage: less raw noise, more useful grouping.

## Features

- EXE and DLL analysis workflow
- WinAPI monitoring with hooked API events
- ETW kernel telemetry scoped to the target process tree
- Process, file, registry, network, memory, DLL, crypto, IPC, service/driver, COM/WMI/task, anti-analysis, and injection views
- System-wide watcher tabs for process, file, network, registry, and injection activity
- Sysmon event viewer with process-focused filtering
- Import/export JSON analysis sessions
- AI summary support using OpenAI-compatible or Anthropic-style endpoints
- Dark and white UI themes

## Main idea

Inspecthor combines a few sources of visibility:

- user-mode API hooks through the Inspecthor agent
- ETW kernel telemetry
- optional Sysmon event parsing
- controller-side process and system watchers

No single source is perfect. API hooks can miss direct syscalls or unsupported libraries. ETW is useful but noisy. Sysmon is powerful but can be heavy without filtering. Inspecthor tries to combine them into views that are easier to reason about.

## Build

Requirements:

- Windows
- Visual Studio with C++ build tools
- CMake

Build release binaries:

```bat
build_release.bat
```

The compiled files are copied into:

```text
Release\
```

## Run

After building, run:

```text
Release\InspecthorController.exe
```

Use a safe malware lab or VM. Do not run unknown samples on your main machine.

## Sysmon support

Inspecthor can read Sysmon events if Sysmon is installed and the event log is available.

The Sysmon page can help check readiness and download/install Sysmon, but installation requires Administrator approval.

Manual install example:

```bat
Sysmon64.exe -accepteula -i sysmonconfig-advanced-public-detection-v3.3.xml
```

## Notes

This is a research and analysis tool, not a replacement for a full sandbox product. It is meant to help analysts understand behavior faster and to make Windows malware activity easier to inspect.

## Credits

API dictionary data used for WinAPI monitoring is credited to Rohitab.
