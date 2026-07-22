#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace Inspecthor {

inline bool ReadPipeExact(HANDLE pipe, void* buffer, size_t size) {
    auto* cursor = static_cast<uint8_t*>(buffer);
    size_t remaining = size;
    while (remaining > 0) {
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : static_cast<DWORD>(remaining);
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, cursor, chunk, &bytesRead, nullptr) || bytesRead == 0) {
            return false;
        }
        cursor += bytesRead;
        remaining -= bytesRead;
    }
    return true;
}

inline bool WritePipeExact(HANDLE pipe, const void* buffer, size_t size) {
    const auto* cursor = static_cast<const uint8_t*>(buffer);
    size_t remaining = size;
    while (remaining > 0) {
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : static_cast<DWORD>(remaining);
        DWORD bytesWritten = 0;
        if (!WriteFile(pipe, cursor, chunk, &bytesWritten, nullptr) || bytesWritten == 0) {
            return false;
        }
        cursor += bytesWritten;
        remaining -= bytesWritten;
    }
    return true;
}

} // namespace Inspecthor
