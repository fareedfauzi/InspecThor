#include "ai_client.h"
#include "nlohmann/json.hpp"

#include <Windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <vector>

namespace Inspecthor {
using json = nlohmann::json;
namespace {

std::filesystem::path ConfigPath() {
    wchar_t modulePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    return std::filesystem::path(modulePath).parent_path() / L"inspecthor_ai.json";
}

std::string Base64(const BYTE* data, DWORD size) {
    DWORD chars = 0;
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars)) return {};
    std::string output(chars, '\0');
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output.data(), &chars)) return {};
    if (!output.empty() && output.back() == '\0') output.pop_back();
    return output;
}

bool Unbase64(const std::string& value, std::vector<BYTE>& bytes) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(value.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr)) return false;
    bytes.resize(size);
    return CryptStringToBinaryA(value.c_str(), 0, CRYPT_STRING_BASE64, bytes.data(), &size, nullptr, nullptr) != FALSE;
}

std::string Protect(const std::string& plain) {
    if (plain.empty()) return {};
    DATA_BLOB in{ (DWORD)plain.size(), (BYTE*)plain.data() }, out{};
    if (!CryptProtectData(&in, L"Inspecthor AI API key", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return {};
    std::string encoded = Base64(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return encoded;
}

bool Unprotect(const std::string& encoded, std::string& plain) {
    if (encoded.empty()) { plain.clear(); return true; }
    std::vector<BYTE> bytes;
    if (!Unbase64(encoded, bytes)) return false;
    DATA_BLOB in{ (DWORD)bytes.size(), bytes.data() }, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    plain.assign((char*)out.pbData, (char*)out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0);
    std::wstring result(count, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), result.data(), count);
    return result;
}

std::string WinError(const char* operation) {
    return std::string(operation) + " failed (Windows error " + std::to_string(GetLastError()) + ").";
}

} // namespace

bool LoadAiConfig(AiConfig& config, std::string& error) {
    error.clear();
    std::ifstream file(ConfigPath(), std::ios::binary);
    if (!file) return true;
    try {
        json root; file >> root;
        config.provider = root.value("provider", "openai") == "anthropic" ? AiProvider::Anthropic : AiProvider::OpenAICompatible;
        config.endpoint = root.value("endpoint", config.endpoint);
        config.model = root.value("model", "");
        if (!Unprotect(root.value("api_key_dpapi", ""), config.apiKey)) {
            error = "The saved API key could not be decrypted for this Windows user.";
            return false;
        }
        return true;
    } catch (const std::exception& ex) { error = ex.what(); return false; }
}

bool SaveAiConfig(const AiConfig& config, std::string& error) {
    error.clear();
    std::string encrypted = Protect(config.apiKey);
    if (!config.apiKey.empty() && encrypted.empty()) { error = "Windows DPAPI could not protect the API key."; return false; }
    json root = {
        {"provider", config.provider == AiProvider::Anthropic ? "anthropic" : "openai"},
        {"endpoint", config.endpoint}, {"model", config.model}, {"api_key_dpapi", encrypted}
    };
    std::ofstream file(ConfigPath(), std::ios::binary | std::ios::trunc);
    if (!file) { error = "Could not open the AI configuration file for writing."; return false; }
    file << root.dump(2);
    return file.good();
}

bool RequestAiCompletion(const AiConfig& config, const std::string& systemPrompt,
    const std::string& userPrompt, std::string& response, std::string& error) {
    response.clear(); error.clear();
    if (config.apiKey.empty()) { error = "Enter an API key first."; return false; }
    if (config.model.empty()) { error = "Enter a model name first."; return false; }
    std::wstring endpoint = Utf8ToWide(config.endpoint);
    URL_COMPONENTSW parts{}; parts.dwStructSize = sizeof(parts);
    wchar_t host[256] = {}, path[2048] = {};
    parts.lpszHostName = host; parts.dwHostNameLength = _countof(host);
    parts.lpszUrlPath = path; parts.dwUrlPathLength = _countof(path);
    if (!WinHttpCrackUrl(endpoint.c_str(), 0, 0, &parts)) { error = "Invalid AI endpoint URL."; return false; }
    if (parts.nScheme != INTERNET_SCHEME_HTTPS) { error = "AI endpoint must use HTTPS."; return false; }

    json body;
    std::wstring headers = L"Content-Type: application/json\r\n";
    if (config.provider == AiProvider::Anthropic) {
        body = {{"model", config.model}, {"max_tokens", 2048}, {"system", systemPrompt},
            {"messages", json::array({{{"role", "user"}, {"content", userPrompt}}})}};
        headers += L"x-api-key: " + Utf8ToWide(config.apiKey) + L"\r\nanthropic-version: 2023-06-01\r\n";
    } else {
        body = {{"model", config.model}, {"messages", json::array({
            {{"role", "system"}, {"content", systemPrompt}}, {{"role", "user"}, {"content", userPrompt}}
        })}};
        headers += L"Authorization: Bearer " + Utf8ToWide(config.apiKey) + L"\r\n";
    }
    std::string payload = body.dump();

    HINTERNET session = WinHttpOpen(L"Inspecthor/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nullptr, nullptr, 0);
    if (!session) { error = WinError("WinHttpOpen"); return false; }
    WinHttpSetTimeouts(session, 15000, 15000, 30000, 120000);
    HINTERNET connect = WinHttpConnect(session, std::wstring(host, parts.dwHostNameLength).c_str(), parts.nPort, 0);
    HINTERNET request = connect ? WinHttpOpenRequest(connect, L"POST", std::wstring(path, parts.dwUrlPathLength).c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    bool ok = request && WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L, payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0)
        && WinHttpReceiveResponse(request, nullptr);
    std::string raw;
    if (ok) {
        DWORD status = 0, statusSize = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &statusSize, nullptr);
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available) {
            std::string chunk(available, '\0'); DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read)) { ok = false; break; }
            raw.append(chunk.data(), read);
        }
        if (status < 200 || status >= 300) { error = "AI service returned HTTP " + std::to_string(status) + ": " + raw.substr(0, 1000); ok = false; }
    } else if (error.empty()) error = WinError("AI request");
    if (request) WinHttpCloseHandle(request); if (connect) WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
    if (!ok) return false;
    try {
        json root = json::parse(raw);
        if (config.provider == AiProvider::Anthropic) {
            for (const auto& item : root.at("content")) if (item.value("type", "") == "text") response += item.value("text", "");
        } else response = root.at("choices").at(0).at("message").value("content", "");
        if (response.empty()) { error = "AI service returned no text."; return false; }
        return true;
    } catch (const std::exception& ex) { error = std::string("Invalid AI response: ") + ex.what(); return false; }
}

} // namespace Inspecthor
