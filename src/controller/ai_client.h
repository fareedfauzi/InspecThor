#pragma once

#include <string>

namespace Inspecthor {

enum class AiProvider { OpenAICompatible = 0, Anthropic = 1 };

struct AiConfig {
    AiProvider provider = AiProvider::OpenAICompatible;
    std::string endpoint = "https://api.openai.com/v1/chat/completions";
    std::string apiKey;
    std::string model;
};

bool LoadAiConfig(AiConfig& config, std::string& error);
bool SaveAiConfig(const AiConfig& config, std::string& error);
bool RequestAiCompletion(const AiConfig& config, const std::string& systemPrompt,
    const std::string& userPrompt, std::string& response, std::string& error);

} // namespace Inspecthor
