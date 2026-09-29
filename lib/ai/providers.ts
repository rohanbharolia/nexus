import type { AIProvider } from "./types";
import { DeterministicAIProvider } from "./fallback";
import { OpenAICompatibleProvider } from "./openai-provider";
import { GeminiProvider } from "./gemini-provider";

export type SupportedAIProvider =
  | "openai"
  | "openrouter"
  | "deepseek"
  | "ollama"
  | "groq"
  | "gemini"
  | "deterministic-fallback";

// Base URLs for each provider (can be overridden by AI_ENDPOINT)
const DEFAULT_ENDPOINTS: Partial<Record<SupportedAIProvider, string>> = {
  openai:      "https://api.openai.com/v1",
  openrouter:  "https://openrouter.ai/api/v1",
  deepseek:    "https://api.deepseek.com/v1",
  groq:        "https://api.groq.com/openai/v1",
  ollama:      "http://localhost:11434/v1",
};

// Default models for each provider
const DEFAULT_MODELS: Partial<Record<SupportedAIProvider, string>> = {
  openai:      "gpt-4o-mini",
  openrouter:  "openai/gpt-4o-mini",
  deepseek:    "deepseek-chat",
  groq:        "llama-3.1-8b-instant",
  ollama:      "llama3.2",
  gemini:      "gemini-1.5-flash",
};

export function getAIProvider(): AIProvider {
  const providerName = (process.env.AI_PROVIDER ?? "deterministic-fallback") as SupportedAIProvider;
  const apiKey       = process.env.AI_API_KEY ?? "";
  const model        = process.env.AI_MODEL || DEFAULT_MODELS[providerName] || "default";
  const endpoint     = process.env.AI_ENDPOINT || DEFAULT_ENDPOINTS[providerName];

  // Fall back to deterministic if no key is set
  if (providerName === "deterministic-fallback" || !apiKey) {
    if (providerName !== "deterministic-fallback" && !apiKey) {
      console.warn(`[ai] AI_PROVIDER="${providerName}" but AI_API_KEY is not set — falling back to deterministic mode`);
    }
    return new DeterministicAIProvider();
  }

  // Gemini uses its own REST API
  if (providerName === "gemini") {
    console.info(`[ai] Using Gemini provider (model: ${model})`);
    return new GeminiProvider(apiKey, model);
  }

  // Ollama runs locally — no key required in practice, but we still route through OpenAI-compat
  if (providerName === "ollama") {
    console.info(`[ai] Using Ollama provider (model: ${model}, endpoint: ${endpoint})`);
    return new OpenAICompatibleProvider("ollama", apiKey || "ollama", model, endpoint);
  }

  // All other providers speak OpenAI chat-completions
  console.info(`[ai] Using ${providerName} provider (model: ${model})`);
  return new OpenAICompatibleProvider(providerName, apiKey, model, endpoint);
}

// Singleton — created once at module load so the server doesn't re-instantiate per request
export const aiProvider: AIProvider = getAIProvider();
