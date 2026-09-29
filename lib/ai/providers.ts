import type { AIProvider } from "./types";
import { DeterministicAIProvider } from "./fallback";
import { ConfiguredHTTPAIProvider } from "./http-provider";

export type SupportedAIProvider = "openai" | "openrouter" | "ollama" | "gemini" | "deepseek" | "deterministic-fallback";
export function getAIProvider(): AIProvider {
  const provider = (process.env.AI_PROVIDER ?? "deterministic-fallback") as SupportedAIProvider;
  if (provider === "deterministic-fallback" || !process.env.AI_API_KEY || !process.env.AI_ENDPOINT) return new DeterministicAIProvider();
  return new ConfiguredHTTPAIProvider(provider, process.env.AI_ENDPOINT, process.env.AI_API_KEY, process.env.AI_MODEL ?? "default");
}
