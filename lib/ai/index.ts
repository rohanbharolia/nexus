export * from "./types";
export { DeterministicAIProvider } from "./fallback";
export { OpenAICompatibleProvider } from "./openai-provider";
export { GeminiProvider } from "./gemini-provider";
// Singleton provider + factory — always import aiProvider from here
export { aiProvider, getAIProvider, type SupportedAIProvider } from "./providers";
