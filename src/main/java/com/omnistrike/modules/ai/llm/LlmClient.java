package com.omnistrike.modules.ai.llm;

import com.google.gson.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Unified client for calling LLM providers via CLI tools.
 * Supports CLI providers (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI).
 *
 * All config fields are volatile — written from the EDT, read from the LLM background thread.
 */
public class LlmClient {

    private static final Gson GSON = new Gson();

    private final CliBackend cliBackend = new CliBackend();

    // Volatile config — written from EDT, read from LLM thread
    private volatile LlmProvider provider = LlmProvider.CLI_CLAUDE;
    private volatile String model = LlmProvider.CLI_CLAUDE.getDefaultModel();
    private volatile boolean configured = false;

    // CLI binary path override (empty = use default)
    private volatile String cliBinaryPath = "";

    public LlmClient() {
    }

    /**
     * Updates the client configuration for CLI providers.
     */
    public void configureCli(LlmProvider provider, String binaryPath) {
        this.provider = provider;
        this.cliBinaryPath = binaryPath != null ? binaryPath : "";
        this.model = provider.getDefaultModel();
        this.configured = true;
    }

    /**
     * Sends a prompt to the configured CLI tool and returns the raw text response.
     */
    public String call(String prompt) throws LlmException {
        return cliBackend.call(provider, cliBinaryPath, prompt);
    }

    /**
     * Tests connectivity to the configured CLI tool. Returns a status message.
     */
    public String testConnection() throws LlmException {
        return cliBackend.testConnection(provider, cliBinaryPath);
    }

    // ==================== Response parsing ====================

    /**
     * Parses the LLM text response into structured findings.
     * Expects JSON with structure: {"findings": [{"title", "severity", ...}]}
     */
    public LlmAnalysisResult parseResponse(String rawText) {
        List<LlmAnalysisResult.LlmFinding> findings = new ArrayList<>();

        // Extract JSON block from the response (LLMs often wrap in markdown code fences)
        String json = extractJson(rawText);
        if (json == null) {
            return new LlmAnalysisResult(findings, rawText);
        }

        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.getAsJsonArray("findings");
            if (arr == null) return new LlmAnalysisResult(findings, rawText);

            for (JsonElement el : arr) {
                JsonObject obj = el.getAsJsonObject();
                findings.add(new LlmAnalysisResult.LlmFinding(
                        getStr(obj, "title"),
                        getStr(obj, "severity"),
                        getStr(obj, "description"),
                        getStr(obj, "evidence"),
                        getStr(obj, "poc"),
                        getStr(obj, "remediation"),
                        getStr(obj, "cwe")
                ));
            }
        } catch (Exception e) {
            // Log parse failure — don't silently swallow
            System.err.println("[LlmClient] Failed to parse AI findings JSON: " + e.getMessage()
                    + " | json snippet: " + (json != null ? json.substring(0, Math.min(json.length(), 300)) : "null"));
        }

        return new LlmAnalysisResult(findings, rawText);
    }

    private String extractJson(String text) {
        if (text == null) return null;
        // Try to find JSON in markdown code fences first.
        // Use "\n```" for the closing fence so we don't match backticks
        // inside JSON string values (e.g., evidence fields containing code snippets).
        int start = text.indexOf("```json");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) return text.substring(start, end).trim();
        }
        // Try generic code fence
        start = text.indexOf("```");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) {
                String block = text.substring(start, end).trim();
                if (block.startsWith("{")) return block;
            }
        }
        // Try to find raw JSON object
        start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return text.substring(start, end + 1);
        }
        return null;
    }

    private String getStr(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsString() : "";
    }

    // ==================== Getters / Setters ====================

    public LlmProvider getProvider() { return provider; }
    public String getModel() { return model; }

    /** Returns true if the client has been configured with a provider. */
    public boolean isConfigured() {
        return configured;
    }

    public String getCliBinaryPath() { return cliBinaryPath; }
}
