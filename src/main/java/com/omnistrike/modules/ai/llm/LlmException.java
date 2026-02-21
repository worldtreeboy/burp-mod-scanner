package com.omnistrike.modules.ai.llm;

/**
 * Typed exception for LLM client errors, categorized by error type
 * so callers can take appropriate action (e.g., back off on rate limit).
 */
public class LlmException extends Exception {

    public enum ErrorType {
        AUTH_FAILURE,
        RATE_LIMITED,
        TIMEOUT,
        PARSE_ERROR,
        CONNECTION_ERROR
    }

    private final ErrorType errorType;

    public LlmException(ErrorType errorType, String message) {
        super(message);
        this.errorType = errorType;
    }

    public LlmException(ErrorType errorType, String message, Throwable cause) {
        super(message, cause);
        this.errorType = errorType;
    }

    public ErrorType getErrorType() { return errorType; }
}
