package com.omnistrike.framework.stepper;

/**
 * Defines how to extract a named variable from a step's HTTP response.
 *
 * - BODY_REGEX: pattern is a regex; capture group 1 is the extracted value.
 * - HEADER: pattern is the header name (e.g., "X-CSRF-Token").
 * - COOKIE: pattern is the cookie name (e.g., "PHPSESSID").
 * - JSON_PATH: pattern is a dot-notation path (e.g., "data.token").
 */
public class ExtractionRule {

    private final String variableName;
    private final ExtractionType type;
    private final String pattern;

    public ExtractionRule(String variableName, ExtractionType type, String pattern) {
        this.variableName = variableName;
        this.type = type;
        this.pattern = pattern;
    }

    public String getVariableName() { return variableName; }
    public ExtractionType getType() { return type; }
    public String getPattern() { return pattern; }

    @Override
    public String toString() {
        return variableName + " (" + type + ": " + pattern + ")";
    }
}
