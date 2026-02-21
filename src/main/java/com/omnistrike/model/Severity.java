package com.omnistrike.model;

public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /**
     * Map to Burp's AuditIssueSeverity string for native issue reporting.
     * Burp has no CRITICAL — maps to HIGH.
     */
    public String toBurpSeverity() {
        return switch (this) {
            case INFO -> "INFORMATION";
            case LOW -> "LOW";
            case MEDIUM -> "MEDIUM";
            case HIGH, CRITICAL -> "HIGH";
        };
    }

    public boolean isHigherThan(Severity other) {
        return this.ordinal() > other.ordinal();
    }
}
