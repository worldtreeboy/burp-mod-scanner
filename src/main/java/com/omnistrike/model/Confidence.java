package com.omnistrike.model;

public enum Confidence {
    TENTATIVE,
    FIRM,
    CERTAIN;

    /**
     * Map to Burp's AuditIssueConfidence string for native issue reporting.
     */
    public String toBurpConfidence() {
        return switch (this) {
            case TENTATIVE -> "TENTATIVE";
            case FIRM -> "FIRM";
            case CERTAIN -> "CERTAIN";
        };
    }
}
