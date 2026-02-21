package com.omnistrike.modules.ai.llm;

import java.util.Collections;
import java.util.List;

/**
 * Parsed response from an LLM vulnerability analysis call.
 */
public class LlmAnalysisResult {

    private final List<LlmFinding> findings;
    private final String rawResponse;

    public LlmAnalysisResult(List<LlmFinding> findings, String rawResponse) {
        this.findings = findings != null ? Collections.unmodifiableList(findings) : Collections.emptyList();
        this.rawResponse = rawResponse;
    }

    public List<LlmFinding> getFindings() { return findings; }
    public String getRawResponse() { return rawResponse; }

    /**
     * A single finding extracted from the LLM response.
     */
    public static class LlmFinding {
        private final String title;
        private final String severity;
        private final String description;
        private final String evidence;
        private final String poc;
        private final String remediation;
        private final String cweId;

        public LlmFinding(String title, String severity, String description,
                           String evidence, String poc, String remediation, String cweId) {
            this.title = title;
            this.severity = severity;
            this.description = description;
            this.evidence = evidence;
            this.poc = poc;
            this.remediation = remediation;
            this.cweId = cweId;
        }

        public String getTitle() { return title; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public String getEvidence() { return evidence; }
        public String getPoc() { return poc; }
        public String getRemediation() { return remediation; }
        public String getCweId() { return cweId; }
    }
}
