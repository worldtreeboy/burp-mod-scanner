package com.omnistrike.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Objects;

/**
 * Represents a single finding reported by any scan module.
 */
public class Finding {

    private final String moduleId;
    private final String title;
    private final Severity severity;
    private final Confidence confidence;
    private final String description;
    private final String url;
    private final String parameter;
    private final String evidence;
    private final String remediation;
    private final HttpRequestResponse requestResponse;
    private final String targetModuleId;
    private final long timestamp;

    private Finding(Builder builder) {
        this.moduleId = Objects.requireNonNull(builder.moduleId, "moduleId is required");
        this.title = Objects.requireNonNull(builder.title, "title is required");
        this.severity = Objects.requireNonNull(builder.severity, "severity is required");
        this.confidence = Objects.requireNonNull(builder.confidence, "confidence is required");
        this.description = builder.description;
        this.url = builder.url;
        this.parameter = builder.parameter;
        this.evidence = builder.evidence;
        this.remediation = builder.remediation;
        this.requestResponse = builder.requestResponse;
        this.targetModuleId = builder.targetModuleId;
        this.timestamp = builder.timestamp;
    }

    public String getModuleId() { return moduleId; }
    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public Confidence getConfidence() { return confidence; }
    public String getDescription() { return description; }
    public String getUrl() { return url; }
    public String getParameter() { return parameter; }
    public String getEvidence() { return evidence; }
    public String getRemediation() { return remediation; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public String getTargetModuleId() { return targetModuleId; }
    public long getTimestamp() { return timestamp; }

    public static Builder builder(String moduleId, String title, Severity severity, Confidence confidence) {
        return new Builder(moduleId, title, severity, confidence);
    }

    @Override
    public String toString() {
        return "[" + severity + "] " + title + " (" + moduleId + ") @ " + url
                + (parameter != null ? " param=" + parameter : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Finding finding = (Finding) o;
        return Objects.equals(moduleId, finding.moduleId)
                && Objects.equals(title, finding.title)
                && Objects.equals(url, finding.url)
                && Objects.equals(parameter, finding.parameter);
    }

    @Override
    public int hashCode() {
        return Objects.hash(moduleId, title, url, parameter);
    }

    public static class Builder {
        private final String moduleId;
        private final String title;
        private final Severity severity;
        private final Confidence confidence;
        private String description = "";
        private String url = "";
        private String parameter = "";
        private String evidence = "";
        private String remediation = "";
        private HttpRequestResponse requestResponse;
        private String targetModuleId;
        private long timestamp = System.currentTimeMillis();

        private Builder(String moduleId, String title, Severity severity, Confidence confidence) {
            this.moduleId = moduleId;
            this.title = title;
            this.severity = severity;
            this.confidence = confidence;
        }

        public Builder description(String d) { this.description = d != null ? d : ""; return this; }
        public Builder url(String u) { this.url = u != null ? u : ""; return this; }
        public Builder parameter(String p) { this.parameter = p != null ? p : ""; return this; }
        public Builder evidence(String e) { this.evidence = e != null ? e : ""; return this; }
        public Builder remediation(String r) { this.remediation = r != null ? r : ""; return this; }
        public Builder requestResponse(HttpRequestResponse rr) { this.requestResponse = rr; return this; }
        public Builder targetModuleId(String id) { this.targetModuleId = id; return this; }
        public Builder timestamp(long t) { this.timestamp = t; return this; }

        public Finding build() {
            return new Finding(this);
        }
    }
}
