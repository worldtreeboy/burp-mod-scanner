package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Host Header Injection Scanner
 * Tests 4 attack scenarios: password reset poisoning (via Collaborator),
 * routing SSRF to internal hosts, duplicate Host headers, and override headers.
 */
public class HostHeaderScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Password reset / auth-related endpoint pattern
    private static final Pattern RESET_ENDPOINT_PATTERN = Pattern.compile(
            "/reset|/forgot|/password|/register|/signup|/login|/auth|/account/recover|/recover|/verify|/activate|/invitation|/invite|/confirm",
            Pattern.CASE_INSENSITIVE
    );

    // Internal host payloads for routing SSRF
    private static final String[] INTERNAL_HOSTS = {
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "169.254.169.254",
            "metadata.google.internal",
            "[::1]",
    };

    // Override headers
    private static final String[] OVERRIDE_HEADERS = {
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "Forwarded",
    };

    @Override
    public String getId() { return "host-header"; }

    @Override
    public String getName() { return "Host Header Injection Scanner"; }

    @Override
    public String getDescription() {
        return "Detects Host header injection: password reset poisoning, routing SSRF, duplicate Host, and override headers (X-Forwarded-Host, etc.).";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());

        if (!dedup.markIfNew("host-header", urlPath, "Host")) return Collections.emptyList();

        try {
            String url = request.url();

            // Phase 1: Password reset poisoning (only on reset-like endpoints)
            if (config.getBool("host.oob.enabled", true) && RESET_ENDPOINT_PATTERN.matcher(urlPath).find()) {
                testPasswordResetPoisoning(requestResponse, url);
            }

            // Phase 2: Routing SSRF via Host header
            if (config.getBool("host.internal.enabled", true)) {
                testRoutingSsrf(requestResponse, url);
            }

            // Phase 3: Duplicate Host headers
            testDuplicateHost(requestResponse, url);

            // Phase 4: Override headers
            testOverrideHeaders(requestResponse, url);

        } catch (Exception e) {
            api.logging().logToError("Host header test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: PASSWORD RESET POISONING ====================

    private void testPasswordResetPoisoning(HttpRequestResponse original, String url) throws InterruptedException {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return;

        AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
        String collabPayload = collaboratorManager.generatePayload(
                "host-header", url, "Host", "Password reset poisoning via Host header",
                interaction -> {
                    findingsStore.addFinding(Finding.builder("host-header",
                                    "Host Header Injection: Password Reset Poisoning",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("Host")
                            .evidence("Collaborator " + interaction.type().name() + " interaction from "
                                    + interaction.clientIp() + " at " + interaction.timeStamp())
                            .description("Password reset poisoning confirmed. When the Host header was replaced "
                                    + "with a Collaborator domain on a password reset endpoint, the application "
                                    + "generated a reset link pointing to the attacker's domain. A victim clicking "
                                    + "the link would leak their reset token to the attacker.")
                            .remediation("Never use the Host header to generate URLs in emails or password reset links. "
                                    + "Use a hardcoded, server-side configured base URL instead.")
                            .requestResponse(sentRequest.get())
                            .build());
                    api.logging().logToOutput("[Host Header] Password reset poisoning confirmed! " + url);
                });

        if (collabPayload == null) return;

        try {
            HttpRequest modified = original.request()
                    .withRemovedHeader("Host")
                    .withAddedHeader("Host", collabPayload);
            HttpRequestResponse result = api.http().sendRequest(modified);
            sentRequest.set(result);
        } catch (Exception e) {
            api.logging().logToError("Password reset poisoning test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 2: ROUTING SSRF ====================

    private void testRoutingSsrf(HttpRequestResponse original, String url) throws InterruptedException {
        // Capture baseline first
        HttpRequestResponse baseline;
        try {
            baseline = api.http().sendRequest(original.request());
        } catch (Exception e) {
            return;
        }
        if (baseline == null || baseline.response() == null) return;

        int baselineStatus = baseline.response().statusCode();
        int baselineLen = baseline.response().bodyToString().length();

        for (String internalHost : INTERNAL_HOSTS) {
            try {
                HttpRequest modified = original.request()
                        .withRemovedHeader("Host")
                        .withAddedHeader("Host", internalHost);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                int resultLen = result.response().bodyToString().length();

                // Different status code or significantly different body length suggests routing change
                boolean statusChanged = resultStatus != baselineStatus;
                boolean bodyChanged = Math.abs(resultLen - baselineLen) > 200;

                if (resultStatus == 200 && (statusChanged || bodyChanged)) {
                    Severity sev = Severity.HIGH;
                    Confidence conf = bodyChanged && statusChanged ? Confidence.CERTAIN : Confidence.FIRM;

                    findingsStore.addFinding(Finding.builder("host-header",
                                    "Host Header Injection: Routing to Internal Host (" + internalHost + ")",
                                    sev, conf)
                            .url(url).parameter("Host")
                            .evidence("Host: " + internalHost + " | Status: " + resultStatus
                                    + " (baseline: " + baselineStatus + ") | Body length: " + resultLen
                                    + " (baseline: " + baselineLen + ")")
                            .description("Setting the Host header to '" + internalHost + "' caused a different "
                                    + "response, indicating the server may route requests based on the Host header. "
                                    + "This could allow access to internal services or admin panels.")
                            .remediation("Configure the web server to reject requests with unexpected Host headers. "
                                    + "Use a whitelist of allowed Host values.")
                            .requestResponse(result)
                            .build());
                    return;
                }
            } catch (Exception e) {
                api.logging().logToError("Host routing SSRF test failed for " + internalHost + ": " + e.getMessage());
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 3: DUPLICATE HOST HEADERS ====================

    private void testDuplicateHost(HttpRequestResponse original, String url) throws InterruptedException {
        String originalHost = "";
        for (var h : original.request().headers()) {
            if (h.name().equalsIgnoreCase("Host")) {
                originalHost = h.value();
                break;
            }
        }
        if (originalHost.isEmpty()) return;

        String attackerHost = "attacker.com";
        try {
            // Add a second Host header (keep the original, add attacker's)
            HttpRequest modified = original.request()
                    .withAddedHeader("Host", attackerHost);
            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result == null || result.response() == null) return;

            String body = result.response().bodyToString();
            // Check if the attacker host appears in the response (indicating the second Host was used)
            if (body != null && body.contains(attackerHost)) {
                findingsStore.addFinding(Finding.builder("host-header",
                                "Host Header Injection: Duplicate Host Header Accepted",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("Host")
                        .evidence("Original Host: " + originalHost + " | Injected second Host: " + attackerHost
                                + " | Attacker host reflected in response body")
                        .description("The server accepted a request with two Host headers and used the "
                                + "attacker-controlled value. This can lead to cache poisoning, password "
                                + "reset poisoning, or SSRF depending on how the Host is used.")
                        .remediation("Configure the web server/reverse proxy to reject requests with "
                                + "duplicate Host headers.")
                        .requestResponse(result)
                        .build());
            }
        } catch (Exception e) {
            api.logging().logToError("Duplicate Host test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 4: OVERRIDE HEADERS ====================

    private void testOverrideHeaders(HttpRequestResponse original, String url) throws InterruptedException {
        String attackerValue = "attacker.com";

        for (String header : OVERRIDE_HEADERS) {
            try {
                // Test 1: Simple reflection test
                String headerValue = header.equals("Forwarded")
                        ? "host=attacker.com"
                        : attackerValue;

                HttpRequest modified = original.request()
                        .withRemovedHeader(header)
                        .withAddedHeader(header, headerValue);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result != null && result.response() != null) {
                    String body = result.response().bodyToString();
                    if (body != null && body.contains(attackerValue)) {
                        findingsStore.addFinding(Finding.builder("host-header",
                                        "Host Header Override via " + header,
                                        Severity.MEDIUM, Confidence.FIRM)
                                .url(url).parameter(header)
                                .evidence(header + ": " + headerValue + " | Attacker value reflected in response")
                                .description("The override header '" + header + "' is processed by the server "
                                        + "and its value reflected in the response. This can be used for cache "
                                        + "poisoning, password reset poisoning, or open redirect attacks.")
                                .remediation("Ignore or strip override headers unless they come from a trusted "
                                        + "reverse proxy. Configure the web server to only trust these headers "
                                        + "from specific upstream IPs.")
                                .requestResponse(result)
                                .build());
                    }
                }
                perHostDelay();

                // Test 2: OOB test via Collaborator
                if (config.getBool("host.oob.enabled", true)
                        && collaboratorManager != null && collaboratorManager.isAvailable()) {
                    AtomicReference<HttpRequestResponse> oobSent = new AtomicReference<>();
                    String collabPayload = collaboratorManager.generatePayload(
                            "host-header", url, header, "Host override OOB via " + header,
                            interaction -> {
                                findingsStore.addFinding(Finding.builder("host-header",
                                                "Host Header Override (OOB Confirmed) via " + header,
                                                Severity.CRITICAL, Confidence.CERTAIN)
                                        .url(url).parameter(header)
                                        .evidence("Collaborator " + interaction.type().name() + " interaction from "
                                                + interaction.clientIp() + " via " + header)
                                        .description("The server followed the override header '" + header + "' "
                                                + "and made an external request to the Collaborator server. "
                                                + "This confirms the header is actively used for routing or URL generation.")
                                        .remediation("Strip or ignore override headers from untrusted sources.")
                                        .requestResponse(oobSent.get())
                                        .build());
                            });

                    if (collabPayload != null) {
                        String oobHeaderValue = header.equals("Forwarded")
                                ? "host=" + collabPayload
                                : collabPayload;
                        HttpRequest oobModified = original.request()
                                .withRemovedHeader(header)
                                .withAddedHeader(header, oobHeaderValue);
                        oobSent.set(api.http().sendRequest(oobModified));
                        perHostDelay();
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Override header test failed for " + header + ": " + e.getMessage());
            }
        }
    }

    // ==================== HELPERS ====================

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("host.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}
