package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;

/**
 * CORS Misconfiguration Scanner
 * Replays requests with manipulated Origin headers and checks ACAO/ACAC response headers
 * for dangerous misconfigurations that allow cross-origin data theft.
 */
public class CorsMisconfScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    @Override
    public String getId() { return "cors-scanner"; }

    @Override
    public String getName() { return "CORS Misconfiguration Scanner"; }

    @Override
    public String getDescription() {
        return "Detects CORS misconfigurations: reflected origins, null origin, subdomain trust, scheme downgrade, wildcard with credentials.";
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

        if (!dedup.markIfNew("cors-scanner", urlPath, "Origin")) return Collections.emptyList();

        try {
            testCors(requestResponse);
        } catch (Exception e) {
            api.logging().logToError("CORS test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    private void testCors(HttpRequestResponse original) throws InterruptedException {
        String url = original.request().url();
        String targetDomain = extractDomain(url);

        // Phase 1: Reflected origin (with credentials)
        testReflectedOrigin(original, url);

        // Phase 2: Null origin
        testNullOrigin(original, url);

        // Phase 3: Subdomain trust
        testSubdomainTrust(original, url, targetDomain);

        // Phase 4: Scheme downgrade
        if (url.startsWith("https://")) {
            testSchemeDowngrade(original, url, targetDomain);
        }

        // Phase 5: Wildcard with credentials (check existing response)
        testWildcardWithCredentials(original, url);

        // Phase 6: Preflight bypass
        if (config.getBool("cors.preflight.enabled", true)) {
            testPreflightBypass(original, url);
        }
    }

    // ==================== PHASE 1: REFLECTED ORIGIN ====================

    private void testReflectedOrigin(HttpRequestResponse original, String url) throws InterruptedException {
        String attackerOrigin = "https://attacker.com";
        HttpRequestResponse result = sendWithOrigin(original, attackerOrigin);
        if (result == null || result.response() == null) return;

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);

        if (attackerOrigin.equals(acao)) {
            if (acac) {
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Misconfiguration: Reflected Origin with Credentials",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + attackerOrigin + " | ACAO: " + acao + " | ACAC: true")
                        .description("The server reflects arbitrary Origin headers in Access-Control-Allow-Origin "
                                + "AND sets Access-Control-Allow-Credentials: true. An attacker can steal "
                                + "authenticated data cross-origin via a malicious page.")
                        .remediation("Whitelist specific trusted origins instead of reflecting the Origin header. "
                                + "Never combine reflected origins with Access-Control-Allow-Credentials: true.")
                        .requestResponse(result)
                        .build());
            } else {
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Misconfiguration: Reflected Origin (no credentials)",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + attackerOrigin + " | ACAO: " + acao + " | ACAC: false/absent")
                        .description("The server reflects arbitrary Origin headers but does not set "
                                + "Access-Control-Allow-Credentials. Unauthenticated cross-origin reads are possible.")
                        .remediation("Whitelist specific trusted origins instead of reflecting the Origin header.")
                        .requestResponse(result)
                        .build());
            }
        }
        perHostDelay();
    }

    // ==================== PHASE 2: NULL ORIGIN ====================

    private void testNullOrigin(HttpRequestResponse original, String url) throws InterruptedException {
        HttpRequestResponse result = sendWithOrigin(original, "null");
        if (result == null || result.response() == null) return;

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);

        if ("null".equals(acao) && acac) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS Misconfiguration: Null Origin Trusted with Credentials",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url).parameter("Origin")
                    .evidence("Origin: null | ACAO: null | ACAC: true")
                    .description("The server trusts the 'null' origin with credentials. Sandboxed iframes "
                            + "(e.g., data: URIs, file:// pages) send Origin: null. An attacker can exploit "
                            + "this via a sandboxed iframe to steal authenticated data.")
                    .remediation("Never whitelist the null origin. Reject requests with Origin: null.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: SUBDOMAIN TRUST ====================

    private void testSubdomainTrust(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        String[] evilOrigins = {
                "https://evil-" + targetDomain,
                "https://" + targetDomain + ".evil.com",
                "https://evil." + targetDomain,
        };

        for (String evilOrigin : evilOrigins) {
            HttpRequestResponse result = sendWithOrigin(original, evilOrigin);
            if (result == null || result.response() == null) continue;

            String acao = extractAcao(result);
            if (evilOrigin.equals(acao)) {
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Misconfiguration: Subdomain/Prefix Trust",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + evilOrigin + " | ACAO: " + acao
                                + " | ACAC: " + hasAcac(result))
                        .description("The server trusts origins that partially match the target domain. "
                                + "Origin '" + evilOrigin + "' was accepted. An attacker controlling a "
                                + "similar domain or subdomain can perform cross-origin data theft.")
                        .remediation("Use strict origin matching. Do not use substring/prefix/suffix matching "
                                + "for allowed origins.")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 4: SCHEME DOWNGRADE ====================

    private void testSchemeDowngrade(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        String httpOrigin = "http://" + targetDomain;
        HttpRequestResponse result = sendWithOrigin(original, httpOrigin);
        if (result == null || result.response() == null) return;

        String acao = extractAcao(result);
        if (httpOrigin.equals(acao)) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS Misconfiguration: HTTP Origin Trusted on HTTPS",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: " + httpOrigin + " | ACAO: " + acao
                            + " | ACAC: " + hasAcac(result))
                    .description("The HTTPS endpoint trusts HTTP origins. A man-in-the-middle attacker can "
                            + "hijack the HTTP origin to steal data from the HTTPS endpoint via CORS.")
                    .remediation("Only allow HTTPS origins on HTTPS endpoints. Never trust HTTP origins "
                            + "for sensitive resources served over HTTPS.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 5: WILDCARD WITH CREDENTIALS ====================

    private void testWildcardWithCredentials(HttpRequestResponse original, String url) throws InterruptedException {
        // Send a request with an Origin header to trigger CORS response headers
        HttpRequestResponse result = sendWithOrigin(original, "https://check.example.com");
        if (result == null || result.response() == null) return;

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);

        if ("*".equals(acao) && acac) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS Misconfiguration: Wildcard with Credentials",
                            Severity.LOW, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("ACAO: * | ACAC: true")
                    .description("The server sets Access-Control-Allow-Origin: * together with "
                            + "Access-Control-Allow-Credentials: true. Per the CORS spec, browsers "
                            + "should reject this combination, but older/misconfigured clients may not. "
                            + "This indicates a misconfigured CORS policy.")
                    .remediation("Never use ACAO: * with ACAC: true. If credentials are needed, "
                            + "reflect a specific whitelisted origin.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 6: PREFLIGHT BYPASS ====================

    private void testPreflightBypass(HttpRequestResponse original, String url) throws InterruptedException {
        // Send a simple GET request (no custom headers) with an attacker origin
        // If ACAO reflects on a simple request, preflight is not required and CORS is exploitable
        String attackerOrigin = "https://attacker.com";
        HttpRequest simpleGet;
        try {
            // Build a simple GET to the same URL with only the Origin header
            simpleGet = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader("Origin", attackerOrigin);
        } catch (Exception e) {
            return;
        }

        try {
            HttpRequestResponse result = api.http().sendRequest(simpleGet);
            if (result == null || result.response() == null) return;

            String acao = extractAcao(result);
            if (attackerOrigin.equals(acao)) {
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Misconfiguration: Simple Request Reflects Origin (Preflight Bypass)",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Simple GET with Origin: " + attackerOrigin + " | ACAO: " + acao)
                        .description("A simple GET request (no preflight required) reflects the attacker's Origin. "
                                + "This means CORS exploitation does not require a preflight OPTIONS request, "
                                + "making the attack simpler to execute via a basic fetch() or XHR.")
                        .remediation("Validate the Origin header on all request types, not just preflighted requests.")
                        .requestResponse(result)
                        .build());
            }
        } catch (Exception e) {
            api.logging().logToError("CORS preflight bypass test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendWithOrigin(HttpRequestResponse original, String origin) {
        try {
            HttpRequest modified = original.request()
                    .withRemovedHeader("Origin")
                    .withAddedHeader("Origin", origin);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractAcao(HttpRequestResponse response) {
        for (var h : response.response().headers()) {
            if (h.name().equalsIgnoreCase("Access-Control-Allow-Origin")) {
                return h.value().trim();
            }
        }
        return null;
    }

    private boolean hasAcac(HttpRequestResponse response) {
        for (var h : response.response().headers()) {
            if (h.name().equalsIgnoreCase("Access-Control-Allow-Credentials")) {
                return "true".equalsIgnoreCase(h.value().trim());
            }
        }
        return false;
    }

    private String extractDomain(String url) {
        try {
            String noScheme = url.replaceFirst("^https?://", "");
            int slash = noScheme.indexOf('/');
            String hostPort = slash >= 0 ? noScheme.substring(0, slash) : noScheme;
            int colon = hostPort.indexOf(':');
            return colon >= 0 ? hostPort.substring(0, colon) : hostPort;
        } catch (Exception e) {
            return "";
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("cors.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}
