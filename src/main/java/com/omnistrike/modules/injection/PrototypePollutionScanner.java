package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Server-Side Prototype Pollution Scanner
 * Targets JSON-body requests only. Injects __proto__ and constructor.prototype
 * pollution payloads, checks if canary values persist across subsequent requests
 * (indicating server-side object pollution).
 */
public class PrototypePollutionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    @Override
    public String getId() { return "proto-pollution"; }

    @Override
    public String getName() { return "Server-Side Prototype Pollution Scanner"; }

    @Override
    public String getDescription() {
        return "Detects server-side prototype pollution via __proto__ and constructor.prototype injection in JSON bodies, with persistence checks and known gadget testing.";
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

        // Gate: only process JSON body requests
        if (!isJsonRequest(request)) return Collections.emptyList();

        String body = request.bodyToString();
        if (body == null || body.isBlank()) return Collections.emptyList();

        // Verify it parses as JSON object
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
            if (!el.isJsonObject()) return Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }

        String urlPath = extractPath(request.url());
        if (!dedup.markIfNew("proto-pollution", urlPath, "__proto__")) return Collections.emptyList();

        try {
            String url = request.url();

            // Phase 1: __proto__ detection
            testProtoInjection(requestResponse, url);

            // Phase 2: constructor.prototype alternative vector
            testConstructorPrototype(requestResponse, url);

            // Phase 3: Known gadgets (Express/Fastify)
            if (config.getBool("proto.gadgets.enabled", true)) {
                testKnownGadgets(requestResponse, url);
            }

        } catch (Exception e) {
            api.logging().logToError("Prototype pollution test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    // ==================== PHASE 1: __PROTO__ INJECTION ====================

    private void testProtoInjection(HttpRequestResponse original, String url) throws InterruptedException {
        String canary = generateCanary();
        String canaryKey = "omnistrike_canary";

        // Inject __proto__ with canary
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", canaryKey, canary);
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;

        // Check same-request reflection
        String responseBody = result.response().bodyToString();
        boolean sameRequestReflection = responseBody != null && responseBody.contains(canary);

        // Check persistence: send a clean GET to the same host
        boolean persisted = checkPersistence(original, canary);

        if (persisted) {
            findingsStore.addFinding(Finding.builder("proto-pollution",
                            "Server-Side Prototype Pollution Confirmed (__proto__)",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url).parameter("__proto__." + canaryKey)
                    .evidence("Canary: " + canary + " | Injected via __proto__ | Canary persisted in follow-up request")
                    .description("Server-side prototype pollution confirmed. The injected __proto__ property "
                            + "persisted across requests, meaning the server's Object.prototype was polluted. "
                            + "This can lead to denial of service, authentication bypass, or remote code "
                            + "execution depending on how the polluted properties are used.")
                    .remediation("Use Object.create(null) for user-controlled objects. Use Map instead of plain "
                            + "objects. Filter __proto__ and constructor keys from user input. Use --frozen-intrinsics "
                            + "in Node.js.")
                    .requestResponse(result)
                    .build());

            // Cleanup
            if (config.getBool("proto.cleanupEnabled", true)) {
                cleanupPollution(original, canaryKey);
            }
        } else if (sameRequestReflection) {
            findingsStore.addFinding(Finding.builder("proto-pollution",
                            "Potential Server-Side Prototype Pollution (__proto__ reflected)",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url).parameter("__proto__." + canaryKey)
                    .evidence("Canary: " + canary + " | Reflected in same response (not confirmed persistent)")
                    .description("The __proto__ canary was reflected in the response to the same request but "
                            + "did not persist in a follow-up clean request. This may indicate prototype "
                            + "pollution that only affects the current request context, or the persistence "
                            + "check may not have targeted the right endpoint.")
                    .requestResponse(result)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 2: CONSTRUCTOR.PROTOTYPE ====================

    private void testConstructorPrototype(HttpRequestResponse original, String url) throws InterruptedException {
        String canary = generateCanary();
        String canaryKey = "omnistrike_canary";

        // Build constructor.prototype payload manually
        String body = original.request().bodyToString();
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(body).getAsJsonObject();
            com.google.gson.JsonObject prototype = new com.google.gson.JsonObject();
            prototype.addProperty(canaryKey, canary);
            com.google.gson.JsonObject constructor = new com.google.gson.JsonObject();
            constructor.add("prototype", prototype);
            root.add("constructor", constructor);

            String pollutedBody = new com.google.gson.Gson().toJson(root);
            HttpRequestResponse result = sendWithBody(original, pollutedBody);
            if (result == null || result.response() == null) return;

            boolean persisted = checkPersistence(original, canary);
            if (persisted) {
                findingsStore.addFinding(Finding.builder("proto-pollution",
                                "Server-Side Prototype Pollution Confirmed (constructor.prototype)",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter("constructor.prototype." + canaryKey)
                        .evidence("Canary: " + canary + " | Injected via constructor.prototype | Persisted")
                        .description("Server-side prototype pollution confirmed via constructor.prototype vector. "
                                + "This bypasses __proto__ filters but achieves the same effect.")
                        .remediation("Filter both __proto__ and constructor keys from user input. "
                                + "Use Object.create(null) or Map for user-controlled objects.")
                        .requestResponse(result)
                        .build());

                if (config.getBool("proto.cleanupEnabled", true)) {
                    cleanupPollution(original, canaryKey);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Constructor.prototype test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: KNOWN GADGETS ====================

    private void testKnownGadgets(HttpRequestResponse original, String url) throws InterruptedException {
        // Gadget 1: __proto__.status = 510 (Express/Fastify default status override)
        testStatusGadget(original, url);

        // Gadget 2: __proto__.content-type = text/omnistrike
        testContentTypeGadget(original, url);
    }

    private void testStatusGadget(HttpRequestResponse original, String url) throws InterruptedException {
        // Get baseline status
        HttpRequestResponse baseline;
        try {
            baseline = api.http().sendRequest(original.request());
        } catch (Exception e) { return; }
        if (baseline == null || baseline.response() == null) return;
        int baselineStatus = baseline.response().statusCode();

        // Inject __proto__.status = 510
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", "status", "510");
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;
        perHostDelay();

        // Send clean probe to check if status changed globally
        try {
            HttpRequestResponse probe = api.http().sendRequest(original.request());
            if (probe != null && probe.response() != null && probe.response().statusCode() == 510
                    && baselineStatus != 510) {
                findingsStore.addFinding(Finding.builder("proto-pollution",
                                "Prototype Pollution Gadget: Status Code Override",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter("__proto__.status")
                        .evidence("Injected __proto__.status=510 | Follow-up probe returned HTTP 510 "
                                + "(baseline was " + baselineStatus + ")")
                        .description("Prototype pollution gadget confirmed. The __proto__.status property "
                                + "was injected and subsequent responses returned HTTP 510, indicating "
                                + "the Express/Fastify default status was overridden via prototype pollution.")
                        .requestResponse(result)
                        .build());

                // Cleanup
                if (config.getBool("proto.cleanupEnabled", true)) {
                    cleanupPollution(original, "status");
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Status gadget probe failed: " + e.getMessage());
        }
        perHostDelay();
    }

    private void testContentTypeGadget(HttpRequestResponse original, String url) throws InterruptedException {
        String marker = "text/omnistrike";
        String pollutedBody = injectProtoPayload(original.request().bodyToString(),
                "__proto__", "content-type", marker);
        if (pollutedBody == null) return;

        HttpRequestResponse result = sendWithBody(original, pollutedBody);
        if (result == null || result.response() == null) return;
        perHostDelay();

        // Check if follow-up response has the modified content-type
        try {
            HttpRequestResponse probe = api.http().sendRequest(original.request());
            if (probe != null && probe.response() != null) {
                for (var h : probe.response().headers()) {
                    if (h.name().equalsIgnoreCase("Content-Type") && h.value().contains(marker)) {
                        findingsStore.addFinding(Finding.builder("proto-pollution",
                                        "Prototype Pollution Gadget: Content-Type Override",
                                        Severity.MEDIUM, Confidence.TENTATIVE)
                                .url(url).parameter("__proto__.content-type")
                                .evidence("Injected __proto__.content-type=" + marker
                                        + " | Follow-up response Content-Type contains marker")
                                .description("Prototype pollution may have overridden the default Content-Type "
                                        + "header. This could potentially be leveraged for XSS by setting "
                                        + "Content-Type to text/html on JSON endpoints.")
                                .requestResponse(result)
                                .build());

                        if (config.getBool("proto.cleanupEnabled", true)) {
                            cleanupPollution(original, "content-type");
                        }
                        break;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Content-Type gadget probe failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== HELPERS ====================

    private boolean isJsonRequest(HttpRequest request) {
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                return h.value().contains("application/json");
            }
        }
        return false;
    }

    /**
     * Inject a __proto__ (or other root-level key) payload into a JSON body.
     */
    private String injectProtoPayload(String jsonBody, String protoKey, String propertyName, String propertyValue) {
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(jsonBody).getAsJsonObject();
            com.google.gson.JsonObject protoObj = new com.google.gson.JsonObject();
            // Try to set as number if it looks like one, otherwise string
            try {
                int numVal = Integer.parseInt(propertyValue);
                protoObj.addProperty(propertyName, numVal);
            } catch (NumberFormatException e) {
                protoObj.addProperty(propertyName, propertyValue);
            }
            root.add(protoKey, protoObj);
            return new com.google.gson.Gson().toJson(root);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send a clean GET probe to the same host to check if canary persists.
     */
    private boolean checkPersistence(HttpRequestResponse original, String canary) {
        try {
            // Build a clean GET to the same URL (or root path)
            String probeUrl = original.request().url();
            HttpRequest probe = HttpRequest.httpRequestFromUrl(probeUrl);
            // Copy Host header from original
            for (var h : original.request().headers()) {
                if (h.name().equalsIgnoreCase("Host")) {
                    probe = probe.withRemovedHeader("Host").withAddedHeader("Host", h.value());
                    break;
                }
            }

            HttpRequestResponse result = api.http().sendRequest(probe);
            if (result != null && result.response() != null) {
                String body = result.response().bodyToString();
                if (body != null && body.contains(canary)) return true;
                // Also check headers
                for (var h : result.response().headers()) {
                    if (h.value().contains(canary)) return true;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Persistence probe failed: " + e.getMessage());
        }
        return false;
    }

    /**
     * Send a cleanup request setting the polluted property to null.
     */
    private void cleanupPollution(HttpRequestResponse original, String propertyName) {
        try {
            com.google.gson.JsonObject root = com.google.gson.JsonParser.parseString(
                    original.request().bodyToString()).getAsJsonObject();
            com.google.gson.JsonObject protoObj = new com.google.gson.JsonObject();
            protoObj.add(propertyName, com.google.gson.JsonNull.INSTANCE);
            root.add("__proto__", protoObj);
            String cleanupBody = new com.google.gson.Gson().toJson(root);
            sendWithBody(original, cleanupBody);
            api.logging().logToOutput("[ProtoPollution] Sent cleanup for property: " + propertyName);
        } catch (Exception e) {
            api.logging().logToError("Prototype pollution cleanup failed: " + e.getMessage());
        }
    }

    private HttpRequestResponse sendWithBody(HttpRequestResponse original, String body) {
        try {
            HttpRequest modified = original.request().withBody(body);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private String generateCanary() {
        return "omniproto" + String.format("%06x", ThreadLocalRandom.current().nextInt(0, 0xFFFFFF));
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
        int delay = config.getInt("proto.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}
