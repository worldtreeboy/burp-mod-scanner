package com.omnistrike.modules.ai.llm;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable snapshot of an HTTP request/response pair.
 * Captures all data as plain Strings on the proxy thread so it is safe
 * to pass to the background LLM analysis thread without touching Montoya objects.
 */
public class CapturedHttpExchange {

    private final String url;
    private final String method;
    private final List<String> requestHeaders;
    private final String requestBody;
    private final int statusCode;
    private final List<String> responseHeaders;
    private final String responseBody;

    private CapturedHttpExchange(String url, String method,
                                  List<String> requestHeaders, String requestBody,
                                  int statusCode, List<String> responseHeaders,
                                  String responseBody) {
        this.url = url;
        this.method = method;
        this.requestHeaders = Collections.unmodifiableList(requestHeaders);
        this.requestBody = requestBody;
        this.statusCode = statusCode;
        this.responseHeaders = Collections.unmodifiableList(responseHeaders);
        this.responseBody = responseBody;
    }

    /**
     * Creates a snapshot from a Montoya HttpRequestResponse.
     * Body strings are truncated to maxBodySize characters.
     */
    public static CapturedHttpExchange from(HttpRequestResponse reqRes, int maxBodySize) {
        var req = reqRes.request();
        var resp = reqRes.response();

        String url = req.url();
        String method = req.method();

        List<String> reqHeaders = new ArrayList<>();
        for (var h : req.headers()) {
            reqHeaders.add(h.name() + ": " + h.value());
        }

        String reqBody = truncate(req.bodyToString(), maxBodySize);

        int statusCode = resp != null ? resp.statusCode() : 0;

        List<String> respHeaders = new ArrayList<>();
        String respBody = "";
        if (resp != null) {
            for (var h : resp.headers()) {
                respHeaders.add(h.name() + ": " + h.value());
            }
            respBody = truncate(resp.bodyToString(), maxBodySize);
        }

        return new CapturedHttpExchange(url, method, reqHeaders, reqBody,
                statusCode, respHeaders, respBody);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "\n[... truncated at " + max + " chars]" : s;
    }

    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public List<String> getRequestHeaders() { return requestHeaders; }
    public String getRequestBody() { return requestBody; }
    public int getStatusCode() { return statusCode; }
    public List<String> getResponseHeaders() { return responseHeaders; }
    public String getResponseBody() { return responseBody; }

    /**
     * Builds a compact text representation for including in the LLM prompt.
     */
    public String toPromptText() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== REQUEST ===\n");
        sb.append(method).append(" ").append(url).append("\n");
        for (String h : requestHeaders) {
            // Skip large or binary-looking headers
            if (h.length() < 500) sb.append(h).append("\n");
        }
        if (!requestBody.isEmpty()) {
            sb.append("\n").append(requestBody).append("\n");
        }

        sb.append("\n=== RESPONSE (").append(statusCode).append(") ===\n");
        for (String h : responseHeaders) {
            if (h.length() < 500) sb.append(h).append("\n");
        }
        if (!responseBody.isEmpty()) {
            sb.append("\n").append(responseBody).append("\n");
        }
        return sb.toString();
    }
}
