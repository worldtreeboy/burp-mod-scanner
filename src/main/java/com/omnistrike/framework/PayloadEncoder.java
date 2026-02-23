package com.omnistrike.framework;

/**
 * Smart URL encoder for scanner payloads.
 * Encodes only characters that break HTTP/URL syntax (space, &amp;, #, +)
 * while preserving existing percent-encoded sequences (%0a, %00, %252e, etc.).
 *
 * This prevents double-encoding of pre-encoded bypass payloads while still
 * producing valid HTTP requests.
 */
public final class PayloadEncoder {

    private PayloadEncoder() {}

    /**
     * Encode a payload value for use in a URL query string or form-encoded body.
     * Preserves existing %XX sequences, encodes only HTTP-breaking characters.
     *
     * @param payload The raw payload string (may contain pre-encoded sequences)
     * @return Encoded string safe for URL/body parameter values
     */
    public static String encode(String payload) {
        if (payload == null) return null;

        StringBuilder sb = new StringBuilder(payload.length() + 16);
        int len = payload.length();

        for (int i = 0; i < len; i++) {
            char c = payload.charAt(i);

            // Preserve existing %XX sequences (pre-encoded bypass payloads)
            if (c == '%' && i + 2 < len && isHex(payload.charAt(i + 1)) && isHex(payload.charAt(i + 2))) {
                sb.append(c);
                sb.append(payload.charAt(i + 1));
                sb.append(payload.charAt(i + 2));
                i += 2;
                continue;
            }

            // Encode characters that break HTTP request line or URL/body parameter parsing
            switch (c) {
                case ' ':  sb.append("%20"); break;
                case '&':  sb.append("%26"); break;
                case '#':  sb.append("%23"); break;
                case '+':  sb.append("%2B"); break;
                case ';':  sb.append("%3B"); break;  // Parameter separator in some servers
                case '%':  sb.append("%25"); break;  // Bare % not followed by hex digits
                default:   sb.append(c);     break;
            }
        }

        return sb.toString();
    }

    /**
     * Inject a payload into a specific cookie within the Cookie header,
     * bypassing Burp's cookie parser which splits on ';' and corrupts
     * payloads containing semicolons (e.g., SQL injection with multiple statements).
     *
     * Performs a direct string replacement in the raw Cookie header.
     *
     * @param request     The original HTTP request
     * @param cookieName  The cookie name to replace
     * @param payload     The payload value (may contain ';', spaces, etc.)
     * @return Modified request with the cookie value replaced
     */
    public static burp.api.montoya.http.message.requests.HttpRequest injectCookie(
            burp.api.montoya.http.message.requests.HttpRequest request,
            String cookieName, String payload) {
        String cookieHeader = null;
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Cookie")) {
                cookieHeader = h.value();
                break;
            }
        }

        if (cookieHeader == null) {
            // No existing Cookie header — add one
            return request.withAddedHeader("Cookie", cookieName + "=" + payload);
        }

        // Replace the cookie value using regex that matches from '=' to next '; ' or end of string
        String escaped = java.util.regex.Pattern.quote(cookieName);
        String replaced = cookieHeader.replaceFirst(
                escaped + "=[^;]*",
                cookieName + "=" + payload);

        return request.withRemovedHeader("Cookie").withAddedHeader("Cookie", replaced);
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
