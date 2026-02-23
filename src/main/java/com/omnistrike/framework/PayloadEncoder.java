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

            // Encode characters that break HTTP request line or URL parsing
            switch (c) {
                case ' ':  sb.append("%20"); break;
                case '&':  sb.append("%26"); break;
                case '#':  sb.append("%23"); break;
                case '+':  sb.append("%2B"); break;
                case '%':  sb.append("%25"); break;  // Bare % not followed by hex digits
                default:   sb.append(c);     break;
            }
        }

        return sb.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
