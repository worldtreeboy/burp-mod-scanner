package com.omnistrike.framework.wordlist;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.model.*;

import burp.api.montoya.sitemap.SiteMapFilter;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Passive Word Harvester — collects words from all proxied HTTP traffic
 * for a user-specified target domain. Extracted words can be filtered and
 * exported as wordlists for fuzzing, brute-forcing, and dictionary attacks.
 *
 * Only collects from the domain set via setTargetDomain(). If no domain is
 * set, no words are collected. This module is purely passive — it cannot be
 * triggered from the context menu or active scan.
 */
public class WordlistGenerator implements ScanModule {

    private MontoyaApi api;

    // Target domain — only traffic matching this domain is harvested
    private volatile String targetDomain = "";

    // Thread-safe word storage: word (lowercase) -> WordEntry
    private final ConcurrentHashMap<String, WordEntry> wordStore = new ConcurrentHashMap<>();

    // Dedup: skip flows we've already processed (host + path + bodyLength)
    private final ConcurrentHashMap<String, Boolean> processedFlows = new ConcurrentHashMap<>();

    // Max response body size to analyze (500KB)
    private static final int MAX_BODY_SIZE = 512_000;

    // Word length constraints
    private static final int DEFAULT_MIN_LENGTH = 3;
    private static final int DEFAULT_MAX_LENGTH = 64;

    // ==================== Stop Words ====================
    private static final Set<String> STOP_WORDS = Set.of(
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
            "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
            "how", "its", "may", "new", "now", "old", "see", "way", "who", "did",
            "let", "say", "she", "too", "use", "from", "have", "been", "some",
            "than", "that", "them", "then", "this", "what", "when", "will", "with",
            "about", "could", "other", "their", "there", "these", "those", "which",
            "would", "after", "before", "being", "between", "both", "each", "into",
            "just", "like", "more", "most", "much", "must", "over", "such", "very",
            "your", "also", "back", "come", "does", "done", "down", "even",
            "find", "first", "give", "goes", "good", "here", "high", "home", "keep",
            "last", "long", "look", "made", "make", "many", "name",
            "only", "part", "same", "still", "take", "tell", "text", "time", "well",
            "work", "year", "true", "false", "null", "undefined", "none", "class",
            "function", "return", "import", "export", "const", "var", "http", "https",
            "www", "html", "body", "head", "meta", "link", "script", "style", "div",
            "span", "img", "type", "charset", "utf", "content", "application",
            "json", "xml", "javascript", "css", "width", "height", "display", "margin",
            "padding", "border", "color", "font", "size", "weight", "solid"
    );

    // ==================== Noise Patterns ====================
    // Hex tokens (32+ chars of hex)
    private static final Pattern HEX_TOKEN = Pattern.compile("^[0-9a-f]{32,}$", Pattern.CASE_INSENSITIVE);
    // Base64 blobs (20+ chars)
    private static final Pattern BASE64_BLOB = Pattern.compile("^[A-Za-z0-9+/]{20,}={0,2}$");
    // Pure numbers
    private static final Pattern PURE_NUMBER = Pattern.compile("^\\d+$");
    // CSS values like px, em, rgb, hex colors
    private static final Pattern CSS_NOISE = Pattern.compile("^(\\d+px|\\d+em|\\d+rem|#[0-9a-f]{3,8}|rgba?\\()$", Pattern.CASE_INSENSITIVE);

    // ==================== Extraction Patterns ====================
    // JS string literals: 'word' or "word"
    private static final Pattern JS_STRING = Pattern.compile("[\"']([a-zA-Z][a-zA-Z0-9_/-]{2,63})[\"']");
    // JS variable/function names
    private static final Pattern JS_IDENTIFIER = Pattern.compile("(?:var|let|const|function)\\s+([a-zA-Z_$][a-zA-Z0-9_$]{2,63})");
    // JS route patterns: '/api/something'
    private static final Pattern JS_ROUTE = Pattern.compile("[\"'](/[a-zA-Z][a-zA-Z0-9_/-]{2,63})[\"']");
    // HTML form input names/ids
    private static final Pattern HTML_INPUT = Pattern.compile("(?:name|id|class|value)\\s*=\\s*[\"']([a-zA-Z][a-zA-Z0-9_-]{2,63})[\"']", Pattern.CASE_INSENSITIVE);
    // HTML comment content
    private static final Pattern HTML_COMMENT = Pattern.compile("<!--\\s*(.*?)\\s*-->", Pattern.DOTALL);
    // JSON key names
    private static final Pattern JSON_KEY = Pattern.compile("\"([a-zA-Z][a-zA-Z0-9_]{2,63})\"\\s*:");
    // Generic word boundary words (alphanumeric with underscores/hyphens)
    private static final Pattern WORD_BOUNDARY = Pattern.compile("\\b([a-zA-Z][a-zA-Z0-9_-]{2,63})\\b");
    // Error message keywords
    private static final Pattern ERROR_KEYWORDS = Pattern.compile("(?:error|exception|warning|denied|forbidden|unauthorized|invalid|failed|missing|timeout|expired|duplicate)", Pattern.CASE_INSENSITIVE);

    // ==================== Word Category ====================
    public enum WordCategory {
        PATH("Path"),
        PARAM("Parameter"),
        CONTENT("Content");

        private final String displayName;
        WordCategory(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
    }

    // ==================== Word Entry ====================
    public static class WordEntry {
        private final String word;
        private final AtomicInteger frequency;
        private volatile WordCategory category;
        private volatile String firstSeenUrl;

        public WordEntry(String word, WordCategory category, String firstSeenUrl) {
            this.word = word;
            this.frequency = new AtomicInteger(1);
            this.category = category;
            this.firstSeenUrl = firstSeenUrl;
        }

        public String getWord() { return word; }
        public int getFrequency() { return frequency.get(); }
        public int incrementFrequency() { return frequency.incrementAndGet(); }
        public WordCategory getCategory() { return category; }
        public String getFirstSeenUrl() { return firstSeenUrl; }

        /** Upgrade category priority: PATH > PARAM > CONTENT */
        public void upgradeCategory(WordCategory newCat) {
            if (newCat.ordinal() < category.ordinal()) {
                category = newCat;
            }
        }
    }

    // ==================== ScanModule Interface ====================

    @Override
    public String getId() { return "wordlist-generator"; }

    @Override
    public String getName() { return "Wordlist Generator"; }

    @Override
    public String getDescription() { return "Passive word harvester for building custom wordlists from proxied traffic"; }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
    }

    @Override
    public void destroy() {
        // No background threads to clean up
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        try {
            // Skip if no target domain configured
            String domain = targetDomain;
            if (domain == null || domain.isEmpty()) return List.of();

            HttpRequest request = requestResponse.request();
            if (request == null) return List.of();

            // Domain filtering — only harvest from the user's specified domain
            String host = request.httpService().host().toLowerCase();
            if (!matchesDomain(host, domain)) return List.of();

            // Dedup check
            String path = request.path();
            HttpResponse response = requestResponse.response();
            int bodyLen = (response != null && response.body() != null) ? response.body().length() : 0;
            String dedupKey = host + "|" + path + "|" + bodyLen;
            if (processedFlows.putIfAbsent(dedupKey, Boolean.TRUE) != null) return List.of();

            String url = request.url();

            // 1. Extract from URL path segments
            extractFromPath(path, url);

            // 2. Extract from query parameter names and values
            extractFromParams(request, url);

            // 3. Extract from request headers (custom headers)
            extractFromRequestHeaders(request, url);

            // 4. Extract from response
            if (response != null) {
                // Response headers
                extractFromResponseHeaders(response, url);

                // Response body (with size cap)
                String body = null;
                if (response.body() != null && response.body().length() <= MAX_BODY_SIZE) {
                    body = response.bodyToString();
                }
                if (body != null && !body.isEmpty()) {
                    String contentType = getContentType(response);
                    extractFromBody(body, contentType, url);
                }
            }
        } catch (Exception e) {
            // Never break the proxy pipeline
            if (api != null) {
                try {
                    api.logging().logToError("WordlistGenerator error: " + e.getMessage());
                } catch (Exception ignored) {}
            }
        }
        // This module doesn't produce findings
        return List.of();
    }

    // ==================== Domain Matching ====================

    private boolean matchesDomain(String host, String targetDomain) {
        String target = targetDomain.toLowerCase().trim();
        if (target.isEmpty()) return false;
        // Exact match or subdomain match
        return host.equals(target) || host.endsWith("." + target);
    }

    // ==================== Extraction Methods ====================

    private void extractFromPath(String path, String url) {
        if (path == null) return;
        // Remove query string
        int qIdx = path.indexOf('?');
        String cleanPath = qIdx > 0 ? path.substring(0, qIdx) : path;
        // Split by '/'
        String[] segments = cleanPath.split("/");
        for (String segment : segments) {
            if (segment.isEmpty()) continue;
            // Remove file extensions
            int dotIdx = segment.lastIndexOf('.');
            if (dotIdx > 0) {
                String name = segment.substring(0, dotIdx);
                addWord(name, WordCategory.PATH, url);
                // Also add the full segment if it's not just an extension
                String ext = segment.substring(dotIdx + 1);
                if (ext.length() <= 10) {
                    addWord(ext, WordCategory.PATH, url);
                }
            }
            addWord(segment, WordCategory.PATH, url);
            // Split camelCase and snake_case segments into sub-words
            splitCompoundWord(segment, WordCategory.PATH, url);
        }
    }

    private void extractFromParams(HttpRequest request, String url) {
        try {
            var params = request.parameters();
            if (params == null) return;
            for (var param : params) {
                // Parameter names are high-value
                String name = param.name();
                if (name != null && !name.isEmpty()) {
                    addWord(name, WordCategory.PARAM, url);
                    splitCompoundWord(name, WordCategory.PARAM, url);
                }
                // Parameter values (only short ones, not large blobs)
                String value = param.value();
                if (value != null && !value.isEmpty() && value.length() <= DEFAULT_MAX_LENGTH) {
                    addWord(value, WordCategory.PARAM, url);
                }
            }
        } catch (Exception ignored) {
            // Some requests may not have parseable parameters
        }
    }

    private void extractFromRequestHeaders(HttpRequest request, String url) {
        try {
            for (var header : request.headers()) {
                String name = header.name();
                // Skip standard headers — focus on custom/app-specific ones
                if (isStandardHeader(name)) continue;
                addWord(name, WordCategory.PARAM, url);
                // Short header values only
                String value = header.value();
                if (value != null && value.length() <= DEFAULT_MAX_LENGTH) {
                    extractWordsFromText(value, WordCategory.PARAM, url);
                }
            }
        } catch (Exception ignored) {}
    }

    private void extractFromResponseHeaders(HttpResponse response, String url) {
        try {
            for (var header : response.headers()) {
                String name = header.name();
                if (isStandardHeader(name)) continue;
                addWord(name, WordCategory.PARAM, url);
            }
        } catch (Exception ignored) {}
    }

    private void extractFromBody(String body, String contentType, String url) {
        if (contentType == null) contentType = "";

        if (contentType.contains("json")) {
            extractFromJson(body, url);
        }

        if (contentType.contains("html")) {
            extractFromHtml(body, url);
        }

        if (contentType.contains("javascript") || contentType.contains("ecmascript")) {
            extractFromJavaScript(body, url);
        }

        // Always do generic word extraction as a catch-all
        extractWordsFromText(body, WordCategory.CONTENT, url);
    }

    private void extractFromJson(String body, String url) {
        Matcher m = JSON_KEY.matcher(body);
        while (m.find()) {
            addWord(m.group(1), WordCategory.PARAM, url);
        }
    }

    private void extractFromHtml(String body, String url) {
        // Form input names, ids, classes
        Matcher inputM = HTML_INPUT.matcher(body);
        while (inputM.find()) {
            addWord(inputM.group(1), WordCategory.PARAM, url);
        }

        // HTML comments often contain useful info
        Matcher commentM = HTML_COMMENT.matcher(body);
        while (commentM.find()) {
            String comment = commentM.group(1);
            if (comment.length() <= 500) {
                extractWordsFromText(comment, WordCategory.CONTENT, url);
            }
        }

        // Extract from visible text (strip tags crudely)
        String textOnly = body.replaceAll("<script[^>]*>.*?</script>", " ")
                .replaceAll("<style[^>]*>.*?</style>", " ")
                .replaceAll("<[^>]+>", " ");
        extractWordsFromText(textOnly, WordCategory.CONTENT, url);
    }

    private void extractFromJavaScript(String body, String url) {
        // String literals
        Matcher strM = JS_STRING.matcher(body);
        while (strM.find()) {
            addWord(strM.group(1), WordCategory.CONTENT, url);
        }

        // Variable/function names
        Matcher idM = JS_IDENTIFIER.matcher(body);
        while (idM.find()) {
            addWord(idM.group(1), WordCategory.PARAM, url);
        }

        // Route patterns
        Matcher routeM = JS_ROUTE.matcher(body);
        while (routeM.find()) {
            String route = routeM.group(1);
            addWord(route, WordCategory.PATH, url);
            // Also extract individual segments
            extractFromPath(route, url);
        }
    }

    private void extractWordsFromText(String text, WordCategory category, String url) {
        Matcher m = WORD_BOUNDARY.matcher(text);
        int count = 0;
        while (m.find() && count < 5000) { // Cap to avoid runaway extraction
            addWord(m.group(1), category, url);
            count++;
        }
    }

    // ==================== Word Storage ====================

    private void addWord(String raw, WordCategory category, String url) {
        if (raw == null) return;
        String word = raw.trim().toLowerCase();

        // Length filter
        if (word.length() < DEFAULT_MIN_LENGTH || word.length() > DEFAULT_MAX_LENGTH) return;

        // Noise filters
        if (STOP_WORDS.contains(word)) return;
        if (PURE_NUMBER.matcher(word).matches()) return;
        if (HEX_TOKEN.matcher(word).matches()) return;
        if (BASE64_BLOB.matcher(word).matches()) return;
        if (CSS_NOISE.matcher(word).matches()) return;

        WordEntry existing = wordStore.get(word);
        if (existing != null) {
            existing.incrementFrequency();
            existing.upgradeCategory(category);
        } else {
            wordStore.putIfAbsent(word, new WordEntry(word, category, url));
        }
    }

    private void splitCompoundWord(String word, WordCategory category, String url) {
        // Split camelCase: "getUserName" -> "get", "User", "Name"
        String[] camelParts = word.split("(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");
        if (camelParts.length > 1) {
            for (String part : camelParts) {
                addWord(part, category, url);
            }
        }
        // Split snake_case/kebab-case: "user_name" -> "user", "name"
        String[] snakeParts = word.split("[_-]");
        if (snakeParts.length > 1) {
            for (String part : snakeParts) {
                addWord(part, category, url);
            }
        }
    }

    // ==================== Utility ====================

    private String getContentType(HttpResponse response) {
        try {
            for (var h : response.headers()) {
                if ("Content-Type".equalsIgnoreCase(h.name())) {
                    return h.value().toLowerCase();
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static final Set<String> STANDARD_HEADERS = Set.of(
            "host", "user-agent", "accept", "accept-language", "accept-encoding",
            "connection", "content-type", "content-length", "cache-control", "pragma",
            "cookie", "set-cookie", "authorization", "referer", "origin",
            "if-modified-since", "if-none-match", "etag", "last-modified",
            "date", "server", "expires", "transfer-encoding", "content-encoding",
            "vary", "access-control-allow-origin", "access-control-allow-methods",
            "access-control-allow-headers", "x-content-type-options",
            "x-frame-options", "x-xss-protection", "strict-transport-security",
            "content-security-policy", "location", "upgrade-insecure-requests",
            "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "dnt",
            "keep-alive", "te", "trailer", "upgrade"
    );

    private boolean isStandardHeader(String name) {
        return name == null || STANDARD_HEADERS.contains(name.toLowerCase());
    }

    // ==================== Public API ====================

    /** Set the target domain. Only traffic to this domain (and subdomains) is harvested.
     *  Accepts full URLs like https://example.com/ — protocol and trailing slashes are stripped. */
    public void setTargetDomain(String domain) {
        this.targetDomain = normalizeDomain(domain);
    }

    /** Strip protocol, path, port, and trailing slashes to get a bare hostname. */
    private static String normalizeDomain(String input) {
        if (input == null) return "";
        String d = input.trim().toLowerCase();
        // Strip protocol
        if (d.startsWith("https://")) d = d.substring(8);
        else if (d.startsWith("http://")) d = d.substring(7);
        // Strip path and query
        int slashIdx = d.indexOf('/');
        if (slashIdx >= 0) d = d.substring(0, slashIdx);
        // Strip port
        int colonIdx = d.indexOf(':');
        if (colonIdx >= 0) d = d.substring(0, colonIdx);
        return d.trim();
    }

    /** Get the currently configured target domain. */
    public String getTargetDomain() {
        return targetDomain;
    }

    /** Returns all collected words. */
    public Collection<WordEntry> getAllWords() {
        return wordStore.values();
    }

    /** Returns words filtered by category. */
    public List<WordEntry> getWordsByCategory(WordCategory category) {
        return wordStore.values().stream()
                .filter(e -> e.getCategory() == category)
                .collect(Collectors.toList());
    }

    /** Total unique word count. */
    public int getTotalCount() {
        return wordStore.size();
    }

    /** Count of words in a specific category. */
    public int getCountByCategory(WordCategory category) {
        return (int) wordStore.values().stream()
                .filter(e -> e.getCategory() == category)
                .count();
    }

    /** Clear all collected words and dedup state. */
    public void clearAll() {
        wordStore.clear();
        processedFlows.clear();
    }

    /**
     * Scrape existing site map history for the configured target domain.
     * Clears the dedup cache so all matching history items are re-processed.
     * Should be called from a background thread — not the EDT or Burp proxy thread.
     *
     * @return number of history items processed
     */
    public int scrapeHistory() {
        if (api == null) return 0;
        String domain = targetDomain;
        if (domain == null || domain.isEmpty()) return 0;

        // Clear dedup so we process history items even if seen during live capture
        processedFlows.clear();

        int processed = 0;
        for (String scheme : new String[]{"https://", "http://"}) {
            String prefix = scheme + domain;
            try {
                var filter = SiteMapFilter.prefixFilter(prefix);
                List<HttpRequestResponse> entries = api.siteMap().requestResponses(filter);
                api.logging().logToOutput("[WordlistGenerator] Scraping " + prefix + " → " + entries.size() + " site map entries");
                for (HttpRequestResponse rr : entries) {
                    try {
                        if (rr.request() == null) continue;
                        processHttpFlow(rr, api);
                        processed++;
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                api.logging().logToError("[WordlistGenerator] Error scraping " + prefix + ": " + e.getMessage());
            }
        }
        api.logging().logToOutput("[WordlistGenerator] Scrape complete: processed " + processed + " items, " + wordStore.size() + " unique words");
        return processed;
    }

    /**
     * Export words matching the given filters.
     * @param category null for all categories
     * @param minLength minimum word length (0 for no filter)
     * @param maxLength maximum word length (0 for no filter)
     * @param includeRegex include only words matching this regex (null for no filter)
     * @param excludeRegex exclude words matching this regex (null for no filter)
     * @param sortByFrequency true to sort by frequency descending, false for alphabetical
     * @return list of words matching all filters
     */
    public List<String> exportWords(WordCategory category, int minLength, int maxLength,
                                     String includeRegex, String excludeRegex, boolean sortByFrequency) {
        Pattern include = null;
        Pattern exclude = null;
        try {
            if (includeRegex != null && !includeRegex.isEmpty()) include = Pattern.compile(includeRegex, Pattern.CASE_INSENSITIVE);
        } catch (Exception ignored) {}
        try {
            if (excludeRegex != null && !excludeRegex.isEmpty()) exclude = Pattern.compile(excludeRegex, Pattern.CASE_INSENSITIVE);
        } catch (Exception ignored) {}

        final Pattern incl = include;
        final Pattern excl = exclude;

        var stream = wordStore.values().stream();

        if (category != null) {
            stream = stream.filter(e -> e.getCategory() == category);
        }
        if (minLength > 0) {
            stream = stream.filter(e -> e.getWord().length() >= minLength);
        }
        if (maxLength > 0) {
            stream = stream.filter(e -> e.getWord().length() <= maxLength);
        }
        if (incl != null) {
            stream = stream.filter(e -> incl.matcher(e.getWord()).find());
        }
        if (excl != null) {
            stream = stream.filter(e -> !excl.matcher(e.getWord()).find());
        }

        if (sortByFrequency) {
            stream = stream.sorted(Comparator.comparingInt(WordEntry::getFrequency).reversed());
        } else {
            stream = stream.sorted(Comparator.comparing(WordEntry::getWord));
        }

        return stream.map(WordEntry::getWord).collect(Collectors.toList());
    }
}
