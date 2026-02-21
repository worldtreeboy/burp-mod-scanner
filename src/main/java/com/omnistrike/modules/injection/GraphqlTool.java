package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * MODULE 9: GraphQL Introspection & Attack Tool
 * Auto-detects GraphQL endpoints, runs introspection, maps schemas,
 * generates test queries, and runs security tests.
 */
public class GraphqlTool implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    private final ConcurrentHashMap<String, Boolean> detectedEndpoints = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, JsonObject> schemas = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> generatedQueries = new ConcurrentHashMap<>();
    private volatile String rawIntrospectionJson;

    private static final String INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } isDeprecated deprecationReason } inputFields { name type { kind name ofType { kind name ofType { kind name } } } defaultValue } interfaces { kind name } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { kind name } } directives { name description locations args { name type { kind name ofType { kind name ofType { kind name } } } defaultValue } } } }";

    // Sensitive field/type name patterns
    private static final Pattern SENSITIVE_AUTH = Pattern.compile(
            "(?i)(password|token|secret|apikey|api_key|accesstoken|refreshtoken|sessiontoken|credential|auth_token)");
    private static final Pattern SENSITIVE_PII = Pattern.compile(
            "(?i)(ssn|socialsecurity|creditcard|cardnumber|cvv|dob|dateofbirth|social_security)");
    private static final Pattern DANGEROUS_MUTATION = Pattern.compile(
            "(?i)(delete|remove|drop|destroy|admin|purge|truncate|reset|wipe|execute|runquery)");

    // Common GraphQL paths
    private static final String[] GRAPHQL_PATHS = {
            "/graphql", "/graphql/v1", "/api/graphql", "/gql", "/query",
            "/v1/graphql", "/graphql/console", "/graphiql", "/api/gql",
            "/v2/graphql", "/graphql/api"
    };

    @Override
    public String getId() { return "graphql-tool"; }

    @Override
    public String getName() { return "GraphQL Tool"; }

    @Override
    public String getDescription() {
        return "GraphQL introspection, schema analysis, query generation, and security testing.";
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

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        // Passive detection: look for GraphQL traffic patterns
        HttpRequest request = requestResponse.request();
        String url = request.url();
        String path = extractPath(url);
        String host = request.httpService().host();
        String baseUrl = request.httpService().toString();

        // Detect by path
        boolean pathMatch = false;
        for (String gqlPath : GRAPHQL_PATHS) {
            if (path.equalsIgnoreCase(gqlPath) || path.toLowerCase().startsWith(gqlPath + "?")) {
                pathMatch = true;
                break;
            }
        }

        // Detect by request body
        String body = null;
        try {
            body = request.bodyToString();
        } catch (Exception ignored) {}

        boolean bodyMatch = body != null && (body.contains("\"query\"") || body.contains("\"operationName\""));

        // Detect by response shape
        boolean responseMatch = false;
        if (requestResponse.response() != null) {
            try {
                String respBody = requestResponse.response().bodyToString();
                responseMatch = respBody != null && (respBody.contains("\"data\"") || respBody.contains("\"errors\""));
            } catch (Exception ignored) {}
        }

        if ((pathMatch || bodyMatch) && responseMatch) {
            String endpointKey = host + path;
            if (!dedup.markIfNew("graphql-tool", host, path)) return Collections.emptyList();
            if (detectedEndpoints.putIfAbsent(endpointKey, Boolean.TRUE) == null) {
                api.logging().logToOutput("[GraphQL] Detected endpoint: " + url);

                // Run introspection and analysis
                try {
                    runIntrospection(request, endpointKey, url);
                } catch (Exception e) {
                    api.logging().logToError("GraphQL introspection error: " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    private void runIntrospection(HttpRequest originalRequest, String endpointKey, String url) throws InterruptedException {
        // Build introspection request
        String introspectionBody = new Gson().toJson(Map.of("query", INTROSPECTION_QUERY));

        HttpRequest introspectionReq = HttpRequest.httpRequest(originalRequest.httpService(),
                        "POST " + extractPath(url) + " HTTP/1.1\r\n" +
                                "Host: " + originalRequest.httpService().host() + "\r\n" +
                                "Content-Type: application/json\r\n" +
                                "Content-Length: " + introspectionBody.length() + "\r\n\r\n" +
                                introspectionBody);


        HttpRequestResponse result = api.http().sendRequest(introspectionReq);

        if (result == null || result.response() == null) return;

        String responseBody = result.response().bodyToString();
        if (responseBody == null || responseBody.isBlank()) return;

        try {
            JsonElement root = JsonParser.parseString(responseBody);
            if (!root.isJsonObject()) return;
            JsonObject rootObj = root.getAsJsonObject();

            if (rootObj.has("data") && rootObj.getAsJsonObject("data").has("__schema")) {
                JsonObject schema = rootObj.getAsJsonObject("data").getAsJsonObject("__schema");
                schemas.put(endpointKey, schema);
                rawIntrospectionJson = responseBody;

                // Report introspection enabled
                findingsStore.addFinding(Finding.builder("graphql-tool",
                                "GraphQL Introspection Enabled",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Full schema retrieved via introspection query")
                        .description("GraphQL introspection is enabled. This exposes the entire API schema "
                                + "including types, fields, and mutations. Should be disabled in production.")
                        .requestResponse(result)
                        .build());

                // Analyze schema
                analyzeSchema(schema, url);

                // Generate queries
                generateSampleQueries(schema, endpointKey);

                // Run security tests if enabled
                if (config.getBool("graphql.securityTests.enabled", true)) {
                    runSecurityTests(originalRequest, url, schema);
                }

            } else if (rootObj.has("errors")) {
                api.logging().logToOutput("[GraphQL] Introspection disabled or error: " + responseBody.substring(0, Math.min(200, responseBody.length())));
            }
        } catch (JsonSyntaxException e) {
            api.logging().logToError("GraphQL introspection response not valid JSON: " + e.getMessage());
        }
    }

    private void analyzeSchema(JsonObject schema, String url) {
        if (!schema.has("types")) return;
        JsonArray types = schema.getAsJsonArray("types");

        for (JsonElement typeEl : types) {
            JsonObject type = typeEl.getAsJsonObject();
            String typeName = type.has("name") ? type.get("name").getAsString() : "";
            if (typeName.startsWith("__")) continue; // Skip introspection types

            if (!type.has("fields") || type.get("fields").isJsonNull()) continue;
            JsonArray fields = type.getAsJsonArray("fields");

            for (JsonElement fieldEl : fields) {
                JsonObject field = fieldEl.getAsJsonObject();
                String fieldName = field.has("name") ? field.get("name").getAsString() : "";
                String fullPath = typeName + "." + fieldName;

                // Check for sensitive auth fields
                if (SENSITIVE_AUTH.matcher(fieldName).find()) {
                    findingsStore.addFinding(Finding.builder("graphql-tool",
                                    "Sensitive field exposed: " + fullPath,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("Field: " + fullPath)
                            .description("Authentication/secret-related field '" + fieldName
                                    + "' exposed in GraphQL schema on type '" + typeName + "'.")
                            .build());
                }

                // Check for PII fields
                if (SENSITIVE_PII.matcher(fieldName).find()) {
                    findingsStore.addFinding(Finding.builder("graphql-tool",
                                    "PII field exposed: " + fullPath,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("Field: " + fullPath)
                            .description("PII field '" + fieldName + "' exposed in GraphQL schema.")
                            .build());
                }
            }
        }

        // Check mutations
        if (schema.has("mutationType") && !schema.get("mutationType").isJsonNull()) {
            String mutationTypeName = schema.getAsJsonObject("mutationType").get("name").getAsString();
            for (JsonElement typeEl : types) {
                JsonObject type = typeEl.getAsJsonObject();
                if (mutationTypeName.equals(type.get("name").getAsString()) && type.has("fields") && !type.get("fields").isJsonNull()) {
                    for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                        String mutName = fieldEl.getAsJsonObject().get("name").getAsString();
                        if (DANGEROUS_MUTATION.matcher(mutName).find()) {
                            findingsStore.addFinding(Finding.builder("graphql-tool",
                                            "Dangerous mutation: " + mutName,
                                            Severity.MEDIUM, Confidence.TENTATIVE)
                                    .url(url)
                                    .evidence("Mutation: " + mutName)
                                    .description("Potentially dangerous mutation '" + mutName + "' available. Verify authorization controls.")
                                    .build());
                        }
                    }
                }
            }
        }
    }

    private void generateSampleQueries(JsonObject schema, String endpointKey) {
        List<String> queries = new ArrayList<>();

        if (schema.has("queryType") && !schema.get("queryType").isJsonNull()) {
            String queryTypeName = schema.getAsJsonObject("queryType").get("name").getAsString();
            JsonArray types = schema.getAsJsonArray("types");

            for (JsonElement typeEl : types) {
                JsonObject type = typeEl.getAsJsonObject();
                if (!queryTypeName.equals(type.get("name").getAsString())) continue;
                if (!type.has("fields") || type.get("fields").isJsonNull()) continue;

                for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                    JsonObject field = fieldEl.getAsJsonObject();
                    String fieldName = field.get("name").getAsString();

                    StringBuilder query = new StringBuilder("query {\n  " + fieldName);

                    // Add arguments
                    if (field.has("args") && !field.get("args").isJsonNull()) {
                        JsonArray args = field.getAsJsonArray("args");
                        if (args.size() > 0) {
                            query.append("(");
                            List<String> argParts = new ArrayList<>();
                            for (JsonElement argEl : args) {
                                JsonObject arg = argEl.getAsJsonObject();
                                String argName = arg.get("name").getAsString();
                                String placeholder = getPlaceholder(arg.getAsJsonObject("type"));
                                argParts.add(argName + ": " + placeholder);
                            }
                            query.append(String.join(", ", argParts));
                            query.append(")");
                        }
                    }

                    // Add selection set based on return type
                    String returnTypeFields = getFieldSelection(field.getAsJsonObject("type"), schema, 0);
                    if (!returnTypeFields.isEmpty()) {
                        query.append(" {\n").append(returnTypeFields).append("  }");
                    }

                    query.append("\n}");
                    queries.add(query.toString());
                }
            }
        }

        generatedQueries.put(endpointKey, queries);
    }

    private String getPlaceholder(JsonObject typeObj) {
        if (typeObj == null) return "\"test\"";
        String kind = typeObj.has("kind") ? typeObj.get("kind").getAsString() : "";
        String name = typeObj.has("name") && !typeObj.get("name").isJsonNull() ? typeObj.get("name").getAsString() : "";

        if ("NON_NULL".equals(kind) && typeObj.has("ofType")) {
            return getPlaceholder(typeObj.getAsJsonObject("ofType"));
        }
        if ("LIST".equals(kind) && typeObj.has("ofType")) {
            return "[" + getPlaceholder(typeObj.getAsJsonObject("ofType")) + "]";
        }

        switch (name) {
            case "String": return "\"test\"";
            case "Int": return "1";
            case "Float": return "1.0";
            case "Boolean": return "true";
            case "ID": return "\"1\"";
            default: return "\"test\"";
        }
    }

    private String getFieldSelection(JsonObject typeObj, JsonObject schema, int depth) {
        if (depth > 1 || typeObj == null) return "";

        String kind = typeObj.has("kind") ? typeObj.get("kind").getAsString() : "";
        String name = typeObj.has("name") && !typeObj.get("name").isJsonNull() ? typeObj.get("name").getAsString() : "";

        if ("NON_NULL".equals(kind) || "LIST".equals(kind)) {
            if (typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
                return getFieldSelection(typeObj.getAsJsonObject("ofType"), schema, depth);
            }
        }

        if ("SCALAR".equals(kind) || "ENUM".equals(kind)) return "";

        // Find this type in the schema
        if (!schema.has("types")) return "";
        for (JsonElement typeEl : schema.getAsJsonArray("types")) {
            JsonObject type = typeEl.getAsJsonObject();
            if (name.equals(type.get("name").getAsString())) {
                if (!type.has("fields") || type.get("fields").isJsonNull()) return "";
                StringBuilder sb = new StringBuilder();
                for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                    JsonObject field = fieldEl.getAsJsonObject();
                    String fieldName = field.get("name").getAsString();
                    JsonObject fieldType = field.getAsJsonObject("type");

                    String innerKind = resolveKind(fieldType);
                    if ("SCALAR".equals(innerKind) || "ENUM".equals(innerKind)) {
                        sb.append("    ".repeat(depth + 2)).append(fieldName).append("\n");
                    } else if (depth < 1) {
                        String nested = getFieldSelection(fieldType, schema, depth + 1);
                        if (!nested.isEmpty()) {
                            sb.append("    ".repeat(depth + 2)).append(fieldName).append(" {\n");
                            sb.append(nested);
                            sb.append("    ".repeat(depth + 2)).append("}\n");
                        }
                    }
                }
                return sb.toString();
            }
        }
        return "";
    }

    private String resolveKind(JsonObject typeObj) {
        if (typeObj == null) return "";
        String kind = typeObj.has("kind") ? typeObj.get("kind").getAsString() : "";
        if ("NON_NULL".equals(kind) || "LIST".equals(kind)) {
            if (typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
                return resolveKind(typeObj.getAsJsonObject("ofType"));
            }
        }
        return kind;
    }

    // ==================== SECURITY TESTS ====================

    private void runSecurityTests(HttpRequest originalRequest, String url, JsonObject schema) throws InterruptedException {
        String path = extractPath(url);

        // Batch query abuse
        testBatchQuery(originalRequest, path, url);

        // Deep nesting test
        testDeepNesting(originalRequest, path, url, schema);

        // Field suggestion enumeration
        testFieldSuggestion(originalRequest, path, url);

        // Alias-based resource exhaustion
        testAliasDos(originalRequest, path, url);
    }

    private void testBatchQuery(HttpRequest originalRequest, String path, String url) throws InterruptedException {


        // Send 10 batched queries
        JsonArray batch = new JsonArray();
        for (int i = 0; i < 10; i++) {
            JsonObject q = new JsonObject();
            q.addProperty("query", "{ __typename }");
            batch.add(q);
        }
        String body = new Gson().toJson(batch);

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n" +
                        "Host: " + originalRequest.httpService().host() + "\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: " + body.length() + "\r\n\r\n" + body);

        HttpRequestResponse result = api.http().sendRequest(req);
        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody.contains("__typename")) {
                findingsStore.addFinding(Finding.builder("graphql-tool",
                                "GraphQL batch queries not limited",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("10 batched queries all succeeded")
                        .description("Server accepts batched queries without limits. Could be used for brute-force or DoS.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testDeepNesting(HttpRequest originalRequest, String path, String url, JsonObject schema) throws InterruptedException {
        // Find a type with a self-referencing field for deep nesting
        // Use a generic deep nesting test with __typename


        String deepQuery = "{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }";
        String body = new Gson().toJson(Map.of("query", deepQuery));

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n" +
                        "Host: " + originalRequest.httpService().host() + "\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: " + body.length() + "\r\n\r\n" + body);

        HttpRequestResponse result = api.http().sendRequest(req);
        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder("graphql-tool",
                            "GraphQL no query depth limiting",
                            Severity.LOW, Confidence.FIRM)
                    .url(url)
                    .evidence("Deeply nested query processed successfully")
                    .description("Server processes deeply nested queries without depth limiting. Risk of DoS via recursive queries.")
                    .requestResponse(result)
                    .build());
        }
    }

    private void testFieldSuggestion(HttpRequest originalRequest, String path, String url) throws InterruptedException {


        String query = "{ __typenameXXXX }";
        String body = new Gson().toJson(Map.of("query", query));

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n" +
                        "Host: " + originalRequest.httpService().host() + "\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: " + body.length() + "\r\n\r\n" + body);

        HttpRequestResponse result = api.http().sendRequest(req);
        if (result != null && result.response() != null) {
            String respBody = result.response().bodyToString();
            if (respBody.contains("Did you mean") || respBody.contains("did you mean")) {
                findingsStore.addFinding(Finding.builder("graphql-tool",
                                "GraphQL field suggestion enabled",
                                Severity.INFO, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Server returned 'Did you mean' suggestions for misspelled field")
                        .description("Field suggestions are enabled. Can be used to enumerate valid fields without introspection.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testAliasDos(HttpRequest originalRequest, String path, String url) throws InterruptedException {


        StringBuilder sb = new StringBuilder("{ ");
        for (int i = 0; i < 50; i++) {
            sb.append("a").append(i).append(": __typename ");
        }
        sb.append("}");

        String body = new Gson().toJson(Map.of("query", sb.toString()));

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n" +
                        "Host: " + originalRequest.httpService().host() + "\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: " + body.length() + "\r\n\r\n" + body);

        HttpRequestResponse result = api.http().sendRequest(req);
        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody.contains("a49")) { // Check if last alias was processed
                findingsStore.addFinding(Finding.builder("graphql-tool",
                                "GraphQL alias-based resource exhaustion possible",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("50 aliases for __typename all processed successfully")
                        .description("Server does not limit the number of aliases per query. Could be used for DoS with expensive fields.")
                        .requestResponse(result)
                        .build());
            }
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

    @Override
    public void destroy() {
        detectedEndpoints.clear();
        schemas.clear();
        generatedQueries.clear();
    }

    // Accessors for UI
    public ConcurrentHashMap<String, Boolean> getDetectedEndpoints() { return detectedEndpoints; }
    public ConcurrentHashMap<String, JsonObject> getSchemas() { return schemas; }
    public ConcurrentHashMap<String, List<String>> getGeneratedQueries() { return generatedQueries; }
    public String getRawIntrospectionJson() { return rawIntrospectionJson; }
}
