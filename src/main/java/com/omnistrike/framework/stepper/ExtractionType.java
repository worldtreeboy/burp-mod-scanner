package com.omnistrike.framework.stepper;

/**
 * Types of value extraction from HTTP responses.
 */
public enum ExtractionType {
    /** Extract via regex capture group 1 from the response body. */
    BODY_REGEX,
    /** Extract the value of a named response header. */
    HEADER,
    /** Extract the value of a named cookie from Set-Cookie headers. */
    COOKIE,
    /** Extract via simple dot-notation JSON path from the response body. */
    JSON_PATH
}
