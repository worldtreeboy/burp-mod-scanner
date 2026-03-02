package com.omnistrike.framework.stepper;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Thread-safe store of named variables extracted during Stepper chain execution.
 * Variables are referenced in request templates as {{variableName}}.
 */
public class StepperVariableStore {

    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{([^}]+)\\}\\}");

    private final ConcurrentHashMap<String, String> variables = new ConcurrentHashMap<>();

    public void set(String name, String value) {
        if (name != null && value != null) {
            variables.put(name, value);
        }
    }

    public String get(String name) {
        return variables.get(name);
    }

    public void clear() {
        variables.clear();
    }

    public Map<String, String> getAll() {
        return Collections.unmodifiableMap(variables);
    }

    /**
     * Replaces all {{variableName}} placeholders in the input with their stored values.
     * Unknown variables are left as-is.
     */
    public String substitute(String input) {
        if (input == null || input.isEmpty()) return input;
        Matcher m = VARIABLE_PATTERN.matcher(input);
        if (!m.find()) return input;

        StringBuilder sb = new StringBuilder();
        m.reset();
        while (m.find()) {
            String varName = m.group(1);
            String value = variables.get(varName);
            m.appendReplacement(sb, Matcher.quoteReplacement(value != null ? value : m.group(0)));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
