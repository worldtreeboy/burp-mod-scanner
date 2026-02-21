package com.omnistrike.model;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-module configuration holder. Modules read their settings from here.
 * The UI writes config values; modules read them.
 */
public class ModuleConfig {

    private final Map<String, String> stringProps = new ConcurrentHashMap<>();
    private final Map<String, Integer> intProps = new ConcurrentHashMap<>();
    private final Map<String, Boolean> boolProps = new ConcurrentHashMap<>();

    public void setString(String key, String value) {
        stringProps.put(key, value);
    }

    public String getString(String key, String defaultValue) {
        return stringProps.getOrDefault(key, defaultValue);
    }

    public void setInt(String key, int value) {
        intProps.put(key, value);
    }

    public int getInt(String key, int defaultValue) {
        return intProps.getOrDefault(key, defaultValue);
    }

    public void setBool(String key, boolean value) {
        boolProps.put(key, value);
    }

    public boolean getBool(String key, boolean defaultValue) {
        return boolProps.getOrDefault(key, defaultValue);
    }

    /** Returns an unmodifiable view of all boolean property keys. */
    public Set<String> getBoolKeys() {
        return Collections.unmodifiableSet(boolProps.keySet());
    }

    /** Returns an unmodifiable view of all integer property keys. */
    public Set<String> getIntKeys() {
        return Collections.unmodifiableSet(intProps.keySet());
    }

    /** Returns an unmodifiable view of all string property keys. */
    public Set<String> getStringKeys() {
        return Collections.unmodifiableSet(stringProps.keySet());
    }

    /** Returns an unmodifiable view of the boolean properties map. */
    public Map<String, Boolean> getBoolProps() {
        return Collections.unmodifiableMap(boolProps);
    }

    /** Returns an unmodifiable view of the integer properties map. */
    public Map<String, Integer> getIntProps() {
        return Collections.unmodifiableMap(intProps);
    }

    /** Returns an unmodifiable view of the string properties map. */
    public Map<String, String> getStringProps() {
        return Collections.unmodifiableMap(stringProps);
    }
}
