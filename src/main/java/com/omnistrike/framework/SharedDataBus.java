package com.omnistrike.framework;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Inter-module data sharing bus. Modules can publish and consume shared data
 * without directly referencing each other.
 *
 * Common channels:
 *   "discovered-params"  -> Set of parameter names (from param-miner)
 *   "discovered-endpoints" -> Set of URL paths (from endpoint-finder)
 *   "discovered-subdomains" -> Set of subdomains (from subdomain-collector)
 */
public class SharedDataBus {

    private final ConcurrentHashMap<String, Set<String>> stringSets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> objects = new ConcurrentHashMap<>();

    /**
     * Add a value to a named set channel.
     */
    public void addToSet(String channel, String value) {
        stringSets.computeIfAbsent(channel, k -> ConcurrentHashMap.newKeySet()).add(value);
    }

    /**
     * Get all values from a named set channel.
     */
    public Set<String> getSet(String channel) {
        Set<String> set = stringSets.get(channel);
        return set != null ? Collections.unmodifiableSet(set) : Collections.emptySet();
    }

    /**
     * Store an arbitrary object.
     */
    public void putObject(String key, Object value) {
        objects.put(key, value);
    }

    /**
     * Retrieve an arbitrary object.
     */
    @SuppressWarnings("unchecked")
    public <T> T getObject(String key, Class<T> clazz) {
        Object obj = objects.get(key);
        if (obj != null && clazz.isInstance(obj)) {
            return (T) obj;
        }
        return null;
    }

    public void clear() {
        stringSets.clear();
        objects.clear();
    }
}
