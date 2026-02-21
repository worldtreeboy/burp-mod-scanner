package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Manages Burp Collaborator client lifecycle, payload generation, and interaction polling.
 * Shared by all modules that need OOB testing (SQLi OOB, SSRF, SSTI).
 * Requires Burp Suite Professional.
 */
public class CollaboratorManager {

    private final MontoyaApi api;
    private CollaboratorClient client;
    private ScheduledExecutorService poller;
    private volatile boolean available = false;
    private volatile int payloadTtlMinutes = 10;

    // Map payload ID -> callback to invoke when interaction is received
    private final ConcurrentHashMap<String, PendingPayload> pendingPayloads = new ConcurrentHashMap<>();

    public static class PendingPayload {
        public final String moduleId;
        public final String url;
        public final String parameter;
        public final String payloadDescription;
        public final Consumer<Interaction> callback;
        public final long createdAt;

        public PendingPayload(String moduleId, String url, String parameter,
                              String payloadDescription, Consumer<Interaction> callback) {
            this.moduleId = moduleId;
            this.url = url;
            this.parameter = parameter;
            this.payloadDescription = payloadDescription;
            this.callback = callback;
            this.createdAt = System.currentTimeMillis();
        }
    }

    public CollaboratorManager(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Initialize the Collaborator client. Must be called during extension init.
     * Returns false if Collaborator is not available (Community edition).
     */
    public boolean initialize() {
        try {
            // Try to restore from persistence first
            String savedKey = api.persistence().extensionData().getString("omnistrike_collab_key");
            if (savedKey != null) {
                client = api.collaborator().restoreClient(SecretKey.secretKey(savedKey));
                api.logging().logToOutput("Restored Collaborator client from saved key.");
            } else {
                client = api.collaborator().createClient();
                api.persistence().extensionData().setString(
                        "omnistrike_collab_key", client.getSecretKey().toString());
                api.logging().logToOutput("Created new Collaborator client.");
            }
            available = true;

            // Start polling for interactions every 5 seconds
            startPolling(5);

            return true;
        } catch (Exception e) {
            api.logging().logToError("Collaborator not available (Community edition?): " + e.getMessage());
            available = false;
            return false;
        }
    }

    /**
     * Generate a Collaborator payload and register a callback for when it receives an interaction.
     *
     * @param moduleId          Which module generated this payload
     * @param url               The target URL being tested
     * @param parameter         The parameter being injected into
     * @param payloadDescription Description of the payload type (e.g., "OOB SQLi DNS exfil")
     * @param callback          Called when an interaction is received for this payload
     * @return The full Collaborator payload string (e.g., "abc123.oastify.com"), or null if unavailable
     */
    public String generatePayload(String moduleId, String url, String parameter,
                                   String payloadDescription, Consumer<Interaction> callback) {
        if (!available || client == null) return null;
        try {
            CollaboratorPayload payload = client.generatePayload();
            String payloadStr = payload.toString();
            String payloadId = payload.id().toString();

            pendingPayloads.put(payloadId, new PendingPayload(
                    moduleId, url, parameter, payloadDescription, callback));

            return payloadStr;
        } catch (Exception e) {
            api.logging().logToError("Failed to generate Collaborator payload: " + e.getMessage());
            return null;
        }
    }

    /**
     * Generate a payload without server location (just the subdomain part).
     */
    public String generatePayloadShort(String moduleId, String url, String parameter,
                                        String payloadDescription, Consumer<Interaction> callback) {
        if (!available || client == null) return null;
        try {
            CollaboratorPayload payload = client.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION);
            String payloadStr = payload.toString();
            String payloadId = payload.id().toString();

            pendingPayloads.put(payloadId, new PendingPayload(
                    moduleId, url, parameter, payloadDescription, callback));

            return payloadStr;
        } catch (Exception e) {
            api.logging().logToError("Failed to generate short Collaborator payload: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the Collaborator server address (e.g., "oastify.com").
     */
    public String getServerAddress() {
        if (!available || client == null) return null;
        try {
            return client.server().address();
        } catch (Exception e) {
            return null;
        }
    }

    public boolean isAvailable() {
        return available;
    }

    private void startPolling(int intervalSeconds) {
        poller = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "OmniStrike-CollabPoller");
            t.setDaemon(true);
            return t;
        });

        poller.scheduleAtFixedRate(() -> {
            try {
                if (client == null) return;

                List<Interaction> interactions = client.getAllInteractions();
                for (Interaction interaction : interactions) {
                    // Match interaction to a pending payload using the interaction ID.
                    // Burp's interaction.id() is a PayloadId that can be compared to
                    // the payload.id() we stored via exact string match.
                    String interactionId = interaction.id().toString();
                    PendingPayload matched = null;
                    String matchedKey = null;

                    // Try exact match first (most reliable)
                    matched = pendingPayloads.get(interactionId);
                    if (matched != null) {
                        matchedKey = interactionId;
                    } else {
                        // Fallback: interaction ID may be a prefix/suffix of our stored key
                        // (Burp may append subdomain info). Use contains as fallback.
                        for (Map.Entry<String, PendingPayload> entry : pendingPayloads.entrySet()) {
                            if (interactionId.contains(entry.getKey())
                                    || entry.getKey().contains(interactionId)) {
                                matched = entry.getValue();
                                matchedKey = entry.getKey();
                                break;
                            }
                        }
                    }

                    if (matched != null) {
                        pendingPayloads.remove(matchedKey);
                        try {
                            matched.callback.accept(interaction);
                        } catch (Exception e) {
                            api.logging().logToError("Collaborator callback error: " + e.getMessage());
                        }
                    } else {
                        api.logging().logToOutput("Collaborator interaction received (no matching payload): "
                                + interaction.type() + " from " + interaction.clientIp());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Collaborator polling error: " + e.getMessage());
            }
        }, 0, intervalSeconds, TimeUnit.SECONDS);

        // Separate scheduled task for cleaning up stale payloads (runs every 60 seconds)
        poller.scheduleAtFixedRate(() -> {
            try {
                long cutoff = System.currentTimeMillis() - (payloadTtlMinutes * 60L * 1000L);
                int before = pendingPayloads.size();
                pendingPayloads.entrySet().removeIf(e -> e.getValue().createdAt < cutoff);
                int removed = before - pendingPayloads.size();
                if (removed > 0) {
                    api.logging().logToOutput("Collaborator cleanup: removed " + removed
                            + " stale payload(s), " + pendingPayloads.size() + " remaining");
                }
            } catch (Exception e) {
                api.logging().logToError("Collaborator cleanup error: " + e.getMessage());
            }
        }, 60, 60, TimeUnit.SECONDS);
    }

    public void shutdown() {
        if (poller != null) {
            poller.shutdown();
            try {
                poller.awaitTermination(3, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                poller.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        pendingPayloads.clear();
    }

    public int getPendingCount() {
        return pendingPayloads.size();
    }

    public void setPayloadTtlMinutes(int minutes) {
        this.payloadTtlMinutes = Math.max(1, minutes);
    }

    public int getPayloadTtlMinutes() {
        return payloadTtlMinutes;
    }
}
