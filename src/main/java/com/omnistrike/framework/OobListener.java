package com.omnistrike.framework;

import burp.api.montoya.collaborator.InteractionType;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;

/**
 * Embedded HTTP + DNS server that catches OOB callbacks from target applications.
 * Runs inside the Burp extension — no external server required.
 *
 * <ul>
 *   <li><b>HTTP</b>: Any request to {@code http://<ip>:<httpPort>/<payloadId>/...} is matched.</li>
 *   <li><b>DNS</b>: Any DNS query for {@code <payloadId>.<anything>} on the configured UDP port is matched.
 *       The first label of the queried domain is the payload ID. Responds with an A record pointing
 *       to the listener's own IP address.</li>
 * </ul>
 */
public class OobListener {

    private HttpServer httpServer;
    private DatagramSocket dnsSocket;
    private Thread dnsThread;
    private final String bindAddress;
    private final int httpPort;
    private volatile int dnsPort;
    private volatile boolean httpRunning = false;
    private volatile boolean dnsRunning = false;

    /**
     * Callback invoked for every incoming request: (payloadId, CustomOobInteraction).
     * Wired by CollaboratorManager to match against pending payloads.
     */
    private BiConsumer<String, CustomOobInteraction> interactionHandler;

    public OobListener(String bindAddress, int httpPort) {
        this.bindAddress = bindAddress;
        this.httpPort = httpPort;
        this.dnsPort = 53; // Default DNS port
    }

    public OobListener(String bindAddress, int httpPort, int dnsPort) {
        this.bindAddress = bindAddress;
        this.httpPort = httpPort;
        this.dnsPort = dnsPort;
    }

    public void setInteractionHandler(BiConsumer<String, CustomOobInteraction> handler) {
        this.interactionHandler = handler;
    }

    // ==================== HTTP LISTENER ====================

    /**
     * Starts the HTTP listener. All paths are handled — the first path segment is the payload ID.
     */
    public void startHttp() throws IOException {
        httpServer = HttpServer.create(new InetSocketAddress(bindAddress, httpPort), 0);
        httpServer.createContext("/", this::handleRequest);
        httpServer.setExecutor(Executors.newFixedThreadPool(4));
        httpServer.start();
        httpRunning = true;
    }

    /** Legacy start() — starts HTTP only for backward compatibility. */
    public void start() throws IOException {
        startHttp();
    }

    public void stopHttp() {
        httpRunning = false;
        if (httpServer != null) {
            httpServer.stop(1);
            httpServer = null;
        }
    }

    // ==================== DNS LISTENER ====================

    /**
     * Starts the DNS listener on a UDP DatagramSocket.
     * Parses incoming DNS queries (RFC 1035), extracts the first label of the queried domain
     * as the payload ID, responds with an A record pointing to {@link #bindAddress},
     * and fires the interaction callback.
     */
    public void startDns() throws IOException {
        InetAddress addr = InetAddress.getByName(bindAddress);
        dnsSocket = new DatagramSocket(dnsPort, addr);

        dnsThread = new Thread(() -> {
            byte[] buf = new byte[512]; // Standard DNS UDP max size
            while (dnsRunning) {
                try {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    dnsSocket.receive(packet);
                    handleDnsQuery(packet);
                } catch (IOException e) {
                    if (dnsRunning) {
                        // Real error, not just socket closed
                    }
                }
            }
        }, "OmniStrike-DNS-Listener");
        dnsThread.setDaemon(true);
        dnsRunning = true;
        dnsThread.start();
    }

    public void stopDns() {
        dnsRunning = false;
        if (dnsSocket != null) {
            dnsSocket.close();
            dnsSocket = null;
        }
        if (dnsThread != null) {
            dnsThread.interrupt();
            dnsThread = null;
        }
    }

    // ==================== COMBINED START/STOP ====================

    /** Starts both HTTP and DNS listeners. */
    public void startAll() throws IOException {
        startHttp();
        startDns();
    }

    public void stop() {
        stopHttp();
        stopDns();
    }

    public boolean isRunning() {
        return httpRunning || dnsRunning;
    }

    public boolean isHttpRunning() {
        return httpRunning;
    }

    public boolean isDnsRunning() {
        return dnsRunning;
    }

    public int getPort() {
        return httpPort;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public int getDnsPort() {
        return dnsPort;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    private void handleRequest(HttpExchange exchange) {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            InetSocketAddress remoteAddr = exchange.getRemoteAddress();

            // Extract payload ID from the first path segment: /abc123/cmdi → abc123
            String payloadId = extractPayloadId(path);

            // Build raw request string for evidence
            String rawRequest = method + " " + exchange.getRequestURI() + " HTTP/1.1\n"
                    + "Host: " + exchange.getRequestHeaders().getFirst("Host") + "\n"
                    + "From: " + remoteAddr.getAddress().getHostAddress() + ":" + remoteAddr.getPort();

            // Dispatch to CollaboratorManager
            if (payloadId != null && !payloadId.isEmpty() && interactionHandler != null) {
                CustomOobInteraction interaction = new CustomOobInteraction(
                        payloadId,
                        remoteAddr.getAddress(),
                        remoteAddr.getPort(),
                        rawRequest
                );
                interactionHandler.accept(payloadId, interaction);
            }

            // Always return 200 OK — we want the target to think the request succeeded
            byte[] body = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        } catch (Exception e) {
            try {
                exchange.sendResponseHeaders(500, 0);
                exchange.close();
            } catch (IOException ignored) {}
        }
    }

    /**
     * Extracts the payload ID from the first URL path segment.
     * {@code /abc123def/cmdi} → {@code abc123def}
     * {@code /abc123def} → {@code abc123def}
     * {@code /} → {@code null}
     */
    private String extractPayloadId(String path) {
        if (path == null || path.length() <= 1) return null;
        // Remove leading slash
        String trimmed = path.substring(1);
        int slashIdx = trimmed.indexOf('/');
        return slashIdx > 0 ? trimmed.substring(0, slashIdx) : trimmed;
    }

    /**
     * Lists all UP, non-loopback IPv4 network interfaces for the UI dropdown.
     * Returns a list of "interfaceName - ipAddress" strings.
     */
    public static List<String[]> getNetworkInterfaces() {
        List<String[]> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        result.add(new String[]{
                                ni.getDisplayName(),
                                addr.getHostAddress()
                        });
                    }
                }
            }
        } catch (SocketException e) {
            // Fallback: at least offer localhost
        }
        // Always offer loopback as last option
        result.add(new String[]{"loopback", "127.0.0.1"});
        return result;
    }

    /**
     * Finds a random available TCP port by briefly opening and closing a server socket.
     */
    public static int randomAvailablePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            return 8888 + (int) (Math.random() * 1000);
        }
    }

    /**
     * Finds a random available UDP port by briefly opening and closing a datagram socket.
     */
    public static int randomAvailableUdpPort() {
        try (DatagramSocket socket = new DatagramSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            return 5353 + (int) (Math.random() * 1000);
        }
    }

    // ==================== DNS PACKET HANDLING ====================

    /**
     * Handles an incoming DNS query packet (RFC 1035).
     * Extracts the queried domain name, uses the first label as the payload ID,
     * sends a valid A record response, and fires the interaction callback.
     */
    private void handleDnsQuery(DatagramPacket packet) {
        try {
            byte[] data = packet.getData();
            int len = packet.getLength();
            if (len < 12) return; // Too short for a DNS header

            // Parse DNS header (RFC 1035 Section 4.1.1)
            int txnId = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
            int qdCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);

            // Only handle standard queries (QR=0, OPCODE=0)
            if ((flags & 0x8000) != 0) return; // QR bit set = response, not query
            if (qdCount < 1) return;

            // Parse the question section — extract the queried domain name
            int offset = 12; // Skip header
            String domain = parseDomainName(data, offset, len);
            if (domain == null || domain.isEmpty()) return;

            // Extract payload ID from the first label (before first dot)
            String payloadId = domain.contains(".")
                    ? domain.substring(0, domain.indexOf('.'))
                    : domain;

            // Build raw request string for evidence
            String rawRequest = "DNS Query: " + domain
                    + " from " + packet.getAddress().getHostAddress() + ":" + packet.getPort()
                    + " (txnId=" + txnId + ")";

            // Fire the interaction callback
            if (payloadId != null && !payloadId.isEmpty() && interactionHandler != null) {
                CustomOobInteraction interaction = new CustomOobInteraction(
                        payloadId,
                        packet.getAddress(),
                        packet.getPort(),
                        rawRequest,
                        InteractionType.DNS
                );
                interactionHandler.accept(payloadId, interaction);
            }

            // Build and send DNS response with A record pointing to our IP
            byte[] response = buildDnsResponse(data, len, txnId, domain);
            if (response != null) {
                DatagramPacket responsePacket = new DatagramPacket(
                        response, response.length, packet.getAddress(), packet.getPort());
                dnsSocket.send(responsePacket);
            }
        } catch (Exception e) {
            // Never crash the DNS listener thread
        }
    }

    /**
     * Parses a domain name from the DNS question section (RFC 1035 Section 4.1.2).
     * Format: sequence of (length-byte, label-bytes), terminated by 0x00.
     * Example: 0x07 "example" 0x03 "com" 0x00 → "example.com"
     */
    private String parseDomainName(byte[] data, int offset, int maxLen) {
        StringBuilder domain = new StringBuilder();
        while (offset < maxLen) {
            int labelLen = data[offset] & 0xFF;
            if (labelLen == 0) break; // End of domain name
            if ((labelLen & 0xC0) == 0xC0) break; // Pointer (compression) — stop parsing
            if (offset + 1 + labelLen > maxLen) break; // Bounds check
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, offset + 1, labelLen, StandardCharsets.US_ASCII));
            offset += 1 + labelLen;
        }
        return domain.toString().toLowerCase();
    }

    /**
     * Builds a DNS response packet with an A record pointing to our listener IP.
     * Mirrors the query's transaction ID and question section, sets QR=1 (response),
     * AA=1 (authoritative), and appends a single A record answer.
     */
    private byte[] buildDnsResponse(byte[] queryData, int queryLen, int txnId, String domain) {
        try {
            InetAddress responseIp = InetAddress.getByName(bindAddress);
            if (!(responseIp instanceof Inet4Address)) return null;
            byte[] ipBytes = responseIp.getAddress();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(512);

            // DNS Header (12 bytes)
            baos.write((txnId >> 8) & 0xFF); // Transaction ID high
            baos.write(txnId & 0xFF);        // Transaction ID low
            baos.write(0x85);                 // Flags high: QR=1, AA=1, RD=1
            baos.write(0x00);                 // Flags low: RCODE=0 (no error)
            baos.write(0x00); baos.write(0x01); // QDCOUNT = 1
            baos.write(0x00); baos.write(0x01); // ANCOUNT = 1
            baos.write(0x00); baos.write(0x00); // NSCOUNT = 0
            baos.write(0x00); baos.write(0x00); // ARCOUNT = 0

            // Question section — copy the domain name from the query
            int offset = 12;
            while (offset < queryLen) {
                int labelLen = queryData[offset] & 0xFF;
                if (labelLen == 0) {
                    baos.write(0x00); // Terminator
                    offset++;
                    break;
                }
                baos.write(queryData, offset, 1 + labelLen);
                offset += 1 + labelLen;
            }
            // QTYPE (2 bytes) + QCLASS (2 bytes) — copy from query
            if (offset + 4 <= queryLen) {
                baos.write(queryData, offset, 4);
            } else {
                baos.write(0x00); baos.write(0x01); // A record
                baos.write(0x00); baos.write(0x01); // IN class
            }

            // Answer section — pointer to domain name in question (0xC00C)
            baos.write(0xC0); baos.write(0x0C); // Name pointer to offset 12
            baos.write(0x00); baos.write(0x01); // TYPE = A
            baos.write(0x00); baos.write(0x01); // CLASS = IN
            baos.write(0x00); baos.write(0x00); // TTL high (60 seconds)
            baos.write(0x00); baos.write(0x3C); // TTL low
            baos.write(0x00); baos.write(0x04); // RDLENGTH = 4 (IPv4)
            baos.write(ipBytes);                // RDATA = our IP

            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }
}
