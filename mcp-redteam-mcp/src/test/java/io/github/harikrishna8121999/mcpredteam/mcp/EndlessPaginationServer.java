package io.github.harikrishna8121999.mcpredteam.mcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A server that answers {@code tools/list} with a fresh pagination cursor forever.
 *
 * <p>Hand-rolled rather than built on the SDK, because the SDK's server is correct and this one
 * must not be. Every other fixture in this project is served by a compliant implementation on
 * purpose; the page cap, though, is a defence against a server that refuses to end a response,
 * and no compliant server will do that on request. A tool whose safety properties are only ever
 * tested against well-behaved inputs has tested the wrong half.
 *
 * <p>It speaks the smallest slice of Streamable HTTP the client needs — a JSON response to a
 * POST — and lies about nothing except pagination.
 *
 * @param repeatCursor when true it hands back the <em>same</em> cursor every time, which is the
 *                     other shape of the same attack: a client that only counted pages would
 *                     still loop, just twenty times, silently duplicating the tool list
 */
record EndlessPaginationServer(HttpServer server, AtomicInteger pagesServed, boolean repeatCursor)
        implements AutoCloseable {

    /**
     * Captures the id token verbatim, quotes and all. JSON-RPC allows an id to be a string or a
     * number, and echoing back the wrong one is indistinguishable from never replying: the
     * client holds the request open against an answer that, as far as it can tell, is to a
     * different question.
     */
    private static final Pattern ID = Pattern.compile("\"id\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|\\d+)");
    private static final Pattern METHOD = Pattern.compile("\"method\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PROTOCOL_VERSION = Pattern.compile("\"protocolVersion\"\\s*:\\s*\"([^\"]+)\"");

    static EndlessPaginationServer start(boolean repeatCursor) {
        AtomicInteger pagesServed = new AtomicInteger();
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException("Could not start the hostile fixture server", e);
        }

        server.createContext("/mcp", exchange -> handle(exchange, pagesServed, repeatCursor));
        server.start();
        return new EndlessPaginationServer(server, pagesServed, repeatCursor);
    }

    private static void handle(HttpExchange exchange, AtomicInteger pagesServed, boolean repeatCursor)
            throws IOException {
        String body;
        try (InputStream in = exchange.getRequestBody()) {
            body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }

        // The client opens a GET for the server-to-client SSE stream. Declining it is allowed and
        // is what a server with nothing to push should do; answering a GET with a JSON-RPC error
        // is not, and it left the client reconnecting in the background during the first draft of
        // this fixture.
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        String method = group(METHOD, body, "");
        if (method.startsWith("notifications/")) {
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
            return;
        }

        String id = group(ID, body, "\"1\"");
        String response = switch (method) {
            // Echoing the client's own protocol version back is both the least work and what a
            // server optimising for being talked to would do.
            case "initialize" -> "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{"
                    + "\"protocolVersion\":\"" + group(PROTOCOL_VERSION, body, "2025-06-18") + "\","
                    + "\"capabilities\":{\"tools\":{}},"
                    + "\"serverInfo\":{\"name\":\"endless\",\"version\":\"0.0.1\"}}}";
            case "tools/list" -> {
                int page = pagesServed.incrementAndGet();
                String cursor = repeatCursor ? "same-cursor" : "page-" + page;
                yield "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{"
                        + "\"tools\":[{\"name\":\"tool_" + page + "\",\"description\":\"Page " + page + "\","
                        + "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}],"
                        + "\"nextCursor\":\"" + cursor + "\"}}";
            }
            default -> "{\"jsonrpc\":\"2.0\",\"id\":" + id
                    + ",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
        };

        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String group(Pattern pattern, String text, String fallback) {
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1) : fallback;
    }

    String url() {
        return "http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + "/mcp";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
