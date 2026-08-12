package io.github.mcpredteam.mcp;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Where an MCP server is, and how to reach it.
 *
 * <p>A value, not a connection: describing a target opens nothing and validates nothing about
 * the server. That separation is deliberate — a test can name the server it means in a field
 * initialiser, and the connection attempt (the part that can hang, fail or be attacked) happens
 * where the test can see it.
 *
 * <pre>{@code
 * McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp")
 * McpServerTarget.stdio("npx", "-y", "@vendor/mcp-server")
 * }</pre>
 */
public sealed interface McpServerTarget {

    /** A short description for messages and findings; never trusted, never from the server. */
    String describe();

    /**
     * A server launched as a child process, speaking JSON-RPC over its stdin and stdout.
     *
     * <p>This is how locally installed MCP servers ship, and it is worth being clear about what
     * running one costs: launching a target is executing an arbitrary program on the machine
     * running the tests, with its privileges. Scanning a stdio server's metadata for hostile
     * content is a strictly weaker safeguard than not running it, because the process starts
     * before {@code tools/list} can answer. Prefer {@link StreamableHttp} for anything genuinely
     * untrusted; a hostile HTTP server can lie to you, but it cannot read your filesystem.
     */
    record Stdio(String command, List<String> args, Map<String, String> env) implements McpServerTarget {

        public Stdio {
            Objects.requireNonNull(command, "command");
            if (command.isBlank()) {
                throw new IllegalArgumentException("A stdio target needs a command to launch");
            }
            args = args == null ? List.of() : List.copyOf(args);
            env = env == null ? Map.of() : Map.copyOf(env);
        }

        /** The same command with additional environment variables for the child process. */
        public Stdio withEnv(String key, String value) {
            Map<String, String> merged = new LinkedHashMap<>(env);
            merged.put(key, value);
            return new Stdio(command, args, merged);
        }

        @Override
        public String describe() {
            return args.isEmpty() ? command : command + " " + String.join(" ", args);
        }
    }

    /**
     * A remote server speaking Streamable HTTP, the transport the MCP spec defines for anything
     * that is not a local subprocess.
     *
     * @param baseUri  scheme, host and port — no path
     * @param endpoint the request path, conventionally {@code /mcp}
     * @param headers  extra request headers, typically {@code Authorization}. Note that these are
     *                 credentials being handed to a server whose trustworthiness is exactly what
     *                 is under test; send a scoped token, not a production one.
     */
    record StreamableHttp(String baseUri, String endpoint, Map<String, String> headers) implements McpServerTarget {

        public StreamableHttp {
            Objects.requireNonNull(baseUri, "baseUri");
            Objects.requireNonNull(endpoint, "endpoint");
            headers = headers == null ? Map.of() : Map.copyOf(headers);
        }

        /** The same target with an additional request header. */
        public StreamableHttp withHeader(String name, String value) {
            Map<String, String> merged = new LinkedHashMap<>(headers);
            merged.put(name, value);
            return new StreamableHttp(baseUri, endpoint, merged);
        }

        @Override
        public String describe() {
            return baseUri + endpoint;
        }
    }

    /** A server launched as a subprocess. */
    static Stdio stdio(String command, String... args) {
        return new Stdio(command, List.of(args), Map.of());
    }

    /**
     * A remote server, from one whole URL.
     *
     * <p>The SDK wants the origin and the path separately, which is a detail no caller should
     * have to know: they have a URL. A URL with no path gets {@code /mcp}, the conventional
     * endpoint — stated here rather than left implicit, because silently scanning a different
     * path than the one you passed is the kind of surprise that ends with someone reporting a
     * clean result for a server they never reached.
     */
    static StreamableHttp streamableHttp(String url) {
        URI uri;
        try {
            uri = new URI(Objects.requireNonNull(url, "url"));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Not a valid MCP server URL: " + url, e);
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException(
                    "An MCP server URL needs a scheme and a host, e.g. https://host/mcp — got: " + url);
        }

        StringBuilder base = new StringBuilder(uri.getScheme()).append("://").append(uri.getHost());
        if (uri.getPort() != -1) {
            base.append(':').append(uri.getPort());
        }

        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() || uri.getRawPath().equals("/")
                ? "/mcp"
                : uri.getRawPath();
        if (uri.getRawQuery() != null) {
            path = path + "?" + uri.getRawQuery();
        }

        return new StreamableHttp(base.toString(), path, Map.of());
    }
}
