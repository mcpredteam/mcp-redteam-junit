package io.github.harikrishna8121999.mcpredteam.mcp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpServerTargetTest {

    @Test
    @DisplayName("splits a URL into the origin and path the SDK wants")
    void splitsUrl() {
        McpServerTarget.StreamableHttp target =
                McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp");

        assertEquals("https://mcp.vendor.example", target.baseUri());
        assertEquals("/mcp", target.endpoint());
    }

    @Test
    @DisplayName("keeps a non-default port and a nested path")
    void keepsPortAndPath() {
        McpServerTarget.StreamableHttp target =
                McpServerTarget.streamableHttp("http://localhost:8931/api/v2/mcp");

        assertEquals("http://localhost:8931", target.baseUri());
        assertEquals("/api/v2/mcp", target.endpoint());
    }

    @Test
    @DisplayName("keeps the query string, which some servers use to route tenants")
    void keepsQuery() {
        McpServerTarget.StreamableHttp target =
                McpServerTarget.streamableHttp("https://host.example/mcp?tenant=acme");

        assertEquals("/mcp?tenant=acme", target.endpoint());
    }

    @Test
    @DisplayName("defaults a bare origin to the conventional /mcp endpoint")
    void defaultsEndpoint() {
        assertEquals("/mcp", McpServerTarget.streamableHttp("https://host.example").endpoint());
        assertEquals("/mcp", McpServerTarget.streamableHttp("https://host.example/").endpoint());
    }

    @Test
    @DisplayName("rejects a URL with no scheme rather than guessing one")
    void rejectsSchemelessUrl() {
        // Worth being strict about: "localhost:8080/mcp" parses as a URI whose *scheme* is
        // "localhost", so a lenient reading would send the scan somewhere nobody asked for and
        // report whatever it found there.
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> McpServerTarget.streamableHttp("localhost:8080/mcp"));

        assertTrue(thrown.getMessage().contains("scheme and a host"), thrown.getMessage());
    }

    @Test
    @DisplayName("rejects a blank stdio command")
    void rejectsBlankCommand() {
        assertThrows(IllegalArgumentException.class, () -> McpServerTarget.stdio("  "));
    }

    @Test
    @DisplayName("describes a target without contacting it")
    void describes() {
        assertEquals("npx -y @vendor/server",
                McpServerTarget.stdio("npx", "-y", "@vendor/server").describe());
        assertEquals("https://host.example/mcp",
                McpServerTarget.streamableHttp("https://host.example/mcp").describe());
    }

    @Test
    @DisplayName("headers and env are copied, so a caller cannot mutate a target after building it")
    void isImmutable() {
        McpServerTarget.StreamableHttp base = McpServerTarget.streamableHttp("https://host.example/mcp");
        McpServerTarget.StreamableHttp authorized = base.withHeader("Authorization", "Bearer scoped-token");

        assertTrue(base.headers().isEmpty());
        assertEquals("Bearer scoped-token", authorized.headers().get("Authorization"));
        assertThrows(UnsupportedOperationException.class, () -> authorized.headers().put("X", "y"));
    }
}
