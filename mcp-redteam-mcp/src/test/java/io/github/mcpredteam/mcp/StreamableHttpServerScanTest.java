package io.github.mcpredteam.mcp;

import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ToolDefinition;
import io.github.mcpredteam.mcp.fixture.FixtureCatalog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The exit criterion in the form it will usually be met: a URL.
 *
 * <p>Streamable HTTP is the transport remote MCP servers actually use, so a protocol client that
 * only spoke stdio would cover the servers a user already trusts enough to run locally and miss
 * the third-party ones the scanner exists for.
 */
class StreamableHttpServerScanTest {

    @Test
    @DisplayName("scans a live MCP server from nothing but its URL")
    void scansFromAUrl() {
        try (HttpFixtureServer fixture = HttpFixtureServer.start(FixtureCatalog.TOOL_POISONING);
             McpServerConnection connection = McpServerConnection.connect(
                     "vendor", McpServerTarget.streamableHttp(fixture.url()))) {

            ScanReport report = connection.scan();

            assertTrue(report.toolsScanned() > 0, "a scan of zero tools proves nothing");
            assertTrue(report.hasFindingsAtOrAbove(Severity.HIGH),
                    "the poisoned description should survive Streamable HTTP: " + report.findings());
        }
    }

    @Test
    @DisplayName("the benign profile over HTTP stays clean")
    void benignServerIsClean() {
        try (HttpFixtureServer fixture = HttpFixtureServer.start(FixtureCatalog.FINANCE);
             McpServerConnection connection = McpServerConnection.connect(
                     "finance", McpServerTarget.streamableHttp(fixture.url()))) {

            assertFalse(connection.scan().hasFindingsAtOrAbove(Severity.HIGH));
        }
    }

    @Test
    @DisplayName("stdio and Streamable HTTP report the same tools for the same profile")
    void transportsAgree() {
        // The reason the corpus is shared rather than copied. If the two transports ever
        // disagreed about what a profile publishes, every cross-transport claim this project
        // makes would be measuring the transport instead of the payload.
        List<ToolDefinition> overStdio;
        List<ToolDefinition> overHttp;

        try (McpServerConnection stdio = McpServerConnection.connect(
                "vendor", StdioServerScanTest.fixture(FixtureCatalog.CREDENTIAL_PHISH))) {
            overStdio = stdio.listTools();
        }
        try (HttpFixtureServer fixture = HttpFixtureServer.start(FixtureCatalog.CREDENTIAL_PHISH);
             McpServerConnection http = McpServerConnection.connect(
                     "vendor", McpServerTarget.streamableHttp(fixture.url()))) {
            overHttp = http.listTools();
        }

        assertEquals(overStdio, overHttp);
    }

    @Test
    @DisplayName("a URL with nothing listening fails loudly instead of scanning nothing")
    void unreachableUrlFails() {
        assertThrows(IllegalStateException.class, () -> McpServerConnection.connect("nowhere",
                // Port 1 on loopback: reserved, and nothing will ever be listening on it.
                McpServerTarget.streamableHttp("http://localhost:1/mcp"),
                Duration.ofSeconds(2), McpServerConnection.DEFAULT_MAX_PAGES));
    }
}
