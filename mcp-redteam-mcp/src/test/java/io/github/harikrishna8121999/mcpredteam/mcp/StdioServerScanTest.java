package io.github.harikrishna8121999.mcpredteam.mcp;

import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import io.github.harikrishna8121999.mcpredteam.mcp.fixture.FixtureCatalog;
import io.github.harikrishna8121999.mcpredteam.mcp.fixture.McpFixtureServerMain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The exit criterion for this module, over stdio: a scan of a server nobody hand-wrote a
 * {@code ToolDefinition} for.
 */
class StdioServerScanTest {

    static McpServerTarget fixture(String profile) {
        String java = System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java";
        return McpServerTarget.stdio(Path.of(System.getProperty("java.home"), "bin", java).toString(),
                "-cp", System.getProperty("java.class.path"),
                McpFixtureServerMain.class.getName(), profile);
    }

    @Test
    @DisplayName("reads tools/list from a real server process")
    void listsToolsOverStdio() {
        try (McpServerConnection connection = McpServerConnection.connect("finance", fixture(FixtureCatalog.FINANCE))) {
            List<String> names = connection.listTools().stream().map(ToolDefinition::name).sorted().toList();

            assertEquals(List.of("list_invoices", "send_payment"), names);
        }
    }

    @Test
    @DisplayName("scans a poisoned server without anyone writing its tools down first")
    void scansAPoisonedServer() {
        try (McpServerConnection connection =
                     McpServerConnection.connect("evil-analytics", fixture(FixtureCatalog.TOOL_POISONING))) {

            ScanReport report = connection.scan();

            assertTrue(report.hasFindingsAtOrAbove(Severity.HIGH),
                    "the poisoned description should be caught over the wire: " + report.findings());
        }
    }

    @Test
    @DisplayName("the benign profile stays clean, so the scan is not just always red")
    void benignServerIsClean() {
        try (McpServerConnection connection = McpServerConnection.connect("finance", fixture(FixtureCatalog.FINANCE))) {
            ScanReport report = connection.scan();

            assertFalse(report.hasFindingsAtOrAbove(Severity.HIGH),
                    "a false positive here would make the gate unusable: " + report.findings());
        }
    }

    @Test
    @DisplayName("findings are reported against our label, never the name the server chose for itself")
    void serverNameIsOurs() {
        try (McpServerConnection connection =
                     McpServerConnection.connect("vendor-under-test", fixture(FixtureCatalog.TOOL_POISONING))) {

            // The fixture calls itself "mcp-redteam-fixture-tool-poisoning". A hostile server
            // would pick something reassuring instead, and a report that repeated it back would
            // be laundering the server's own claim into evidence.
            assertEquals("mcp-redteam-fixture-tool-poisoning", connection.declaredServerInfo().name());
            assertTrue(connection.listTools().stream()
                            .allMatch(tool -> tool.qualifiedName().startsWith("vendor-under-test/")),
                    "findings must be attributed to the name the harness was given");
        }
    }

    @Test
    @DisplayName("a target that cannot be reached fails as a connection error, not a clean scan")
    void unreachableServerFails() {
        // The failure mode this project fears most is a security check that reports nothing
        // found because it never ran. An unreachable server must not look like an empty one.
        // A short timeout here on purpose: the default is tuned for a cold remote server, and
        // waiting thirty seconds to observe a failure we caused deliberately is thirty seconds
        // on every build.
        assertThrows(IllegalStateException.class, () -> McpServerConnection.connect("nowhere",
                McpServerTarget.stdio(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-version"),
                Duration.ofSeconds(2), McpServerConnection.DEFAULT_MAX_PAGES));
    }
}
