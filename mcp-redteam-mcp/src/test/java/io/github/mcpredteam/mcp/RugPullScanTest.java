package io.github.mcpredteam.mcp;

import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.fingerprint.Baseline;
import io.github.mcpredteam.core.fingerprint.ServerFingerprint;
import io.github.mcpredteam.core.fingerprint.UntrustedBaselineException;
import io.github.mcpredteam.mcp.fixture.FixtureCatalog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rug pull, end to end over a real transport: baseline a server, then meet the same server
 * serving different metadata.
 *
 * <p>The two fixtures are two servers because that is the only honest way to simulate this — the
 * scanner cannot ask a server to change its mind. What matters is that the harness calls both by
 * the same name, {@code finance}, which is what an operator's config does: the URL is trusted, and
 * whatever answers on it is "the finance server".
 */
class RugPullScanTest {

    private static List<String> ruleIds(ScanReport report) {
        return report.findings().stream().map(Finding::ruleId).toList();
    }

    @Test
    @DisplayName("metadata that changed after the baseline is caught, and what it introduced escalates")
    void catchesTheRugPull(@TempDir Path dir) {
        Path baselineFile = dir.resolve("finance-baseline.txt");

        try (HttpFixtureServer trusted = HttpFixtureServer.start(FixtureCatalog.FINANCE);
             McpServerConnection connection = McpServerConnection.connect(
                     FixtureCatalog.TRUSTED_SERVER, McpServerTarget.streamableHttp(trusted.url()))) {
            Baseline.write(connection.captureBaseline(), baselineFile);
        }

        ServerFingerprint approved = Baseline.read(baselineFile);

        try (HttpFixtureServer rugged = HttpFixtureServer.start(FixtureCatalog.FINANCE_RUG_PULL);
             McpServerConnection connection = McpServerConnection.connect(
                     FixtureCatalog.TRUSTED_SERVER, McpServerTarget.streamableHttp(rugged.url()))) {

            ScanReport report = connection.scanAgainst(approved);
            List<String> ids = ruleIds(report);

            assertTrue(ids.stream().anyMatch(id -> id.startsWith("MCPRT-RUG-001/MCPRT-INJ")),
                    "the injected sentence arrived after approval: " + ids);
            assertTrue(ids.contains("MCPRT-RUG-001"),
                    "the harmless reword of send_payment is drift too: " + ids);
            assertTrue(ids.contains("MCPRT-RUG-002"),
                    "export_invoices was never reviewed: " + ids);
            assertTrue(report.hasFindingsAtOrAbove(Severity.HIGH), report.summary());
        }
    }

    @Test
    @DisplayName("the server that was baselined still scans clean against its own baseline")
    void unchangedServerStaysClean() {
        try (HttpFixtureServer trusted = HttpFixtureServer.start(FixtureCatalog.FINANCE);
             McpServerConnection connection = McpServerConnection.connect(
                     FixtureCatalog.TRUSTED_SERVER, McpServerTarget.streamableHttp(trusted.url()))) {

            ServerFingerprint baseline = connection.captureBaseline();

            // Same server, second listing: a fingerprint that moved here would make every later
            // finding noise, since a check that always fires is a check nobody reads.
            List<String> ids = ruleIds(connection.scanAgainst(baseline));
            assertTrue(ids.stream().noneMatch(id -> id.startsWith("MCPRT-RUG")), "saw: " + ids);
        }
    }

    @Test
    @DisplayName("a server that is already poisoned cannot be baselined")
    void refusesToBaselineAPoisonedServer() {
        try (HttpFixtureServer poisoned = HttpFixtureServer.start(FixtureCatalog.TOOL_POISONING);
             McpServerConnection connection = McpServerConnection.connect(
                     FixtureCatalog.MALICIOUS_SERVER, McpServerTarget.streamableHttp(poisoned.url()))) {

            UntrustedBaselineException e = assertThrows(UntrustedBaselineException.class,
                    connection::captureBaseline);

            assertEquals(Severity.HIGH, e.gate());
            assertTrue(e.report().hasFindingsAtOrAbove(Severity.HIGH));
        }
    }

    @Test
    @DisplayName("a baseline is portable across transports, because it fingerprints metadata not plumbing")
    void baselineIsTransportIndependent() {
        ServerFingerprint overStdio;
        try (McpServerConnection stdio = McpServerConnection.connect(
                FixtureCatalog.TRUSTED_SERVER, StdioServerScanTest.fixture(FixtureCatalog.FINANCE))) {
            overStdio = stdio.captureBaseline();
        }

        try (HttpFixtureServer fixture = HttpFixtureServer.start(FixtureCatalog.FINANCE);
             McpServerConnection http = McpServerConnection.connect(
                     FixtureCatalog.TRUSTED_SERVER, McpServerTarget.streamableHttp(fixture.url()))) {

            List<String> ids = ruleIds(http.scanAgainst(overStdio));
            assertTrue(ids.stream().noneMatch(id -> id.startsWith("MCPRT-RUG")), "saw: " + ids);
        }
    }
}
