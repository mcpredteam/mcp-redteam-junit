package com.example.notes;

import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ToolDefinition;
import io.github.mcpredteam.core.report.Reports;
import io.github.mcpredteam.mcp.McpServerConnection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The same checks as {@link OwnServerScanTest}, against a server that is actually running.
 *
 * <p>This is the gate a team would really keep: nobody maintains a hand-written copy of their
 * tool catalog, and a copy that drifts from the server is worse than no check at all.
 *
 * <p>Needs {@code mcp-redteam-mcp} and the MCP SDK on the classpath. Still no model and no
 * API key.
 */
class LiveServerScanTest {

    @Test
    @DisplayName("scanning the running server finds the same clean result")
    void liveServerIsClean() {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            ScanReport report = notes.scan();

            System.out.println("[live] " + report.summary());

            assertThat(report).hasNoFindingsAtOrAbove(Severity.HIGH);
        }
    }

    /**
     * A scan over nothing finds nothing, which renders as a green build indistinguishable from a
     * server that was examined and found clean. Assert something was actually read.
     */
    @Test
    @DisplayName("the server published tools, so the scan examined something")
    void theScanActuallyExaminedSomething() {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            List<ToolDefinition> tools = notes.listTools();

            assertFalse(tools.isEmpty(), "notes server published no tools — the scan proved nothing");
        }
    }

    /**
     * Tool annotations only exist on the wire. Spring AI's tool model has no field for them, so
     * on that path an unannotated destructive tool looks identical to an annotated one; over the
     * protocol client, MCPRT-CAP can finally tell them apart.
     *
     * <p>Both halves are asserted, because a rule that always fires is noise and a rule that
     * never fires is decoration.
     */
    @Test
    @DisplayName("MCPRT-CAP fires when delete_note stops declaring destructiveHint")
    void unannotatedDestructiveToolIsFlagged() {
        try (McpServerConnection annotated = McpServerConnection.connect("notes", NotesServers.notes())) {
            assertThat(annotated.scan()).hasNoFindingFrom("MCPRT-CAP");
        }

        try (McpServerConnection bare = McpServerConnection.connect(
                "notes", NotesServers.notes(NotesMcpServer.DROP_ANNOTATIONS))) {

            assertThat(bare.scan()).hasFinding("MCPRT-CAP");
        }
    }

    /**
     * The artifact half. A failure message is for whoever broke the build; a report is for the
     * reviewer on the pull request and for the person asking in six months what this server
     * looked like when it was approved.
     *
     * <p>Written under {@code target/}, never into the repository — a report can quote a
     * poisoned description verbatim.
     */
    @Test
    @DisplayName("a scan writes JSON and JUnit XML artifacts")
    void scanWritesReports() {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            ScanReport report = notes.scan();

            Reports.json(report).writeTo(Path.of("target/mcp-redteam/scan.json"));
            Reports.junitXml(report).writeTo(Path.of("target/mcp-redteam/scan-junit.xml"));

            // Writing a report never gates anything. The assertion is still the gate.
            assertThat(report).hasNoFindingsAtOrAbove(Severity.HIGH);
        }
    }
}
