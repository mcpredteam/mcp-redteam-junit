package com.example.notes;

import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.fingerprint.Baseline;
import io.github.mcpredteam.core.fingerprint.ServerFingerprint;
import io.github.mcpredteam.core.fingerprint.UntrustedBaselineException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.github.mcpredteam.mcp.McpServerConnection;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The question a scan cannot answer: is this still the server we approved?
 *
 * <p>A scan says whether a server looks malicious <em>today</em>. To catch a rug pull — a server
 * that was clean when you reviewed it and is not clean now — it has to remember. {@code
 * src/test/resources/notes-baseline.txt} is a committed fingerprint of what the server published
 * when it was approved: a sorted line per tool field, so a change shows up as one reviewable line
 * in a pull request.
 *
 * @see CaptureBaseline for how the file is produced — by hand, never by a test
 */
class ServerDriftTest {

    private final ServerFingerprint approved = Baseline.read(CaptureBaseline.FILE);

    @Test
    @DisplayName("the running server still matches what we approved")
    void serverHasNotDrifted() {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            assertThat(notes.scanAgainst(approved)).hasNoFindingsAtOrAbove(Severity.MEDIUM);
        }
    }

    /**
     * The same server after an unreviewed update. All three changes are caught: the new
     * {@code archive_note} nobody looked at, the instruction that appeared inside
     * {@code export_note}, and the reword of {@code search_notes} that breaks no rule at all and
     * is drift anyway.
     *
     * <p>Drift alone is MEDIUM, because vendors do ship features. Drift that introduced text the
     * static rules flag is reported at that rule's severity, under a composite id such as
     * {@code MCPRT-RUG-001/MCPRT-INJ-001} — the change is what escalates it.
     */
    @Test
    @DisplayName("an unreviewed update is caught, and the poisoned edit escalates it")
    void unreviewedUpdateIsCaught() {
        try (McpServerConnection changed = McpServerConnection.connect(
                "notes", NotesServers.notes(NotesMcpServer.COMPROMISED))) {

            AssertionError failure = assertThrows(AssertionError.class,
                    () -> assertThat(changed.scanAgainst(approved))
                            .hasNoFindingsAtOrAbove(Severity.MEDIUM));

            System.out.println();
            System.out.println("=== what a rug pull looks like ===");
            System.out.println(failure.getMessage());
            System.out.println("=================================");
        }
    }

    /**
     * A fingerprint that depended on JSON key order, or on which JVM ran the capture, would drift
     * by itself — and a team that has learned to re-capture until green has no check left.
     */
    @Test
    @DisplayName("re-capturing on this machine reproduces the committed digests")
    void baselineIsReproducible() {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            ServerFingerprint fresh = notes.captureBaseline();

            assertEquals(approved.toolNames(), fresh.toolNames(), "the set of tools changed");
            for (String tool : approved.toolNames()) {
                assertEquals(approved.tool(tool).orElseThrow().digest(),
                        fresh.tool(tool).orElseThrow().digest(),
                        "digest moved for " + tool + " without the server changing");
            }
        }
    }

    /**
     * The tempting fix once {@link #unreviewedUpdateIsCaught} goes red: the drift check fails, so
     * somebody re-captures. Capture refuses, because a baseline of a poisoned server records the
     * poison as trusted.
     */
    @Test
    @DisplayName("capture refuses a server that already fails the scan")
    void refusesToBaselineTheCompromisedServer() {
        try (McpServerConnection changed = McpServerConnection.connect(
                "notes", NotesServers.notes(NotesMcpServer.COMPROMISED))) {

            UntrustedBaselineException refused =
                    assertThrows(UntrustedBaselineException.class, changed::captureBaseline);

            System.out.println("[capture refused] " + refused.getMessage());
        }
    }
}
