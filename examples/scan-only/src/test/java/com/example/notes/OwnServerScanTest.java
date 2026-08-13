package com.example.notes;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.MetadataScanner;
import io.github.mcpredteam.core.ScanReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;

/**
 * Start here. This is the whole library in one test, and it needs nothing running — no MCP
 * server, no agent, no model, no API key.
 *
 * <p>It is the gate you would keep in CI. Its value is not today's green run; it is the day
 * someone edits a tool description and this turns red before an agent ever reads it.
 */
class OwnServerScanTest {

    private final MetadataScanner scanner = MetadataScanner.withDefaultRules();

    @Test
    @DisplayName("our own tools carry no high-risk findings")
    void ourToolsAreClean() {
        ScanReport report = scanner.scan(NotesToolCatalog.all());

        System.out.println("[notes] " + report.summary());

        assertThat(report)
                // Findings carry a confidence as well as a severity. Gate on FIRM and above;
                // review TENTATIVE ones by hand rather than letting them break the build.
                .ignoringConfidenceBelow(Confidence.FIRM)
                .hasNoHighRiskFindings();
    }

    /**
     * The other half of a scanner worth keeping, and the half that usually goes missing.
     *
     * <p>Our {@code export_note} says "base64" and our {@code delete_note} says "delete" — the
     * exact words a careless rule keys on. Asserting the scanner stays quiet is what stops it
     * from becoming noise the team mutes, at which point it is not there when a real poisoned
     * tool arrives.
     */
    @Test
    @DisplayName("ordinary words like base64 and delete do not trip the scanner")
    void honestToolsAreNotFalsePositives() {
        ScanReport report = scanner.scan(NotesToolCatalog.all());

        assertThat(report)
                .hasNoFindingFrom("MCPRT-ENC")   // "base64" in export_note
                .hasNoFindingFrom("MCPRT-CAP");  // delete_note declares destructiveHint
    }
}
