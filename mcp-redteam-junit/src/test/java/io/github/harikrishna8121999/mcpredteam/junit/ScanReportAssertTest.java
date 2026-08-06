package io.github.harikrishna8121999.mcpredteam.junit;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.MetadataScanner;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.fixture.BenignToolFixtures;
import io.github.harikrishna8121999.mcpredteam.core.fixture.PoisonedToolFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static io.github.harikrishna8121999.mcpredteam.junit.McpSecurityAssertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanReportAssertTest {

    private static ScanReport reportWith(Severity severity, Confidence confidence) {
        Finding finding = Finding.builder("MCPRT-TEST-001")
                .threatType(ThreatType.TOOL_POISONING)
                .severity(severity)
                .confidence(confidence)
                .target("srv/tool")
                .location("description")
                .message("test finding")
                .remediation("do the thing")
                .evidence("match", "ignore all previous instructions")
                .build();
        Instant now = Instant.now();
        return new ScanReport(now, now, 1, List.of(finding));
    }

    /**
     * Regression test for the defect that shipped in the first scaffold: the only bundled
     * scanner emitted HIGH findings while the only bundled assertion tripped on CRITICAL,
     * so the pair could never fail. A security assertion that cannot fail is worse than
     * none — it reports safety it never checked.
     */
    @Test
    @DisplayName("a report of HIGH findings fails the default gate")
    void highSeverityFindingsFailTheDefaultGate() {
        ScanReport report = reportWith(Severity.HIGH, Confidence.FIRM);
        assertThrows(AssertionError.class, () -> assertThat(report).hasNoHighRiskFindings());
    }

    @Test
    @DisplayName("the real scanner and the real assertion actually fail on a real poisoned tool")
    void endToEndPoisonedToolFailsTheGate() {
        ScanReport report = MetadataScanner.withDefaultRules()
                .scan(List.of(PoisonedToolFixtures.descriptionPoisoning()));
        assertThrows(AssertionError.class, () -> assertThat(report).hasNoHighRiskFindings(),
                "Scanner and assertion must agree on severity, or the gate is decorative");
    }

    @Test
    void benignCorpusPassesTheDefaultGate() {
        ScanReport report = MetadataScanner.withDefaultRules().scan(BenignToolFixtures.all());
        assertDoesNotThrow(() -> assertThat(report).hasNoHighRiskFindings());
    }

    @Test
    void criticalFindingsAlsoFailTheDefaultGate() {
        assertThrows(AssertionError.class,
                () -> assertThat(reportWith(Severity.CRITICAL, Confidence.CERTAIN)).hasNoHighRiskFindings());
    }

    @Test
    void mediumFindingsPassTheDefaultGateButFailAStricterOne() {
        ScanReport report = reportWith(Severity.MEDIUM, Confidence.FIRM);
        assertDoesNotThrow(() -> assertThat(report).hasNoHighRiskFindings());
        assertThrows(AssertionError.class, () -> assertThat(report).hasNoFindingsAtOrAbove(Severity.MEDIUM));
        assertThrows(AssertionError.class, () -> assertThat(report).isClean());
    }

    @Test
    @DisplayName("confidence filtering lets CI gate on high-signal findings only")
    void confidenceThresholdFiltersTentativeFindings() {
        ScanReport report = reportWith(Severity.HIGH, Confidence.TENTATIVE);
        assertThrows(AssertionError.class, () -> assertThat(report).hasNoHighRiskFindings());
        assertDoesNotThrow(() -> assertThat(report)
                .ignoringConfidenceBelow(Confidence.FIRM)
                .hasNoHighRiskFindings());
    }

    @Test
    @DisplayName("failure messages carry the evidence and the fix, not just a count")
    void failureMessageIsActionable() {
        AssertionError error = assertThrows(AssertionError.class,
                () -> assertThat(reportWith(Severity.HIGH, Confidence.FIRM)).hasNoHighRiskFindings());

        String message = error.getMessage();
        assertTrue(message.contains("MCPRT-TEST-001"), "should name the rule");
        assertTrue(message.contains("srv/tool"), "should name the tool");
        assertTrue(message.contains("description"), "should name the location");
        assertTrue(message.contains("ignore all previous instructions"), "should show the matched evidence");
        assertTrue(message.contains("do the thing"), "should show the remediation");
        assertTrue(message.contains("MCP03"), "should carry the OWASP mapping");
    }

    @Test
    void hasFindingDetectsWhetherARuleFired() {
        ScanReport report = MetadataScanner.withDefaultRules()
                .scan(List.of(PoisonedToolFixtures.descriptionPoisoning()));
        assertDoesNotThrow(() -> assertThat(report).hasFinding("MCPRT-INJ"));
        assertThrows(AssertionError.class, () -> assertThat(report).hasFinding("MCPRT-NOPE"));
    }

    @Test
    void hasNoFindingFromIsTheInverse() {
        ScanReport clean = MetadataScanner.withDefaultRules().scan(BenignToolFixtures.all());
        assertDoesNotThrow(() -> assertThat(clean).hasNoFindingFrom("MCPRT-INJ"));
    }

    @Test
    void nullReportFailsLoudly() {
        assertThrows(AssertionError.class, () -> assertThat((ScanReport) null));
    }
}
