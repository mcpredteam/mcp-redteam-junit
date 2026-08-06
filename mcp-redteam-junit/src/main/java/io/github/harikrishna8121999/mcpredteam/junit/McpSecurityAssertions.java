package io.github.harikrishna8121999.mcpredteam.junit;

import io.github.harikrishna8121999.mcpredteam.core.Canary;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;

/**
 * Entry point for MCP security assertions in JUnit tests.
 *
 * <pre>{@code
 * ScanReport report = MetadataScanner.withDefaultRules().scan(tools);
 *
 * assertThat(report)
 *     .ignoringConfidenceBelow(Confidence.FIRM)
 *     .hasNoHighRiskFindings();
 * }</pre>
 */
public final class McpSecurityAssertions {

    private McpSecurityAssertions() {
    }

    public static ScanReportAssert assertThat(ScanReport report) {
        return new ScanReportAssert(report);
    }

    public static CanaryAssert assertThat(Canary canary) {
        return new CanaryAssert(canary);
    }

    /** Shorthand for the recommended default gate. */
    public static void assertNoHighRiskFindings(ScanReport report) {
        assertThat(report).hasNoHighRiskFindings();
    }

    public static void assertNoFindingsAtOrAbove(ScanReport report, Severity threshold) {
        assertThat(report).hasNoFindingsAtOrAbove(threshold);
    }
}
