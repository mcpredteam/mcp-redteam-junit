package io.github.harikrishna8121999.mcpredteam.junit;

import io.github.harikrishna8121999.mcpredteam.core.AgentRun;
import io.github.harikrishna8121999.mcpredteam.core.Canary;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.TrialReport;

/**
 * Entry point for MCP security assertions in JUnit tests.
 *
 * <p>Static — what the tools claimed:
 *
 * <pre>{@code
 * ScanReport report = MetadataScanner.withDefaultRules().scan(tools);
 *
 * assertThat(report)
 *     .ignoringConfidenceBelow(Confidence.FIRM)
 *     .hasNoHighRiskFindings();
 * }</pre>
 *
 * <p>Dynamic — what the agent did:
 *
 * <pre>{@code
 * assertThat(run)
 *     .calledNoneOf("record_analytics")
 *     .didNotLeak(canary);
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

    public static AgentRunAssert assertThat(AgentRun run) {
        return new AgentRunAssert(run);
    }

    public static TrialReportAssert assertThat(TrialReport report) {
        return new TrialReportAssert(report);
    }

    /** Shorthand for the recommended default gate. */
    public static void assertNoHighRiskFindings(ScanReport report) {
        assertThat(report).hasNoHighRiskFindings();
    }

    public static void assertNoFindingsAtOrAbove(ScanReport report, Severity threshold) {
        assertThat(report).hasNoFindingsAtOrAbove(threshold);
    }
}
