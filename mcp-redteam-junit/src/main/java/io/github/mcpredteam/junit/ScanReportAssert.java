package io.github.mcpredteam.junit;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;

import java.util.List;

/**
 * Fluent assertions over a {@link ScanReport}.
 *
 * <p>The default gate is {@link Severity#HIGH}, not {@code CRITICAL}. Most rules top out at
 * HIGH by design, so a CRITICAL-only gate would pass on almost every real poisoned tool —
 * a test that cannot fail is worse than no test, because it reports safety it never checked.
 */
public final class ScanReportAssert {

    private final ScanReport report;
    private Confidence minimumConfidence = Confidence.TENTATIVE;

    ScanReportAssert(ScanReport report) {
        if (report == null) {
            throw new AssertionError("Expected a ScanReport but was null");
        }
        this.report = report;
    }

    /**
     * Ignores findings below the given confidence. Use {@link Confidence#FIRM} in CI to gate
     * on high-signal detections only while still surfacing tentative ones in the report.
     */
    public ScanReportAssert ignoringConfidenceBelow(Confidence threshold) {
        this.minimumConfidence = threshold;
        return this;
    }

    /** Fails if any finding is HIGH or CRITICAL. The recommended default gate. */
    public ScanReportAssert hasNoHighRiskFindings() {
        return hasNoFindingsAtOrAbove(Severity.HIGH);
    }

    public ScanReportAssert hasNoFindingsAtOrAbove(Severity threshold) {
        List<Finding> offending = report.findingsAtOrAbove(threshold, minimumConfidence);
        if (!offending.isEmpty()) {
            throw new AssertionError(buildMessage(
                    "Expected no MCP security findings at or above " + threshold
                            + " (confidence >= " + minimumConfidence + "), but found " + offending.size(),
                    offending));
        }
        return this;
    }

    /** Strictest gate: fails on anything at all, including INFO. */
    public ScanReportAssert isClean() {
        if (!report.isClean()) {
            throw new AssertionError(buildMessage(
                    "Expected a clean MCP scan, but found " + report.findings().size() + " finding(s)",
                    report.byRisk()));
        }
        return this;
    }

    /**
     * Asserts a rule fired. Used to test the scanner itself — a detector with no
     * positive-case coverage silently degrades into one that never fires.
     *
     * @param ruleIdPrefix exact id ({@code MCPRT-INJ-001}) or family ({@code MCPRT-INJ})
     */
    public ScanReportAssert hasFinding(String ruleIdPrefix) {
        boolean present = report.findings().stream()
                .anyMatch(f -> f.ruleId().startsWith(ruleIdPrefix));
        if (!present) {
            throw new AssertionError(buildMessage(
                    "Expected a finding from rule '" + ruleIdPrefix + "', but it did not fire",
                    report.byRisk()));
        }
        return this;
    }

    public ScanReportAssert hasNoFindingFrom(String ruleIdPrefix) {
        List<Finding> offending = report.findings().stream()
                .filter(f -> f.ruleId().startsWith(ruleIdPrefix))
                .toList();
        if (!offending.isEmpty()) {
            throw new AssertionError(buildMessage(
                    "Expected no findings from rule '" + ruleIdPrefix + "', but got " + offending.size(),
                    offending));
        }
        return this;
    }

    public ScanReportAssert hasFindingCount(int expected) {
        if (report.findings().size() != expected) {
            throw new AssertionError(buildMessage(
                    "Expected exactly " + expected + " finding(s) but got " + report.findings().size(),
                    report.byRisk()));
        }
        return this;
    }

    public ScanReport report() {
        return report;
    }

    private static String buildMessage(String headline, List<Finding> findings) {
        StringBuilder sb = new StringBuilder(headline).append(':').append(System.lineSeparator());
        for (Finding finding : findings) {
            sb.append(System.lineSeparator()).append(finding.describe()).append(System.lineSeparator());
        }
        return sb.toString();
    }
}
