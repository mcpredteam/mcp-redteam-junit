package io.github.harikrishna8121999.mcpredteam.core.report;

import io.github.harikrishna8121999.mcpredteam.core.ScanReport;

import java.util.Objects;

/**
 * Turns a {@link ScanReport} into an artifact.
 *
 * <pre>{@code
 * ScanReport report = MetadataScanner.withDefaultRules().scan(tools);
 *
 * Reports.json(report).writeTo(Path.of("target/mcp-redteam/scan.json"));
 * Reports.junitXml(report).writeTo(Path.of("target/mcp-redteam/scan-junit.xml"));
 *
 * assertThat(report).hasNoHighRiskFindings();     // the gate is still the assertion
 * }</pre>
 *
 * <p>Both formats take the report exactly as given and filter nothing. A report says what was
 * found; deciding what counts is the gate's job, and a writer that quietly dropped everything
 * below some threshold would produce an artifact that disagreed with the test beside it. To
 * publish only what the gate acts on, say so where a reader can see it:
 * {@code Reports.json(report.filteredTo(Severity.HIGH, Confidence.FIRM))}.
 *
 * <p>Rendering the same {@code ScanReport} twice gives the same bytes. Rendering two scans of an
 * unchanged server differs only in the timestamps, which both formats keep in one place for
 * exactly that reason.
 *
 * <p>This also covers dynamic results: {@code BehaviorScanner.scan(AgentRun)} returns a
 * {@code ScanReport}, so a hijack or a canary leak is reported through the same schema as a
 * poisoned description, and a consumer parses one format rather than two.
 */
public final class Reports {

    private Reports() {
    }

    /** The canonical artifact. Everything a finding carries survives the round trip. */
    public static Report json(ScanReport report) {
        Objects.requireNonNull(report, "report");
        return () -> JsonFormat.render(report);
    }

    /**
     * JUnit XML, for CI systems that already know how to display it.
     *
     * <p>Lossy by design — it carries the rule id, the target and the rendered failure text, not
     * the structured evidence. Use it to make findings visible in a build UI; use
     * {@link #json(ScanReport)} when something is going to parse the result.
     */
    public static Report junitXml(ScanReport report) {
        Objects.requireNonNull(report, "report");
        return () -> JUnitXmlFormat.render(report);
    }
}
