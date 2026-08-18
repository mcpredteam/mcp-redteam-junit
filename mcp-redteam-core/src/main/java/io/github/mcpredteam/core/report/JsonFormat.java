package io.github.mcpredteam.core.report;

import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ThreatType;

import java.util.Map;

/**
 * The canonical JSON artifact.
 *
 * <p>Shape, and the reasoning behind it:
 *
 * <pre>{@code
 * {
 *   "schemaVersion": 1,
 *   "reportType": "scan",
 *   "producer":  { "name": "mcp-redteam", "version": "0.1.0" },
 *   "taxonomy":  { "name": "OWASP MCP Top 10", "version": "0.1 (2025)", "url": "..." },
 *   "scan":      { "startedAt": "...", "finishedAt": "...", "durationMillis": 12, "toolsScanned": 3 },
 *   "summary":   { "findings": 2, "highestSeverity": "CRITICAL", "countsBySeverity": { ... } },
 *   "findings":  [ ... ]
 * }
 * }</pre>
 *
 * <p><strong>Everything that varies between two runs of the same scan is in the {@code scan}
 * block, and it is at the top.</strong> That is the whole layout decision. A report is supposed
 * to be diffable in review, and timestamps are genuinely useful information, so the two are
 * reconciled by segregating them: re-scanning an unchanged server produces a file whose only
 * changed lines are the three in {@code scan}, and the findings below are byte-identical. The
 * committed baseline format solves the same problem the same way, with its volatile
 * {@code !capturedAt} directive above the sorted data.
 *
 * <p>Findings are emitted in {@link ScanReport#byRisk()} order, which is a total order, so
 * "byte-identical" is a real guarantee rather than a usual outcome.
 *
 * <p>{@code schemaVersion} is a number at the top of the file for the reason every format wants
 * one and few have one: it costs nothing now and cannot be added later without a reader that
 * has to guess.
 */
final class JsonFormat {

    static final int SCHEMA_VERSION = 1;

    private JsonFormat() {
    }

    static String render(ScanReport report) {
        JsonWriter json = new JsonWriter();
        json.startObject()
                .field("schemaVersion", SCHEMA_VERSION)
                .field("reportType", "scan");

        json.startObject("producer")
                .field("name", BuildInfo.NAME)
                .field("version", BuildInfo.version())
                .endObject();

        json.startObject("taxonomy")
                .field("name", ThreatType.TAXONOMY)
                .field("version", ThreatType.TAXONOMY_VERSION)
                .field("url", ThreatType.TAXONOMY_URL)
                .endObject();

        json.startObject("scan")
                .field("startedAt", String.valueOf(report.startedAt()))
                .field("finishedAt", String.valueOf(report.finishedAt()))
                .field("durationMillis", report.duration().toMillis())
                .field("toolsScanned", report.toolsScanned())
                .endObject();

        json.startObject("summary")
                .field("findings", report.findings().size());
        Severity highest = report.highestSeverity().orElse(null);
        json.field("highestSeverity", highest);
        json.startObject("countsBySeverity");
        // Most severe first, matching ScanReport#summary. The EnumMap would already iterate
        // deterministically, but in declaration order, which puts CRITICAL last in a block whose
        // whole job is to be read at a glance.
        report.countsBySeverity().entrySet().stream()
                .sorted(Map.Entry.<Severity, Long>comparingByKey().reversed())
                .forEach(entry -> json.field(entry.getKey().name(), entry.getValue()));
        json.endObject();
        json.endObject();

        json.startArray("findings");
        for (Finding finding : report.byRisk()) {
            writeFinding(json, finding);
        }
        json.endArray();

        return json.endObject().render() + "\n";
    }

    private static void writeFinding(JsonWriter json, Finding finding) {
        json.startElement()
                .field("ruleId", finding.ruleId())
                .field("threatType", finding.threatType())
                .field("owaspId", finding.threatType().owaspId())
                .field("owaspTitle", finding.threatType().owaspTitle())
                .field("severity", finding.severity())
                .field("confidence", finding.confidence())
                .field("target", finding.target())
                .field("location", finding.location())
                .field("message", finding.message())
                .field("remediation", finding.remediation());

        json.startObject("evidence");
        // Insertion order, not sorted: rules put the matched text first on purpose. Finding
        // preserves that order rather than storing a Map.copyOf, which would reshuffle it on
        // every JVM — see the note on its canonical constructor.
        for (Map.Entry<String, Object> entry : finding.evidence().entrySet()) {
            json.value(entry.getKey(), entry.getValue());
        }
        json.endObject();

        json.endObject();
    }
}
