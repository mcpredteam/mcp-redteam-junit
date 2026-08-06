package io.github.harikrishna8121999.mcpredteam.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public record ScanReport(Instant startedAt, Instant finishedAt, int toolsScanned, List<Finding> findings) {

    private static final Comparator<Finding> BY_RISK = Comparator
            .comparing(Finding::severity).reversed()
            .thenComparing(Comparator.comparing(Finding::confidence).reversed())
            .thenComparing(Finding::target)
            .thenComparing(Finding::ruleId);

    public ScanReport {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    public static ScanReport empty() {
        Instant now = Instant.now();
        return new ScanReport(now, now, 0, List.of());
    }

    public Duration duration() {
        return Duration.between(startedAt, finishedAt);
    }

    public boolean isClean() {
        return findings.isEmpty();
    }

    public boolean hasFindingsAtOrAbove(Severity threshold) {
        return findings.stream().anyMatch(f -> f.severity().isAtLeast(threshold));
    }

    public List<Finding> findingsAtOrAbove(Severity threshold) {
        return findings.stream()
                .filter(f -> f.severity().isAtLeast(threshold))
                .sorted(BY_RISK)
                .toList();
    }

    public List<Finding> findingsAtOrAbove(Severity severityThreshold, Confidence confidenceThreshold) {
        return findings.stream()
                .filter(f -> f.severity().isAtLeast(severityThreshold))
                .filter(f -> f.confidence().isAtLeast(confidenceThreshold))
                .sorted(BY_RISK)
                .toList();
    }

    /** Findings ordered most severe first, then most confident first. */
    public List<Finding> byRisk() {
        return findings.stream().sorted(BY_RISK).toList();
    }

    public Optional<Severity> highestSeverity() {
        return findings.stream().map(Finding::severity).max(Comparator.naturalOrder());
    }

    public Map<Severity, Long> countsBySeverity() {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Finding finding : findings) {
            counts.merge(finding.severity(), 1L, Long::sum);
        }
        return counts;
    }

    public String summary() {
        if (findings.isEmpty()) {
            return "No findings across " + toolsScanned + " tool(s).";
        }
        StringBuilder sb = new StringBuilder(findings.size() + " finding(s) across " + toolsScanned + " tool(s): ");
        Map<Severity, Long> counts = countsBySeverity();
        List<String> parts = counts.entrySet().stream()
                .sorted(Map.Entry.<Severity, Long>comparingByKey().reversed())
                .map(e -> e.getValue() + " " + e.getKey())
                .toList();
        return sb.append(String.join(", ", parts)).toString();
    }
}
