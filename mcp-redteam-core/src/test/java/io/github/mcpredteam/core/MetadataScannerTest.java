package io.github.mcpredteam.core;

import io.github.mcpredteam.core.fixture.BenignToolFixtures;
import io.github.mcpredteam.core.fixture.PoisonedToolFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetadataScannerTest {

    private final MetadataScanner scanner = MetadataScanner.withDefaultRules();

    /**
     * Scanned as one corpus rather than tool by tool, because shadowing and cross-tool
     * redirection only exist in relation to other tools — in isolation those fixtures are
     * genuinely undetectable, and asserting otherwise would be testing the wrong thing.
     */
    @Test
    @DisplayName("every poisoned fixture is flagged when the corpus is scanned together")
    void poisonedFixturesAreDetected() {
        ScanReport report = scanner.scan(PoisonedToolFixtures.all());
        Set<String> flagged = report.findings().stream()
                .map(Finding::target)
                .collect(Collectors.toSet());

        for (ToolDefinition tool : PoisonedToolFixtures.all()) {
            assertTrue(flagged.contains(tool.qualifiedName()),
                    () -> "Poisoned fixture '" + tool.name() + "' produced no finding. "
                            + "A detector that misses a known-bad fixture reports safety it never verified. "
                            + "Flagged: " + flagged);
        }
        assertTrue(report.hasFindingsAtOrAbove(Severity.CRITICAL),
                "The poisoned corpus should include at least one critical finding");
    }

    @Test
    @DisplayName("each single-tool poisoning fixture is caught without needing corpus context")
    void singleToolFixturesAreDetectedInIsolation() {
        List<ToolDefinition> selfContained = List.of(
                PoisonedToolFixtures.descriptionPoisoning(),
                PoisonedToolFixtures.schemaPoisoning(),
                PoisonedToolFixtures.exfiltrationChannel(),
                PoisonedToolFixtures.hiddenUnicodePoisoning(),
                PoisonedToolFixtures.homoglyphShadow(),
                PoisonedToolFixtures.encodedPayload());

        for (ToolDefinition tool : selfContained) {
            ScanReport report = scanner.scan(List.of(tool));
            assertTrue(report.hasFindingsAtOrAbove(Severity.HIGH),
                    () -> "Expected a high-risk finding for '" + tool.name() + "' but got: " + report.summary());
        }
    }

    /**
     * The most important test in the suite. Every entry in the benign corpus contains words a
     * naive rule keys on — "base64", "system prompt", "credentials", "delete", "webhook" — in
     * their ordinary sense. If any of them trips a high-severity rule, the scanner is training
     * users to ignore it.
     */
    @ParameterizedTest(name = "benign tool ''{0}'' produces no high-risk finding")
    @MethodSource("benignTools")
    void benignToolsDoNotProduceHighRiskFindings(String name, ToolDefinition tool) {
        ScanReport report = scanner.scan(List.of(tool));
        assertFalse(report.hasFindingsAtOrAbove(Severity.HIGH),
                () -> "False positive on legitimate tool '" + name + "':" + System.lineSeparator()
                        + report.byRisk().stream().map(Finding::describe).reduce("", (a, b) -> a + b + "\n"));
    }

    static Stream<org.junit.jupiter.params.provider.Arguments> benignTools() {
        return BenignToolFixtures.all().stream()
                .map(tool -> org.junit.jupiter.params.provider.Arguments.of(tool.name(), tool));
    }

    @Test
    @DisplayName("the whole benign corpus scanned together stays below the HIGH gate")
    void benignCorpusIsCleanAtHighSeverity() {
        ScanReport report = scanner.scan(BenignToolFixtures.all());
        assertFalse(report.hasFindingsAtOrAbove(Severity.HIGH),
                () -> "Benign corpus produced high-risk findings: " + report.summary()
                        + System.lineSeparator()
                        + report.findingsAtOrAbove(Severity.HIGH).stream()
                        .map(Finding::describe).reduce("", (a, b) -> a + b + "\n"));
    }

    @Test
    void reportCountsToolsScanned() {
        ScanReport report = scanner.scan(BenignToolFixtures.all());
        assertEquals(BenignToolFixtures.all().size(), report.toolsScanned());
    }

    @Test
    void nullAndEmptyInputProduceAnEmptyReport() {
        assertTrue(scanner.scan(null).isClean());
        assertTrue(scanner.scan(List.of()).isClean());
        assertEquals(0, scanner.scan(null).toolsScanned());
    }

    @Test
    @DisplayName("identical findings from repeated scans of the same tool are de-duplicated")
    void findingsAreDeduplicated() {
        ToolDefinition tool = PoisonedToolFixtures.descriptionPoisoning();
        ScanReport report = scanner.scan(List.of(tool));
        long distinctKeys = report.findings().stream().map(Finding::dedupeKey).distinct().count();
        assertEquals(report.findings().size(), distinctKeys, "Report contains duplicate findings");
    }

    @Test
    void suppressedRuleFamilyIsExcluded() {
        MetadataScanner suppressed = MetadataScanner.builder().suppress("MCPRT-INJ").build();
        ScanReport report = suppressed.scan(List.of(PoisonedToolFixtures.descriptionPoisoning()));
        assertTrue(report.findings().stream().noneMatch(f -> f.ruleId().startsWith("MCPRT-INJ")),
                "Suppressed rule family still produced findings");
    }

    @Test
    void suppressingASingleRuleLeavesTheRestOfTheFamily() {
        MetadataScanner suppressed = MetadataScanner.builder().suppress("MCPRT-INJ-001").build();
        ScanReport report = suppressed.scan(List.of(PoisonedToolFixtures.descriptionPoisoning()));
        assertTrue(report.findings().stream().noneMatch(f -> f.ruleId().equals("MCPRT-INJ-001")));
        assertTrue(report.findings().stream().anyMatch(f -> f.ruleId().startsWith("MCPRT-INJ")),
                "Suppressing one signature should not silence the whole family");
    }

    @Test
    void findingsCarryOwaspMapping() {
        ScanReport report = scanner.scan(List.of(PoisonedToolFixtures.descriptionPoisoning()));
        assertTrue(report.findings().stream().allMatch(f -> f.threatType().owaspId().startsWith("MCP")),
                "Every finding should map onto the OWASP MCP Top 10");
    }
}
