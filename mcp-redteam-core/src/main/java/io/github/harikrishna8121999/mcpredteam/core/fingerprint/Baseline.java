package io.github.harikrishna8121999.mcpredteam.core.fingerprint;

import io.github.harikrishna8121999.mcpredteam.core.McpSecurityScanner;
import io.github.harikrishna8121999.mcpredteam.core.MetadataScanner;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Capturing and storing what a server looked like when it was trusted.
 *
 * <p>The intended shape of a test is two separate acts. Capture is a deliberate, occasional step
 * a person performs and reviews:
 *
 * <pre>{@code
 * Baseline.write(Baseline.capture("finance", connection.listTools()),
 *                Path.of("src/test/resources/finance-baseline.txt"));
 * }</pre>
 *
 * <p>and the test itself only ever reads:
 *
 * <pre>{@code
 * ServerFingerprint trusted = Baseline.read(Path.of("src/test/resources/finance-baseline.txt"));
 * assertThat(connection.scanAgainst(trusted)).hasNoHighRiskFindings();
 * }</pre>
 *
 * <p>There is deliberately no "capture it if the file is missing" convenience. That call is the
 * one everybody wants and it disables the feature: in CI the file would be created on the first
 * run against whatever the server happens to be serving, and a check that re-baselines itself
 * whenever it has nothing to compare against can never fail. Committing the baseline is the
 * point — the file is line-oriented and sorted so that a server changing underneath the agent
 * shows up as a reviewable diff in a pull request.
 */
public final class Baseline {

    /**
     * Severity at or above which capture refuses to record a server.
     *
     * <p>HIGH rather than CRITICAL for the reason {@code ScanReportAssert} gives about its own
     * default: most rules top out at HIGH, so a CRITICAL-only gate would wave through almost
     * every genuinely poisoned tool.
     */
    public static final Severity DEFAULT_GATE = Severity.HIGH;

    private Baseline() {
    }

    /** Captures a baseline, refusing if the server currently fails the default rule set at HIGH. */
    public static ServerFingerprint capture(String serverName, List<ToolDefinition> tools) {
        return capture(serverName, tools, MetadataScanner.withDefaultRules(), DEFAULT_GATE);
    }

    /**
     * Captures a baseline for {@code serverName}, gated by a scan of the tools being recorded.
     *
     * <p>The whole capture is refused, not just the offending tools. Recording the clean ones
     * and dropping the rest would produce a baseline that silently omits the tool a reader most
     * needs to know about, and every later scan would report that tool as newly appeared —
     * drift, from a server that never changed. If a finding is understood and accepted, say so
     * where it can be reviewed: suppress the rule id on the gating scanner, or raise the gate.
     *
     * @param gateScanner the scan capture must pass; pass a configured {@link MetadataScanner}
     *                    to suppress rules that have been triaged
     * @throws UntrustedBaselineException if the server does not pass
     */
    public static ServerFingerprint capture(String serverName, List<ToolDefinition> tools,
                                            McpSecurityScanner gateScanner, Severity gate) {
        Objects.requireNonNull(serverName, "serverName");
        Objects.requireNonNull(gateScanner, "gateScanner");
        Objects.requireNonNull(gate, "gate");
        if (serverName.isBlank()) {
            throw new IllegalArgumentException("A baseline must name the server it belongs to");
        }

        List<ToolDefinition> owned = tools == null ? List.of()
                : tools.stream().filter(t -> serverName.equals(t.serverName())).toList();
        if (owned.isEmpty()) {
            // Capturing an empty baseline would "pass" forever while checking nothing, and the
            // usual cause is a server-name typo rather than a server with no tools.
            throw new IllegalArgumentException("No tools from server '" + serverName + "' to baseline."
                    + " A baseline of nothing would compare against nothing on every later scan.");
        }

        ScanReport gateReport = gateScanner.scan(owned);
        if (gateReport.hasFindingsAtOrAbove(gate)) {
            throw new UntrustedBaselineException(serverName, gate, gateReport);
        }

        return new ServerFingerprint(serverName, Instant.now(),
                owned.stream().map(ToolFingerprint::of).toList());
    }

    /** Writes the baseline, creating parent directories. Overwrites, so the diff is the review. */
    public static void write(ServerFingerprint fingerprint, Path file) {
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(file, "file");
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(file, BaselineFormat.render(fingerprint), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write the MCP baseline to " + file, e);
        }
    }

    public static ServerFingerprint read(Path file) {
        Objects.requireNonNull(file, "file");
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the MCP baseline at " + file
                    + ". Capture one with Baseline.capture(...) and commit it.", e);
        }
        return BaselineFormat.parse(content, file.toString());
    }
}
