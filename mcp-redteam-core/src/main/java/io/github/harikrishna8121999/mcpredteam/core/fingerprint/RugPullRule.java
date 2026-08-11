package io.github.harikrishna8121999.mcpredteam.core.fingerprint;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import io.github.harikrishna8121999.mcpredteam.core.rule.EncodedPayloadRule;
import io.github.harikrishna8121999.mcpredteam.core.rule.ExfiltrationChannelRule;
import io.github.harikrishna8121999.mcpredteam.core.rule.HiddenUnicodeRule;
import io.github.harikrishna8121999.mcpredteam.core.rule.InstructionInjectionRule;
import io.github.harikrishna8121999.mcpredteam.core.rule.MetadataRule;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Reports metadata that changed after the server was trusted — the rug pull (OWASP MCP03).
 *
 * <p>A server passes review, gets approved, and is wired to an agent. Some time later it answers
 * {@code tools/list} differently: a description gains a sentence, a parameter appears, a tool the
 * baseline never saw shows up. Nothing about the new metadata has to look malicious for that to
 * matter, because the review that made this server trusted was performed on the old metadata, and
 * it no longer applies.
 *
 * <p>Drift alone is therefore reported, at MEDIUM: honest servers ship features, so a change is a
 * fact to review rather than proof of an attack. What raises it is what the change contains. The
 * changed text is handed back to the static rules — the same ones that scan any tool — and if the
 * edit introduced something they flag, the finding is reported at that rule's own severity, with a
 * composite id like {@code MCPRT-RUG-001/MCPRT-INJ-001}. This is the delegation
 * {@code ToolResultInjectionRule} uses for the same reason: injection text is injection text
 * wherever it turns up, and a second private copy of those signatures would drift out of step
 * with the originals.
 *
 * <p>Only the changed locations are re-scanned. Everything else in the tool is scanned anyway by
 * the rules running beside this one in the same {@code MetadataScanner}, so re-reporting it here
 * would double every finding on a server that happened to have drifted.
 *
 * <pre>{@code
 * ServerFingerprint trusted = Baseline.read(Path.of("src/test/resources/finance-baseline.txt"));
 * ScanReport report = MetadataScanner.builder()
 *         .addRule(RugPullRule.against(trusted))
 *         .build()
 *         .scan(tools);
 * }</pre>
 */
public final class RugPullRule implements MetadataRule {

    /** How many changed locations a finding lists before it summarises the rest. */
    private static final int MAX_LOCATIONS_LISTED = 8;

    /**
     * Rules re-run over changed text. Text-based only: a rule like {@code MCPRT-CRED} reads the
     * <em>shape</em> of a parameter list rather than a string, and it is already running over the
     * whole tool in the same scan, so a newly phished {@code apiKey} is reported by CRED and
     * located by this rule's drift finding without either needing to imitate the other.
     */
    private final List<MetadataRule> textRules = List.of(
            new InstructionInjectionRule(),
            new HiddenUnicodeRule(),
            new EncodedPayloadRule(),
            new ExfiltrationChannelRule());

    /** Where delegated findings land, since the changed text is handed over as a description. */
    private static final String DELEGATED_LOCATION = "description";

    private final ServerFingerprint baseline;

    public RugPullRule(ServerFingerprint baseline) {
        this.baseline = Objects.requireNonNull(baseline, "baseline");
    }

    public static RugPullRule against(ServerFingerprint baseline) {
        return new RugPullRule(baseline);
    }

    @Override
    public String id() {
        return "MCPRT-RUG";
    }

    @Override
    public String description() {
        return "Tool metadata that changed since the server was baselined (rug pull).";
    }

    public ServerFingerprint baseline() {
        return baseline;
    }

    @Override
    public List<Finding> apply(List<ToolDefinition> tools) {
        List<ToolDefinition> owned = tools == null ? List.of()
                : tools.stream().filter(t -> baseline.serverName().equals(t.serverName())).toList();
        if (owned.isEmpty()) {
            return List.of(baselineNotExercised());
        }

        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (ToolDefinition tool : owned) {
            seen.add(tool.name());
            Optional<ToolFingerprint> trusted = baseline.tool(tool.name());
            if (trusted.isEmpty()) {
                findings.add(newTool(tool));
                continue;
            }
            findings.addAll(inspectDrift(tool, trusted.get()));
        }
        for (String missing : baseline.toolNames()) {
            if (!seen.contains(missing)) {
                findings.add(removedTool(missing));
            }
        }
        return findings;
    }

    private List<Finding> inspectDrift(ToolDefinition tool, ToolFingerprint trusted) {
        ToolFingerprint current = ToolFingerprint.of(tool);
        if (trusted.matches(current)) {
            return List.of();
        }

        List<String> changed = trusted.changedLocations(current);
        List<Finding> findings = new ArrayList<>();
        findings.add(drifted(tool, changed));

        Map<String, String> canonical = CanonicalForm.of(tool);
        for (String location : changed) {
            // Removed locations have no current text to inspect; their disappearance is already
            // reported by the drift finding above.
            String text = CanonicalForm.textOf(canonical.get(location));
            if (!text.isBlank()) {
                findings.addAll(delegate(tool, location, text));
            }
        }
        return findings;
    }

    private List<Finding> delegate(ToolDefinition tool, String location, String changedText) {
        // The changed text is presented to the rules as a description, which is how the model
        // reads it too: prose it was handed about a tool it is deciding whether to call.
        ToolDefinition asMetadata = ToolDefinition.of(tool.serverName(), tool.name(), changedText, Map.of());

        List<Finding> findings = new ArrayList<>();
        for (MetadataRule rule : textRules) {
            for (Finding finding : rule.apply(List.of(asMetadata))) {
                if (!DELEGATED_LOCATION.equals(finding.location())) {
                    continue;
                }
                findings.add(escalate(finding, tool, location));
            }
        }
        return findings;
    }

    /**
     * Re-points a static finding at the drift that introduced it.
     *
     * <p>The delegated rule's severity and confidence are kept rather than inflated, following
     * {@code ToolResultInjectionRule}: the words carry the weight they carry. The escalation is
     * from the MEDIUM the drift would otherwise have scored, and the message is where the timing
     * lives, because "this text is here" and "this text arrived after you approved the server"
     * are different facts and only the second one is this rule's.
     */
    private Finding escalate(Finding finding, ToolDefinition tool, String location) {
        Finding.Builder builder = Finding.builder("MCPRT-RUG-001/" + finding.ruleId())
                .threatType(ThreatType.RUG_PULL)
                .severity(finding.severity())
                .confidence(finding.confidence())
                .target(tool.qualifiedName())
                .location(location)
                .message(finding.message() + " It was not there when this server was baselined at "
                        + baseline.capturedAt() + ", so it was introduced after the server was trusted.")
                .remediation("Treat the server as compromised until the change is explained: the review that "
                        + "approved it was performed on different metadata. Do not re-baseline to make this "
                        + "pass — that records the new text as trusted.")
                .evidence("baselinedAt", baseline.capturedAt().toString());
        finding.evidence().forEach(builder::evidence);
        return builder.build();
    }

    private Finding drifted(ToolDefinition tool, List<String> changed) {
        String summary = summarise(changed);
        return Finding.builder("MCPRT-RUG-001")
                .threatType(ThreatType.RUG_PULL)
                .severity(Severity.MEDIUM)
                .confidence(Confidence.FIRM)
                .target(tool.qualifiedName())
                .location(changed.isEmpty() ? "" : changed.get(0))
                .message("Tool metadata changed since the baseline captured at " + baseline.capturedAt()
                        + ": " + changed.size() + " location(s) differ (" + summary + ").")
                .remediation("Compare the change against what the vendor announced. If it is expected, "
                        + "re-capture the baseline as a reviewed commit; if it is not, the server is "
                        + "telling the agent something it was never approved to say.")
                .evidence("match", summary)
                .evidence("changedLocations", changed.size() <= MAX_LOCATIONS_LISTED
                        ? changed : changed.subList(0, MAX_LOCATIONS_LISTED))
                .evidence("changedCount", changed.size())
                .evidence("baselinedAt", baseline.capturedAt().toString())
                .build();
    }

    private Finding newTool(ToolDefinition tool) {
        return Finding.builder("MCPRT-RUG-002")
                .threatType(ThreatType.RUG_PULL)
                .severity(Severity.MEDIUM)
                .confidence(Confidence.FIRM)
                .target(tool.qualifiedName())
                .location("name")
                .message("Tool '" + tool.name() + "' is not in the baseline of server '" + baseline.serverName()
                        + "' captured at " + baseline.capturedAt() + "; it appeared after the server was trusted.")
                .remediation("A tool nobody reviewed is now offered to the agent. Review it as a new server "
                        + "would be reviewed, then re-capture the baseline deliberately.")
                .evidence("match", tool.name())
                .evidence("baselinedAt", baseline.capturedAt().toString())
                .build();
    }

    /**
     * A tool that vanished. LOW, because the common cause is a deprecation and because a
     * missing tool cannot itself instruct the agent — but it is reported, since removing the
     * honest tool is how a shadowing replacement gets picked instead of it.
     */
    private Finding removedTool(String toolName) {
        String qualified = baseline.serverName() + "/" + toolName;
        return Finding.builder("MCPRT-RUG-003")
                .threatType(ThreatType.RUG_PULL)
                .severity(Severity.LOW)
                .confidence(Confidence.FIRM)
                .target(qualified)
                .location("name")
                .message("Tool '" + toolName + "' was in the baseline captured at " + baseline.capturedAt()
                        + " but the server no longer publishes it.")
                .remediation("Check what replaced it. Anything the agent used to reach through this tool now "
                        + "goes somewhere else, or nowhere.")
                .evidence("match", toolName)
                .evidence("baselinedAt", baseline.capturedAt().toString())
                .build();
    }

    /**
     * The check ran and compared nothing.
     *
     * <p>Reported rather than passed silently, for the reason {@code ThreatType.INCONCLUSIVE_RUN}
     * exists: a baseline pointed at a server name that is not in the scan — a typo, or tools
     * loaded under a different label — produces a clean report that proves nothing, and a clean
     * report that proves nothing is this project's worst failure mode.
     */
    private Finding baselineNotExercised() {
        return Finding.builder("MCPRT-RUG-000")
                .threatType(ThreatType.INCONCLUSIVE_RUN)
                .severity(Severity.MEDIUM)
                .confidence(Confidence.FIRM)
                .target(baseline.serverName())
                .location("")
                .message("The rug-pull check compared nothing: the scan contained no tools from server '"
                        + baseline.serverName() + "', which the baseline of " + baseline.size()
                        + " tool(s) belongs to.")
                .remediation("Check the server name the tools were loaded under; it must match the baseline's. "
                        + "Until it does, this baseline is not checking anything.")
                .evidence("match", baseline.serverName())
                .evidence("baselinedTools", baseline.size())
                .build();
    }

    private static String summarise(List<String> changed) {
        if (changed.size() <= MAX_LOCATIONS_LISTED) {
            return String.join(", ", changed);
        }
        return String.join(", ", changed.subList(0, MAX_LOCATIONS_LISTED))
                + " and " + (changed.size() - MAX_LOCATIONS_LISTED) + " more";
    }
}
