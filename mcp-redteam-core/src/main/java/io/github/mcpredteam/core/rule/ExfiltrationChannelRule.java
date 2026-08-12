package io.github.mcpredteam.core.rule;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.TextNormalizer;
import io.github.mcpredteam.core.ThreatType;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects the outbound half of a data-theft chain: somewhere for stolen context to go,
 * and references to the local secrets worth stealing.
 */
public final class ExfiltrationChannelRule extends PerToolRule {

    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

    /** A URL reachable off-host, paired with a verb that moves data to it. */
    private static final Pattern SEND_TO_URL = Pattern.compile(
            "\\b(?:send|post|forward|upload|transmit|report|beacon|exfiltrate|deliver|copy)\\b"
                    + ".{0,60}?(https?://[^\\s\"'<>)\\]]+)", FLAGS);

    /** Parameter names whose purpose is to receive a caller-supplied destination. */
    private static final Pattern SINK_PARAM_NAME = Pattern.compile(
            "^(?:webhook|callback|notify|notification|forward|report|telemetry|beacon|exfil|relay|proxy)"
                    + "[_-]?(?:url|uri|endpoint|host|address|target)$", Pattern.CASE_INSENSITIVE);

    private static final Pattern SENSITIVE_PATH = Pattern.compile(
            "(?:~/\\.ssh|/etc/(?:passwd|shadow)|\\bid_rsa\\b|\\.aws/credentials|\\.env\\b"
                    + "|\\.git-credentials|/proc/self/environ|\\bkubeconfig\\b|\\.npmrc\\b)", FLAGS);

    @Override
    public String id() {
        return "MCPRT-EXF";
    }

    @Override
    public String description() {
        return "Outbound data sinks and sensitive local paths referenced in tool metadata.";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();

        forEachText(tool, (location, raw) -> {
            String normalized = TextNormalizer.normalize(raw);

            Matcher sendTo = SEND_TO_URL.matcher(normalized);
            if (sendTo.find()) {
                findings.add(Finding.builder("MCPRT-EXF-001")
                        .threatType(ThreatType.EXFILTRATION_CHANNEL)
                        .severity(Severity.HIGH)
                        .confidence(Confidence.FIRM)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Tool metadata instructs the agent to send data to a hard-coded external URL.")
                        .remediation("Tool metadata should describe behaviour, not direct network egress. "
                                + "Verify the destination and remove the directive.")
                        .evidence("match", sendTo.group())
                        .evidence("url", sendTo.group(1))
                        .build());
            }

            Matcher sensitive = SENSITIVE_PATH.matcher(normalized);
            if (sensitive.find()) {
                findings.add(Finding.builder("MCPRT-EXF-003")
                        .threatType(ThreatType.EXFILTRATION_CHANNEL)
                        .severity(Severity.HIGH)
                        .confidence(Confidence.FIRM)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Tool metadata references a sensitive local credential path: " + sensitive.group() + ".")
                        .remediation("A tool that legitimately needs credentials should take them as an explicit, "
                                + "documented parameter rather than naming on-disk secret locations to the agent.")
                        .evidence("match", sensitive.group())
                        .build());
            }
        });

        forEachFieldName(tool, (location, name) -> {
            if (SINK_PARAM_NAME.matcher(name).matches()) {
                findings.add(Finding.builder("MCPRT-EXF-002")
                        .threatType(ThreatType.EXFILTRATION_CHANNEL)
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.TENTATIVE)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Parameter '" + name + "' accepts a caller-controlled destination, which can be "
                                + "steered into an exfiltration channel.")
                        .remediation("Constrain the destination to an allow-list rather than accepting an arbitrary URL.")
                        .evidence("match", name)
                        .build());
            }
        });

        return findings;
    }
}
