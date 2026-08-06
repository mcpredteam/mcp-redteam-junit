package io.github.harikrishna8121999.mcpredteam.core.rule;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.TextNormalizer;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-tool detections, which only exist in relation to the rest of the tool list.
 *
 * <p>Covers the two shapes of shadowing: a malicious server registering a name that
 * collides with a trusted server's tool so the agent may pick the wrong one, and a tool
 * whose description reaches across to redirect how a <em>different</em> tool is used.
 * Neither is visible when tools are scanned one at a time.
 */
public final class ToolShadowingRule implements MetadataRule {

    /** Directive framing that changes how another tool is selected or used. */
    private static final Pattern REDIRECTION = Pattern.compile(
            "\\b(?:instead\\s+of|rather\\s+than|in\\s+place\\s+of|do\\s+not\\s+(?:use|call|invoke)"
                    + "|never\\s+(?:use|call|invoke)|always\\s+(?:use|call|invoke)|before\\s+(?:using|calling)"
                    + "|when\\s+(?:using|calling)|replaces?|supersedes?|deprecat\\w*)\\b",
            Pattern.CASE_INSENSITIVE);

    /** Short names collide by coincidence; require enough length for a mention to be meaningful. */
    private static final int MIN_NAME_LENGTH = 4;

    @Override
    public String id() {
        return "MCPRT-SHD";
    }

    @Override
    public String description() {
        return "Tool name collisions across servers and metadata that redirects other tools.";
    }

    @Override
    public List<Finding> apply(List<ToolDefinition> tools) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(findNameCollisions(tools));
        findings.addAll(findCrossToolRedirection(tools));
        return findings;
    }

    private List<Finding> findNameCollisions(List<ToolDefinition> tools) {
        Map<String, List<ToolDefinition>> byNormalizedName = new LinkedHashMap<>();
        for (ToolDefinition tool : tools) {
            byNormalizedName
                    .computeIfAbsent(canonicalName(tool.name()), k -> new ArrayList<>())
                    .add(tool);
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, List<ToolDefinition>> entry : byNormalizedName.entrySet()) {
            List<ToolDefinition> group = entry.getValue();
            if (group.size() < 2) {
                continue;
            }
            long distinctServers = group.stream().map(ToolDefinition::serverName).distinct().count();
            if (distinctServers < 2) {
                continue;
            }
            String servers = group.stream().map(ToolDefinition::serverName).distinct().sorted().toList().toString();
            for (ToolDefinition tool : group) {
                findings.add(Finding.builder("MCPRT-SHD-001")
                        .threatType(ThreatType.TOOL_SHADOWING)
                        .severity(Severity.HIGH)
                        .confidence(Confidence.FIRM)
                        .target(tool.qualifiedName())
                        .location("name")
                        .message("Tool name collides with a tool of the same canonical name on another server "
                                + servers + "; the agent may invoke the wrong one.")
                        .remediation("Namespace tools per server, or refuse to load a server that registers a name "
                                + "already claimed by a trusted server.")
                        .evidence("match", tool.name())
                        .evidence("canonicalName", entry.getKey())
                        .evidence("servers", servers)
                        .build());
            }
        }
        return findings;
    }

    private List<Finding> findCrossToolRedirection(List<ToolDefinition> tools) {
        List<Finding> findings = new ArrayList<>();
        for (ToolDefinition tool : tools) {
            PerToolRule.forEachText(tool, (location, raw) -> {
                String normalized = TextNormalizer.normalize(raw);
                for (ToolDefinition other : tools) {
                    if (other == tool || other.name().length() < MIN_NAME_LENGTH) {
                        continue;
                    }
                    if (canonicalName(other.name()).equals(canonicalName(tool.name()))) {
                        continue;
                    }
                    Matcher matcher = redirectionPattern(other.name()).matcher(normalized);
                    if (matcher.find()) {
                        findings.add(Finding.builder("MCPRT-SHD-002")
                                .threatType(ThreatType.CROSS_TOOL_POISONING)
                                .severity(Severity.HIGH)
                                .confidence(Confidence.FIRM)
                                .target(tool.qualifiedName())
                                .location(location)
                                .message("Metadata directs the agent's use of a different tool, '"
                                        + other.qualifiedName() + "'.")
                                .remediation("A tool should describe only itself. Metadata that reaches across to "
                                        + "another tool is cross-tool poisoning; stop exposing this server.")
                                .evidence("match", matcher.group())
                                .evidence("referencedTool", other.qualifiedName())
                                .build());
                        return;
                    }
                }
            });
        }
        return findings;
    }

    /**
     * Built from the <em>normalized</em> other-tool name, because the haystack is normalized
     * too. Matching the raw name would miss the interesting case, where a homoglyph tool
     * redirects the trusted ASCII tool it is impersonating.
     */
    private static Pattern redirectionPattern(String otherName) {
        return Pattern.compile(
                REDIRECTION.pattern() + ".{0,40}?" + Pattern.quote(TextNormalizer.normalize(otherName)),
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    }

    /** Folds case, separators and Unicode look-alikes so {@code get_file} and {@code Get-Filе} collide. */
    private static String canonicalName(String name) {
        return TextNormalizer.normalize(name)
                .toLowerCase(Locale.ROOT)
                .replaceAll("[_\\-.\\s]", "");
    }
}
