package io.github.harikrishna8121999.mcpredteam.core.rule;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.TextNormalizer;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects characters that render as nothing (or as something else) but are still read by
 * the model: zero-width joiners, bidirectional overrides, Unicode tag characters, and
 * Latin look-alikes from other scripts.
 *
 * <p>These carry the highest confidence in the rule set. There is no legitimate reason for a
 * tool description to contain a zero-width space, so a match is evidence of deliberate
 * concealment rather than sloppy documentation.
 */
public final class HiddenUnicodeRule extends PerToolRule {

    private static final Pattern INVISIBLE = Pattern.compile(TextNormalizer.invisibleCharPattern());
    private static final Pattern TAG_CHARS = Pattern.compile(TextNormalizer.tagCharPattern());
    private static final Pattern NON_ASCII = Pattern.compile("[^\\p{ASCII}]");

    @Override
    public String id() {
        return "MCPRT-UNI";
    }

    @Override
    public String description() {
        return "Invisible control characters and homoglyph look-alikes in tool metadata.";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();

        forEachText(tool, (location, raw) -> {
            Matcher tags = TAG_CHARS.matcher(raw);
            if (tags.find()) {
                findings.add(Finding.builder("MCPRT-UNI-001")
                        .threatType(ThreatType.TOOL_POISONING)
                        .severity(Severity.CRITICAL)
                        .confidence(Confidence.CERTAIN)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Metadata contains Unicode tag characters (U+E0000 block), which are invisible "
                                + "when rendered but are tokenized by the model.")
                        .remediation("Reject this tool definition. Tag characters have no legitimate use in tool metadata.")
                        .evidence("match", describeCodePoints(raw))
                        .evidence("field", location)
                        .build());
            }

            Matcher invisible = INVISIBLE.matcher(raw);
            if (invisible.find()) {
                findings.add(Finding.builder("MCPRT-UNI-002")
                        .threatType(ThreatType.TOOL_POISONING)
                        .severity(Severity.HIGH)
                        .confidence(Confidence.CERTAIN)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Metadata contains zero-width or bidirectional control characters, which can hide "
                                + "instructions from a human reviewer and break naive pattern matching.")
                        .remediation("Strip invisible characters from tool metadata, or treat the server as untrusted.")
                        .evidence("match", describeCodePoints(raw))
                        .build());
            }
        });

        if (NON_ASCII.matcher(tool.name()).find()) {
            String folded = TextNormalizer.normalize(tool.name());
            findings.add(Finding.builder("MCPRT-UNI-003")
                    .threatType(ThreatType.TOOL_SHADOWING)
                    .severity(Severity.HIGH)
                    .confidence(Confidence.FIRM)
                    .target(tool.qualifiedName())
                    .location("name")
                    .message("Tool name contains non-ASCII characters that may impersonate another tool. "
                            + "It normalizes to '" + folded + "'.")
                    .remediation("Require ASCII tool names, and compare incoming names against trusted tools "
                            + "after Unicode normalization.")
                    .evidence("match", tool.name())
                    .evidence("normalized", folded)
                    .build());
        }

        return findings;
    }

    private static String describeCodePoints(String text) {
        StringBuilder sb = new StringBuilder();
        text.codePoints()
                .filter(cp -> !Character.isLetterOrDigit(cp) && !Character.isWhitespace(cp) && cp > 127)
                .distinct()
                .limit(8)
                .forEach(cp -> sb.append(String.format("U+%04X ", cp)));
        return sb.toString().trim();
    }
}
