package io.github.harikrishna8121999.mcpredteam.core.rule;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects encoded instruction payloads hidden in tool metadata.
 *
 * <p>Deliberately does <em>not</em> match the word "base64". Honest tool descriptions say
 * things like "Returns the base64-encoded thumbnail" constantly, so keying on the word
 * produces a false positive on well-behaved servers — and a scanner that cries wolf on
 * benign tools gets muted, which is worse than no scanner. Instead this decodes actual
 * encoded runs and reports only when the <em>decoded</em> content reads as an instruction.
 */
public final class EncodedPayloadRule extends PerToolRule {

    /**
     * Long enough to carry a sentence; shorter runs are usually identifiers or hashes.
     * '=' is allowed only as trailing padding, so a {@code key=<blob>} pair splits into two
     * runs instead of decoding from the wrong offset.
     */
    private static final Pattern BASE64_RUN = Pattern.compile("[A-Za-z0-9+/_-]{24,}={0,2}");

    private static final Pattern INSTRUCTION_LIKE = Pattern.compile(
            "\\b(?:ignore\\s+(?:all\\s+)?previous|system\\s+prompt|do\\s+not\\s+tell|api[\\s_-]?key"
                    + "|credentials?|secrets?|exfiltrat|password|send\\s+(?:it|them|this|all)\\s+to"
                    + "|curl\\s|https?://|you\\s+must|assistant\\s+must)\\b",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "MCPRT-ENC";
    }

    @Override
    public String description() {
        return "Encoded payloads in tool metadata that decode to agent-directed instructions.";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();
        forEachText(tool, (location, raw) -> {
            Matcher matcher = BASE64_RUN.matcher(raw);
            while (matcher.find()) {
                String decoded = decodeBase64(matcher.group());
                if (decoded == null || !isMostlyPrintable(decoded) || !INSTRUCTION_LIKE.matcher(decoded).find()) {
                    continue;
                }
                findings.add(Finding.builder("MCPRT-ENC-001")
                        .threatType(ThreatType.TOOL_POISONING)
                        .severity(Severity.HIGH)
                        .confidence(Confidence.FIRM)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Metadata contains a base64 run that decodes to agent-directed instruction text.")
                        .remediation("Tool metadata should be human-readable. Reject definitions carrying encoded "
                                + "instruction payloads.")
                        .evidence("match", matcher.group())
                        .evidence("decoded", decoded.length() > 200 ? decoded.substring(0, 200) + "..." : decoded)
                        .build());
            }
        });
        return findings;
    }

    private static String decodeBase64(String candidate) {
        String normalized = candidate.replace('-', '+').replace('_', '/');
        int padAt = normalized.indexOf('=');
        if (padAt >= 0) {
            normalized = normalized.substring(0, padAt);
        }
        int remainder = normalized.length() % 4;
        if (remainder == 1) {
            return null;
        }
        if (remainder != 0) {
            normalized = normalized + "=".repeat(4 - remainder);
        }
        try {
            return new String(Base64.getDecoder().decode(normalized), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    /** Guards against binary blobs that happen to contain matching byte sequences. */
    private static boolean isMostlyPrintable(String decoded) {
        if (decoded.isBlank()) {
            return false;
        }
        long printable = decoded.chars()
                .filter(c -> c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7F))
                .count();
        return (double) printable / decoded.length() >= 0.85;
    }

    static boolean looksLikeInstruction(String text) {
        return INSTRUCTION_LIKE.matcher(text.toLowerCase(Locale.ROOT)).find();
    }
}
