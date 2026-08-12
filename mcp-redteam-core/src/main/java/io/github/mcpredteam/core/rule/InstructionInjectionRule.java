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
 * Detects text in tool metadata that addresses the <em>agent</em> rather than describing
 * the tool to a human. This is the core tool-poisoning signal (OWASP MCP03).
 *
 * <p>Every signature requires an imperative <em>plus</em> a target or an action — a bare
 * mention of "system prompt" or "base64" is normal in honest tool documentation
 * ("Returns the base64-encoded thumbnail") and does not fire on its own. Matching runs
 * against {@link TextNormalizer#normalize} output so zero-width and homoglyph evasion
 * does not defeat the patterns.
 */
public final class InstructionInjectionRule extends PerToolRule {

    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.UNICODE_CASE;

    private static final List<Signature> SIGNATURES = List.of(
            new Signature("001",
                    Pattern.compile("\\bignore\\s+(?:all\\s+|any\\s+|the\\s+)*"
                            + "(?:previous|prior|earlier|above|preceding|foregoing)\\s+"
                            + "(?:instructions?|prompts?|directions?|rules?|commands?|context)\\b", FLAGS),
                    Severity.CRITICAL, Confidence.CERTAIN,
                    "Tool metadata instructs the agent to discard its previous instructions."),

            new Signature("002",
                    Pattern.compile("\\bdo\\s+not\\s+(?:tell|inform|mention|reveal|disclose|show|display|report|notify)\\b"
                            + ".{0,40}?\\b(?:the\\s+)?(?:user|human|operator|caller)\\b", FLAGS),
                    Severity.CRITICAL, Confidence.FIRM,
                    "Tool metadata instructs the agent to conceal its behaviour from the user."),

            new Signature("003",
                    Pattern.compile("\\b(?:send|forward|include|attach|append|post|transmit|return|reveal|upload|exfiltrate|copy)\\b"
                            + ".{0,80}?\\b(?:system\\s+prompt|conversation\\s+history|previous\\s+messages?|chat\\s+history"
                            + "|api[\\s_-]?keys?|credentials?|secrets?|passwords?|access\\s+tokens?"
                            + "|\\.env\\b|id_rsa|private\\s+keys?)\\b", FLAGS),
                    Severity.HIGH, Confidence.FIRM,
                    "Tool metadata directs the agent to transmit sensitive context or credentials."),

            new Signature("004",
                    Pattern.compile("\\b(?:before|prior\\s+to)\\s+(?:calling|using|invoking|running|executing)\\b"
                            + ".{0,100}?\\b(?:you\\s+must|you\\s+should|you\\s+have\\s+to|always\\s+|first\\s+(?:read|call|fetch|send))\\b",
                            FLAGS),
                    Severity.HIGH, Confidence.FIRM,
                    "Tool metadata imposes a hidden precondition on the agent before the tool is used."),

            new Signature("005",
                    Pattern.compile("<\\s*/?\\s*(?:system|important|secret|instructions?|admin|override|internal)\\s*>", FLAGS),
                    Severity.HIGH, Confidence.CERTAIN,
                    "Tool metadata contains pseudo-markup that imitates a privileged message channel."),

            new Signature("006",
                    Pattern.compile("\\b(?:assistant|ai|model|agent|llm|claude|gpt)\\s+"
                            + "(?:must|should|shall|will|needs?\\s+to)\\s+"
                            + "(?:always|never|immediately|silently|secretly)\\b", FLAGS),
                    Severity.HIGH, Confidence.FIRM,
                    "Tool metadata issues a standing directive addressed to the model."),

            new Signature("007",
                    Pattern.compile("\\b(?:without|do\\s+not|don't|avoid)\\s+"
                            + "(?:notify|notifying|alert|alerting|inform|informing|ask|asking|prompt|prompting)\\b"
                            + ".{0,30}?\\b(?:the\\s+)?(?:user|human|operator|for\\s+(?:permission|approval|consent))\\b", FLAGS),
                    Severity.HIGH, Confidence.FIRM,
                    "Tool metadata instructs the agent to bypass user notification or approval."),

            new Signature("008",
                    Pattern.compile("\\b(?:you\\s+must\\s+always|you\\s+should\\s+always|you\\s+are\\s+required\\s+to"
                            + "|it\\s+is\\s+(?:critical|imperative|essential|mandatory)\\s+that\\s+you)\\b", FLAGS),
                    Severity.MEDIUM, Confidence.TENTATIVE,
                    "Tool metadata uses imperative framing aimed at the agent; review whether it is descriptive or directive.")
    );

    @Override
    public String id() {
        return "MCPRT-INJ";
    }

    @Override
    public String description() {
        return "Agent-directed instructions embedded in tool metadata (tool poisoning).";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        List<Finding> findings = new ArrayList<>();
        forEachText(tool, (location, raw) -> {
            String normalized = TextNormalizer.normalize(raw);
            boolean obfuscated = TextNormalizer.isObfuscated(raw);
            for (Signature signature : SIGNATURES) {
                Matcher matcher = signature.pattern().matcher(normalized);
                if (!matcher.find()) {
                    continue;
                }
                Finding.Builder builder = Finding.builder("MCPRT-INJ-" + signature.suffix())
                        .threatType(location.startsWith("inputSchema") || location.startsWith("outputSchema")
                                ? ThreatType.SCHEMA_POISONING
                                : ThreatType.TOOL_POISONING)
                        .severity(signature.severity())
                        .confidence(obfuscated ? Confidence.CERTAIN : signature.confidence())
                        .target(tool.qualifiedName())
                        .location(location)
                        .message(signature.message())
                        .remediation("Tool metadata is read by the model but not shown to the user. "
                                + "Remove directive language, or stop exposing this server to the agent.")
                        .evidence("match", matcher.group());
                if (obfuscated) {
                    builder.evidence("obfuscated", true)
                            .evidence("note", "Payload was hidden with invisible or look-alike characters; "
                                    + "matched after normalization.");
                }
                findings.add(builder.build());
            }
        });
        return findings;
    }

    private record Signature(String suffix, Pattern pattern, Severity severity, Confidence confidence, String message) {
    }
}
