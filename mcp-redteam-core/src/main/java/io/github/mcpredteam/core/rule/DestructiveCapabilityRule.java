package io.github.mcpredteam.core.rule;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ThreatType;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Flags tools whose name implies an irreversible action but which do not declare the MCP
 * {@code destructiveHint} annotation.
 *
 * <p>Scoped to undeclared capability rather than destructiveness itself: a {@code delete_file}
 * tool is perfectly legitimate, but a client cannot apply a confirmation policy to it if the
 * server never says it is destructive. A tool that declares the hint produces no finding, so
 * the rule is actionable — the fix is to add the annotation.
 */
public final class DestructiveCapabilityRule extends PerToolRule {

    private static final Pattern DESTRUCTIVE_NAME = Pattern.compile(
            "\\b(?:delete|destroy|drop|truncate|wipe|purge|erase|remove|revoke|terminate|kill"
                    // Separators are folded to spaces before matching, so allow whitespace here too.
                    + "|shutdown|reset|overwrite|force[\\s_-]?push|exec|eval|shell|spawn|sudo)\\b",
            Pattern.CASE_INSENSITIVE);

    private static final String DESTRUCTIVE_HINT = "destructiveHint";
    private static final String READ_ONLY_HINT = "readOnlyHint";

    @Override
    public String id() {
        return "MCPRT-CAP";
    }

    @Override
    public String description() {
        return "Destructive-sounding tools that do not declare MCP capability annotations.";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        String separated = tool.name().replaceAll("[_\\-.]", " ");
        if (!DESTRUCTIVE_NAME.matcher(separated).find()) {
            return List.of();
        }
        if (tool.hasAnnotation(DESTRUCTIVE_HINT) || tool.annotationIsTrue(READ_ONLY_HINT)) {
            return List.of();
        }
        return List.of(Finding.builder("MCPRT-CAP-001")
                .threatType(ThreatType.OVERBROAD_CAPABILITY)
                .severity(Severity.MEDIUM)
                .confidence(Confidence.TENTATIVE)
                .target(tool.qualifiedName())
                .location("name")
                .message("Tool name implies an irreversible action but no '" + DESTRUCTIVE_HINT
                        + "' annotation is declared, so clients cannot gate it behind confirmation.")
                .remediation("Declare destructiveHint/readOnlyHint on this tool so hosts can apply an approval policy.")
                .evidence("match", tool.name())
                .build());
    }
}
