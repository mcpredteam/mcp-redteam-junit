package io.github.mcpredteam.core;

import io.github.mcpredteam.core.rule.CredentialParameterRule;
import io.github.mcpredteam.core.rule.DestructiveCapabilityRule;
import io.github.mcpredteam.core.rule.EncodedPayloadRule;
import io.github.mcpredteam.core.rule.ExfiltrationChannelRule;
import io.github.mcpredteam.core.rule.HiddenUnicodeRule;
import io.github.mcpredteam.core.rule.InstructionInjectionRule;
import io.github.mcpredteam.core.rule.MetadataRule;
import io.github.mcpredteam.core.rule.ToolShadowingRule;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Static scan of MCP tool metadata.
 *
 * <p>This is table stakes, not the differentiator: several tools already scan MCP metadata
 * well. It runs with no LLM and no network, so it is the cheap first gate — but a clean
 * report here says only that nothing <em>looked</em> malicious, not that a real agent
 * resists the server. That question needs a dynamic agent-in-the-loop test.
 */
public final class MetadataScanner implements McpSecurityScanner {

    private final List<MetadataRule> rules;
    private final Set<String> suppressedRuleIds;

    private MetadataScanner(List<MetadataRule> rules, Set<String> suppressedRuleIds) {
        this.rules = List.copyOf(rules);
        this.suppressedRuleIds = Set.copyOf(suppressedRuleIds);
    }

    /** The full default rule set. */
    public static MetadataScanner withDefaultRules() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static List<MetadataRule> defaultRules() {
        return List.of(
                new InstructionInjectionRule(),
                new HiddenUnicodeRule(),
                new EncodedPayloadRule(),
                new ExfiltrationChannelRule(),
                new CredentialParameterRule(),
                new ToolShadowingRule(),
                new DestructiveCapabilityRule());
    }

    public List<MetadataRule> rules() {
        return rules;
    }

    @Override
    public ScanReport scan(List<ToolDefinition> tools) {
        Instant started = Instant.now();
        List<ToolDefinition> safeTools = tools == null ? List.of() : tools;

        Map<String, Finding> deduped = new LinkedHashMap<>();
        for (MetadataRule rule : rules) {
            for (Finding finding : rule.apply(safeTools)) {
                if (isSuppressed(finding.ruleId())) {
                    continue;
                }
                deduped.putIfAbsent(finding.dedupeKey(), finding);
            }
        }

        return new ScanReport(started, Instant.now(), safeTools.size(), new ArrayList<>(deduped.values()));
    }

    /**
     * Matches either an exact rule id ({@code MCPRT-INJ-008}) or a rule family
     * ({@code MCPRT-INJ}).
     *
     * <p>A family matches only on a {@code -} boundary. Plain prefix matching meant
     * {@code suppress("M")} silenced every rule in the scanner, which is a very quiet way to
     * turn a security tool off.
     */
    private boolean isSuppressed(String ruleId) {
        return suppressedRuleIds.stream()
                .anyMatch(suppressed -> ruleId.equals(suppressed) || ruleId.startsWith(suppressed + "-"));
    }

    public static final class Builder {
        private final List<MetadataRule> rules = new ArrayList<>(defaultRules());
        private final Set<String> suppressed = new LinkedHashSet<>();

        private Builder() {
        }

        /** Replaces the default rule set entirely. */
        public Builder rules(List<MetadataRule> value) {
            rules.clear();
            rules.addAll(value);
            return this;
        }

        public Builder addRule(MetadataRule rule) {
            rules.add(rule);
            return this;
        }

        /**
         * Silences a rule id or family, e.g. {@code MCPRT-CAP} to drop annotation nags or
         * {@code MCPRT-INJ-008} to drop just the tentative imperative-framing signature.
         */
        public Builder suppress(String... ruleIds) {
            for (String id : ruleIds) {
                suppressed.add(id);
            }
            return this;
        }

        public MetadataScanner build() {
            return new MetadataScanner(rules, suppressed);
        }
    }
}
