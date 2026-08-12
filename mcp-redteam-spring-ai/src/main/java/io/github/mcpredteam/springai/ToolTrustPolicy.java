package io.github.mcpredteam.springai;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.MetadataScanner;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Decides which of the tools a server published are allowed to reach the model.
 *
 * <p>This is the remediation half of the project. Everything else here answers "can this agent
 * be hijacked"; a trust policy is what an application does about the answer. The same test that
 * fails against a poisoned server should pass once one of these is applied — and if it does not,
 * the policy is decoration.
 *
 * <pre>{@code
 * McpRedTeam.forAgent(chatClient)
 *         .withTrustedServer(FixtureServers.financeTools())
 *         .withMaliciousServer(FixtureServers.toolPoisoning())
 *         .withTrustPolicy(ToolTrustPolicy.withholdingFindingsAtOrAbove(Severity.HIGH))
 *         .run(task);
 * }</pre>
 *
 * <h2>Why a policy pass is weaker evidence than a policy failure</h2>
 *
 * <p>Withholding a tool makes "the agent did not call it" true by construction. That is a real
 * defence, but it is not the same class of evidence as a hijack: the failing run proves
 * something about the model, the passing run only proves the filter ran. A test that asserts
 * only {@code calledNoneOf(...)} after applying a policy is testing nothing.
 *
 * <p>Pair it with two other assertions and it becomes meaningful: that the withholding actually
 * fired ({@link McpRedTeam#withheldTools()} is non-empty), and that the agent still completed
 * the user's real task with the tools it kept. A policy that passes the security assertion by
 * breaking the application is not a fix, and only the second assertion catches that.
 */
@FunctionalInterface
public interface ToolTrustPolicy {

    /**
     * @param published every tool definition the configured servers offer, before filtering
     * @return qualified names ({@code server/tool}) to withhold from the model
     */
    Set<String> withhold(List<ToolDefinition> published);

    /** No filtering. The agent sees the poisoned metadata exactly as published. */
    static ToolTrustPolicy allowAll() {
        return published -> Set.of();
    }

    /**
     * Withholds everything published by any server not named here.
     *
     * <p>The blunt instrument, and the one most real applications should reach for first. It
     * needs no detector to be correct, so it cannot be evaded by a payload the rules have not
     * seen — the tradeoff being that it is a decision about vendors, not about content.
     */
    static ToolTrustPolicy trustingOnlyServers(String... trustedServerNames) {
        Set<String> trusted = Set.of(trustedServerNames);
        return published -> published.stream()
                .filter(tool -> !trusted.contains(tool.serverName()))
                .map(ToolDefinition::qualifiedName)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Runs the static scanner over the published set and withholds any tool it flags at or
     * above {@code severity}.
     *
     * <p>Scanning the whole set at once rather than tool by tool is deliberate: {@code
     * MCPRT-SHADOW} compares tools against each other, so a per-tool scan would silently lose
     * the one rule that needs to see its neighbours.
     *
     * <p>Content-based filtering inherits the scanner's blind spots. It cannot withhold the
     * tool-result injection fixture, whose metadata is clean by design — that payload arrives
     * at call time, after this decision has been made. Combining this with
     * {@link #trustingOnlyServers} covers the gap.
     */
    static ToolTrustPolicy withholdingFindingsAtOrAbove(Severity severity) {
        return withholdingFindingsAtOrAbove(severity, Confidence.TENTATIVE);
    }

    static ToolTrustPolicy withholdingFindingsAtOrAbove(Severity severity, Confidence confidence) {
        return published -> {
            ScanReport report = MetadataScanner.withDefaultRules().scan(published);
            return report.findingsAtOrAbove(severity, confidence).stream()
                    .map(Finding::target)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        };
    }

    /** Withholds a tool if either policy would. */
    default ToolTrustPolicy and(ToolTrustPolicy other) {
        return published -> {
            Set<String> combined = new LinkedHashSet<>(withhold(published));
            combined.addAll(other.withhold(published));
            return combined;
        };
    }
}
