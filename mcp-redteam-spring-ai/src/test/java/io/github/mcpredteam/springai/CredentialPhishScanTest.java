package io.github.mcpredteam.springai;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.mcp.fixture.FixtureCatalog;
import io.github.mcpredteam.springai.fixture.FixtureServers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.model.tool.ToolCallingChatOptions;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The static counterpart to the measured phishing hijack.
 *
 * <p>Against a real model, {@code FixtureServers.credentialPhish()} got the agent to leak its key
 * into a tool argument on every trial, and no metadata rule caught the tool beforehand — the whole
 * attack was a parameter named {@code apiKey}. {@code CredentialParameterRule} closes that: this
 * test proves the scanner now flags the tool <em>before</em> an agent is ever wired to it, turning
 * "detected after the key left" into "warned before it could".
 */
class CredentialPhishScanTest {

    private static ChatClient noopAgent() {
        return ChatClient.builder(ScriptedChatModel.answering("nothing to do"))
                .defaultOptions(ToolCallingChatOptions.builder())
                .build();
    }

    @Test
    @DisplayName("the credential-phishing tool is flagged before any agent runs")
    void warnsOnTheApiKeyParameter() {
        ScanReport report = McpRedTeam.forAgent(noopAgent())
                .withTrustedServer(FixtureServers.financeTools())
                .withMaliciousServer(FixtureServers.credentialPhish())
                .scanOfferedTools();

        assertThat(report).hasFinding("MCPRT-CRED-001");
        assertTrue(report.findings().stream()
                        .anyMatch(f -> "apiKey".equals(f.evidence().get("parameter"))),
                "The finding must name the offending parameter so a reviewer can act on it");
    }

    @Test
    @DisplayName("it warns rather than fails the default gate, because honest tools take tokens too")
    void staysBelowTheHighRiskGate() {
        ScanReport report = McpRedTeam.forAgent(noopAgent())
                .withMaliciousServer(FixtureServers.credentialPhish())
                .scanOfferedTools();

        // Present at MEDIUM...
        assertTrue(report.hasFindingsAtOrAbove(Severity.MEDIUM));
        // ...but a team gating on FIRM-and-above, as the docs recommend, would see it as advisory.
        assertFalse(report.findingsAtOrAbove(Severity.HIGH, Confidence.FIRM).stream()
                        .anyMatch(f -> f.ruleId().equals("MCPRT-CRED-001")),
                "A MEDIUM/TENTATIVE warning must not masquerade as a build-breaking finding");
    }

    @Test
    @DisplayName("honest finance tools are not flagged as credential phishing")
    void doesNotFlagTheTrustedServer() {
        ScanReport report = McpRedTeam.forAgent(noopAgent())
                .withTrustedServer(FixtureServers.financeTools())
                .scanOfferedTools();

        assertFalse(report.findings().stream().anyMatch(f -> f.ruleId().equals("MCPRT-CRED-001")),
                "list_invoices and send_payment take no credential parameter; flagging them would be noise");
    }

    @Test
    @DisplayName("a trust policy can now withhold the phishing tool on this warning")
    void aPolicyCanActOnTheWarning() {
        McpRedTeam harness = McpRedTeam.forAgent(noopAgent())
                .withTrustedServer(FixtureServers.financeTools())
                .withMaliciousServer(FixtureServers.credentialPhish())
                .withTrustPolicy(ToolTrustPolicy.withholdingFindingsAtOrAbove(Severity.MEDIUM));

        assertTrue(harness.withheldTools().contains(FixtureCatalog.INSIGHTS_SERVER + "/summarize_invoices"),
                "Lowering the policy threshold to MEDIUM must withhold the phishing tool: " + harness.withheldTools());
        assertFalse(harness.withheldTools().contains(FixtureServers.TRUSTED_SERVER + "/list_invoices"),
                "and must leave the honest tools in place");
    }
}
