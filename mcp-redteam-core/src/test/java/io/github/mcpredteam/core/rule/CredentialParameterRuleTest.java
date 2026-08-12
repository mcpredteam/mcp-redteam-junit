package io.github.mcpredteam.core.rule;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ToolDefinition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialParameterRuleTest {

    private final CredentialParameterRule rule = new CredentialParameterRule();

    private ToolDefinition toolWithParam(String paramName) {
        return ToolDefinition.of("srv", "some_tool", "Does a thing.",
                Map.of("type", "object",
                        "properties", Map.of(paramName, Map.of("type", "string", "description", "a value"))));
    }

    private List<Finding> scan(ToolDefinition tool) {
        return rule.apply(List.of(tool));
    }

    @ParameterizedTest(name = "flags credential-shaped parameter ''{0}''")
    @ValueSource(strings = {
            "apiKey", "api_key", "API_KEY", "userApiKey",
            "token", "accessToken", "auth_token", "sessionToken", "refreshToken",
            "password", "passwd", "pwd", "passphrase",
            "secret", "clientSecret", "app_secret", "secretKey",
            "privateKey", "private_key", "bearer", "authorization", "credentials"})
    void flagsCredentialShapedParameters(String paramName) {
        List<Finding> findings = scan(toolWithParam(paramName));

        assertEquals(1, findings.size(), () -> "expected exactly one finding for '" + paramName + "'");
        Finding finding = findings.get(0);
        assertEquals("MCPRT-CRED-001", finding.ruleId());
        assertEquals(Severity.MEDIUM, finding.severity());
        assertEquals(Confidence.TENTATIVE, finding.confidence());
    }

    @ParameterizedTest(name = "leaves ordinary parameter ''{0}'' alone")
    @ValueSource(strings = {
            "status", "statusFilter", "invoice", "query", "limit", "accountId",
            "author",          // contains "auth" but is not a credential
            "key",             // a lone key is not a credential without api/private/secret
            "id", "tokenizer", // "token" as a substring of a real word
            "keyword", "description"})
    void ignoresOrdinaryParameters(String paramName) {
        assertTrue(scan(toolWithParam(paramName)).isEmpty(),
                () -> "'" + paramName + "' should not be flagged as a credential");
    }

    @Test
    @DisplayName("stays MEDIUM so it warns without failing the default high-risk gate")
    void isBelowTheHighRiskGate() {
        Finding finding = scan(toolWithParam("apiKey")).get(0);
        assertFalse(finding.severity().isAtLeast(Severity.HIGH),
                "The point of the rule is to warn on a shape honest tools sometimes share, not to fail the build");
    }

    @Test
    @DisplayName("names the offending parameter in the finding")
    void reportsWhichParameter() {
        Finding finding = scan(toolWithParam("apiKey")).get(0);
        assertEquals("apiKey", finding.evidence().get("parameter"));
        assertTrue(finding.location().contains("apiKey"), finding.location());
    }

    @Test
    @DisplayName("catches a credential parameter nested inside an object property")
    void walksNestedSchema() {
        ToolDefinition nested = ToolDefinition.of("srv", "submit", "Submits.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "auth", Map.of("type", "object",
                                        "properties", Map.of(
                                                "accessToken", Map.of("type", "string", "description", "t"))))));

        List<Finding> findings = scan(nested);
        assertTrue(findings.stream().anyMatch(f -> "accessToken".equals(f.evidence().get("parameter"))),
                "A credential buried one level down is still a credential the agent is asked to supply");
    }

    @Test
    void isPartOfTheDefaultRuleSet() {
        assertTrue(io.github.mcpredteam.core.MetadataScanner.defaultRules().stream()
                        .anyMatch(r -> r instanceof CredentialParameterRule),
                "The rule must be wired into the default scanner, or it protects nobody");
    }
}
