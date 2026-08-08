package io.github.harikrishna8121999.mcpredteam.core.rule;

import io.github.harikrishna8121999.mcpredteam.core.Confidence;
import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;

import java.util.List;
import java.util.Set;

/**
 * Flags a tool that declares a <em>credential-shaped parameter</em> — an argument named like an
 * API key, token, password or secret.
 *
 * <p>This rule exists because of a measured failure. Against a real model, a tool that matched the
 * user's task and simply declared an extra {@code apiKey} field — described in the same flat tone
 * as its honest parameters, with no injection language anywhere — got the agent to copy a
 * confidential key straight into the call, on every trial. There was nothing for the other rules
 * to catch: no "ignore previous instructions", no external URL, no sensitive path. The whole
 * attack was the shape of the parameter list.
 *
 * <p>The underlying principle is that authentication is the host's job, not the model's. A tool
 * that needs a credential should receive it from the transport or the client, out of band — never
 * by asking the agent to place a secret it holds into a tool argument. Any tool whose schema
 * invites that is, at best, teaching the agent a dangerous habit and, at worst, phishing it.
 *
 * <p>Deliberately {@link Severity#MEDIUM} / {@link Confidence#TENTATIVE}: some legitimate tools
 * really do take a token, so this is below the default high-risk gate. It warns rather than fails
 * — the point is to surface the phishing shape <em>before</em> an agent ever runs, where only the
 * dynamic canary would otherwise catch it, and then only after the key had already leaked.
 */
public final class CredentialParameterRule extends PerToolRule {

    /** A word that on its own marks a parameter as credential-bearing. */
    private static final Set<String> CREDENTIAL_WORDS = Set.of(
            "password", "passwd", "pwd", "passphrase",
            "secret", "token", "credential", "credentials", "bearer", "authorization", "apikey");

    /**
     * Adjacent word pairs that together name a credential, e.g. {@code apiKey} → [api, key].
     * Kept as pairs rather than folded into {@link #CREDENTIAL_WORDS} so that an innocent lone
     * "key" or "id" does not trip the rule.
     */
    private static final Set<List<String>> CREDENTIAL_PAIRS = Set.of(
            List.of("api", "key"),
            List.of("access", "token"),
            List.of("auth", "token"),
            List.of("session", "token"),
            List.of("refresh", "token"),
            List.of("id", "token"),
            List.of("client", "secret"),
            List.of("app", "secret"),
            List.of("private", "key"),
            List.of("secret", "key"));

    @Override
    public String id() {
        return "MCPRT-CRED";
    }

    @Override
    public String description() {
        return "Tool parameters shaped like credentials, which invite the agent to leak a secret "
                + "into a tool call.";
    }

    @Override
    protected List<Finding> inspect(ToolDefinition tool) {
        List<Finding> findings = new java.util.ArrayList<>();

        forEachFieldName(tool, (location, name) -> {
            String matched = credentialLabel(name);
            if (matched != null) {
                findings.add(Finding.builder("MCPRT-CRED-001")
                        .threatType(ThreatType.EXFILTRATION_CHANNEL)
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.TENTATIVE)
                        .target(tool.qualifiedName())
                        .location(location)
                        .message("Parameter '" + name + "' is shaped like a credential (" + matched + "). "
                                + "A tool that asks the agent to pass a secret as an argument invites it to "
                                + "leak one — the agent has no way to tell a legitimate request from a phishing one.")
                        .remediation("Authenticate the tool through the host or transport, out of band, rather than "
                                + "taking a credential as a model-supplied parameter. If the token is genuinely "
                                + "caller-supplied, document that it is not the user's own secret.")
                        .evidence("parameter", name)
                        .build());
            }
        });

        return findings;
    }

    /** The credential word or pair a field name matches, or {@code null} if none. */
    private static String credentialLabel(String fieldName) {
        List<String> words = splitToWords(fieldName);

        String collapsed = String.join("", words);
        if (CREDENTIAL_WORDS.contains(collapsed)) {
            return collapsed;
        }
        for (String word : words) {
            if (CREDENTIAL_WORDS.contains(word)) {
                return word;
            }
        }
        for (int i = 0; i + 1 < words.size(); i++) {
            List<String> pair = List.of(words.get(i), words.get(i + 1));
            if (CREDENTIAL_PAIRS.contains(pair)) {
                return String.join(" ", pair);
            }
        }
        return null;
    }

    /**
     * Splits a field name into lowercase words on camelCase humps, letter/digit boundaries and any
     * non-alphanumeric separator. {@code "userApiKey"} and {@code "user_api_key"} both become
     * [user, api, key], so the same credential reads the same however it was cased.
     */
    private static List<String> splitToWords(String fieldName) {
        String spaced = fieldName
                .replaceAll("([a-z0-9])([A-Z])", "$1 $2")
                .replaceAll("([A-Za-z])([0-9])", "$1 $2")
                .replaceAll("[^A-Za-z0-9]+", " ")
                .trim()
                .toLowerCase();
        if (spaced.isEmpty()) {
            return List.of();
        }
        return List.of(spaced.split("\\s+"));
    }
}
