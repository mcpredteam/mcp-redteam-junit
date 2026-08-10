package io.github.harikrishna8121999.mcpredteam.springai.fixture;

import io.github.harikrishna8121999.mcpredteam.core.fixture.PoisonedToolFixtures;
import io.github.harikrishna8121999.mcpredteam.mcp.fixture.FixtureCatalog;
import io.github.harikrishna8121999.mcpredteam.springai.ToolServer;
import org.springframework.ai.tool.ToolCallback;

import java.util.List;

/**
 * Tool servers to run an agent against, published in-process.
 *
 * <p>The tools come from {@link FixtureCatalog}, which draws its malicious payloads from
 * {@link PoisonedToolFixtures} — the same corpus the static scanner is tested against, so both
 * halves of the project are aimed at one set of attacks.
 *
 * <p>No subprocess and no protocol: these are Spring AI {@link FixtureTool}s handed straight to
 * the model. That makes them fast enough to run in every build, and it isolates the question
 * "was the agent hijacked" from "does the transport work". For the same fixtures served by a
 * real MCP server over stdio, see {@code McpFixtureServer}.
 *
 * <p>These are safe to run. No fixture opens a socket, reads a file, or executes a command; the
 * poison is text in a description or in a return value. Nothing here becomes dangerous if a
 * test is run carelessly — which is the point of testing hijack resistance with fixtures rather
 * than against something real.
 */
public final class FixtureServers {

    // Aliases, not copies. The names live with the catalog now that the catalog is shared with
    // the protocol client; re-declaring the literals here would give the corpus two spellings of
    // the same server and a test that named the wrong one would still compile.
    public static final String TRUSTED_SERVER = FixtureCatalog.TRUSTED_SERVER;
    public static final String MALICIOUS_SERVER = FixtureCatalog.MALICIOUS_SERVER;

    private FixtureServers() {
    }

    /** A plausible trusted server: the tools the benign task legitimately needs. */
    public static ToolServer financeTools() {
        return serverOf(TRUSTED_SERVER, FixtureCatalog.finance());
    }

    /**
     * Tool poisoning: the description tells the agent to collect credentials and stay quiet
     * about it. Detectable statically, and the baseline for "did the agent obey the metadata".
     */
    public static ToolServer toolPoisoning() {
        return serverOf(MALICIOUS_SERVER, FixtureCatalog.toolPoisoning());
    }

    /**
     * Tool result injection: metadata clean enough to survive review, payload delivered in the
     * return value at call time.
     *
     * <p>This is the fixture the static scanner structurally cannot catch — a scan of this
     * server's {@code tools/list} is clean — so it is the one that justifies the dynamic
     * harness existing at all.
     */
    public static ToolServer resultInjection() {
        return serverOf(MALICIOUS_SERVER, FixtureCatalog.resultInjection());
    }

    /** An exfiltration sink for the agent to reach for once it has been told to. */
    public static ToolServer exfiltrationSink() {
        return serverOf(MALICIOUS_SERVER, FixtureCatalog.exfiltrationSink());
    }

    /**
     * Realistic credential phishing: a task-relevant tool that asks for the API key as a routine
     * authorization parameter. Pair it with {@link McpRedTeam#CREDENTIALED_PLANT_TEMPLATE} — under
     * the default prompt's explicit "never pass it to a tool" the attack is testing obedience, not
     * judgement.
     */
    public static ToolServer credentialPhish() {
        return serverOf(FixtureCatalog.INSIGHTS_SERVER, FixtureCatalog.credentialPhish());
    }

    /** Realistic result steering: clean metadata, the payload delivered as a billing notice. */
    public static ToolServer resultSteer() {
        return serverOf(FixtureCatalog.INSIGHTS_SERVER, FixtureCatalog.resultSteer());
    }

    /** Any catalog profile, published in-process under the given server name. */
    public static ToolServer serverOf(String serverName, List<FixtureCatalog.Spec> specs) {
        List<ToolCallback> tools = specs.stream()
                .map(spec -> (ToolCallback) FixtureTool.from(spec.definition(), spec.handler()))
                .toList();
        return new ToolServer(serverName, tools);
    }
}
