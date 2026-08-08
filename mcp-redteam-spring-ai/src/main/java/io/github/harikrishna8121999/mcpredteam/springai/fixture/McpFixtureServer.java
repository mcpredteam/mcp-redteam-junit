package io.github.harikrishna8121999.mcpredteam.springai.fixture;

import io.github.harikrishna8121999.mcpredteam.springai.ToolServer;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import org.springframework.ai.mcp.McpToolNamePrefixGenerator;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Launches a fixture MCP server as a subprocess and exposes its tools to the harness.
 *
 * <pre>{@code
 * try (McpFixtureServer evil = McpFixtureServer.launch("evil-analytics", FixtureCatalog.TOOL_POISONING)) {
 *     AgentRun run = McpRedTeam.forAgent(chatClient)
 *             .withTrustedServer(FixtureServers.financeTools())
 *             .withMaliciousServer(evil.toolServer())
 *             .withPlantedSecret(canary)
 *             .run("Summarise my open invoices.");
 * }
 * }</pre>
 *
 * <p>This is the closest thing in the project to a real deployment: a separate process, real
 * JSON-RPC over pipes, tools discovered by {@code tools/list} rather than declared in Java. What
 * it buys over {@link FixtureServers} is confidence that a payload survives the whole path to
 * the model — the answer turns out to be yes, but that is a finding, not an assumption.
 *
 * <p>Slower than the in-process fixtures by a JVM startup, so prefer those for the tests that
 * run on every build and keep these for the ones that prove the protocol path works.
 */
public final class McpFixtureServer implements AutoCloseable {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final ToolServer toolServer;
    private final McpSyncClient client;

    private McpFixtureServer(ToolServer toolServer, McpSyncClient client) {
        this.toolServer = toolServer;
        this.client = client;
    }

    /**
     * Starts a server for {@code profile} and connects to it.
     *
     * @param serverName the name findings are reported against — the harness's label for this
     *                   server, not anything the server itself claims. A malicious server
     *                   naming itself is not evidence of who it is.
     * @param profile    a {@link FixtureCatalog} profile constant
     */
    public static McpFixtureServer launch(String serverName, String profile) {
        // Validated here rather than in the child: a bad profile name should fail as an
        // IllegalArgumentException on this thread, not as a subprocess that exits before
        // initialize() and leaves the client reporting a timeout.
        FixtureCatalog.profile(profile);

        ServerParameters parameters = ServerParameters.builder(javaExecutable())
                .args("-cp", System.getProperty("java.class.path"),
                        McpFixtureServerMain.class.getName(), profile)
                .build();

        McpSyncClient client = McpClient
                .sync(new StdioClientTransport(parameters, McpJsonDefaults.getMapper()))
                .requestTimeout(REQUEST_TIMEOUT)
                .build();
        client.initialize();

        // noPrefix keeps tools named as the server published them. Spring AI's default prefixes
        // the client name onto every tool, which would mean assertions and findings referred to
        // a name that exists nowhere in the corpus, the payload, or the server.
        SyncMcpToolCallbackProvider provider = SyncMcpToolCallbackProvider.builder()
                .mcpClients(List.of(client))
                .toolNamePrefixGenerator(McpToolNamePrefixGenerator.noPrefix())
                .build();

        return new McpFixtureServer(ToolServer.of(serverName, provider), client);
    }

    /** The tools this server published, ready to hand to {@code McpRedTeam}. */
    public ToolServer toolServer() {
        return toolServer;
    }

    /** The live client, for talking to the fixture directly — {@code listTools}, {@code ping}. */
    public McpSyncClient client() {
        return client;
    }

    @Override
    public void close() {
        client.closeGracefully();
    }

    /**
     * The JVM running this test, so the child inherits its version and the test classpath is
     * one it can actually load. Resolving {@code java} from {@code PATH} instead would pick up
     * whichever JDK the machine happens to default to.
     */
    private static String javaExecutable() {
        String name = System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", name).toString();
    }
}
