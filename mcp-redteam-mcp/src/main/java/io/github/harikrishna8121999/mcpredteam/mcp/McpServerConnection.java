package io.github.harikrishna8121999.mcpredteam.mcp;

import io.github.harikrishna8121999.mcpredteam.core.McpSecurityScanner;
import io.github.harikrishna8121999.mcpredteam.core.MetadataScanner;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;
import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import io.github.harikrishna8121999.mcpredteam.core.fingerprint.Baseline;
import io.github.harikrishna8121999.mcpredteam.core.fingerprint.RugPullRule;
import io.github.harikrishna8121999.mcpredteam.core.fingerprint.ServerFingerprint;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A live connection to an MCP server, and the tools it publishes.
 *
 * <p>This is the class that lets a scan stop being a scan of something hand-written:
 *
 * <pre>{@code
 * try (McpServerConnection vendor = McpServerConnection.connect(
 *         "invoice-insights", McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp"))) {
 *     assertThatScan(vendor.scan()).hasNoFindingsAtOrAbove(Severity.HIGH);
 * }
 * }</pre>
 *
 * <p>Everything on the far end of this connection is attacker-controlled — tool names, schemas,
 * descriptions, the pagination cursor, and how much of any of it there is. The client is written
 * on that assumption rather than on the assumption that a server implements the spec in good
 * faith, which is the difference between a protocol client and a security tool's protocol client.
 */
public final class McpServerConnection implements AutoCloseable {

    /** Long enough for a cold remote server, short enough that a hung one fails the test. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * How many {@code tools/list} pages to follow before giving up.
     *
     * <p>Pagination is driven entirely by the server: it hands back a cursor and the client asks
     * again. A server that always returns one more cursor keeps the client asking forever, so an
     * uncapped loop turns "scan this server" into a hang with no output — the same reasoning that
     * caps {@code SchemaWalker}'s recursion depth. Twenty pages is far past any honest server and
     * far short of a problem.
     */
    public static final int DEFAULT_MAX_PAGES = 20;

    private final String serverName;
    private final McpServerTarget target;
    private final McpSyncClient client;
    private final int maxPages;

    private McpServerConnection(String serverName, McpServerTarget target, McpSyncClient client, int maxPages) {
        this.serverName = serverName;
        this.target = target;
        this.client = client;
        this.maxPages = maxPages;
    }

    /** Connects and completes the MCP {@code initialize} handshake. */
    public static McpServerConnection connect(String serverName, McpServerTarget target) {
        return connect(serverName, target, DEFAULT_TIMEOUT, DEFAULT_MAX_PAGES);
    }

    public static McpServerConnection connect(String serverName, McpServerTarget target,
                                              Duration timeout, int maxPages) {
        Objects.requireNonNull(serverName, "serverName");
        Objects.requireNonNull(target, "target");
        if (serverName.isBlank()) {
            throw new IllegalArgumentException("A server must be named; findings are reported against it");
        }
        if (maxPages < 1) {
            throw new IllegalArgumentException("maxPages must be at least 1, got " + maxPages);
        }

        McpSyncClient client = McpClient.sync(transportFor(target))
                .requestTimeout(timeout)
                .initializationTimeout(timeout)
                .clientInfo(new McpSchema.Implementation("mcp-redteam", "0.1.0"))
                .build();
        try {
            client.initialize();
        } catch (RuntimeException e) {
            // Otherwise a failed handshake leaks the subprocess or the HTTP session, and a suite
            // that scans several servers accumulates one orphan per unreachable target.
            closeQuietly(client);
            throw new IllegalStateException(
                    "Could not initialize an MCP session with '" + serverName + "' at " + target.describe(), e);
        }
        return new McpServerConnection(serverName, target, client, maxPages);
    }

    private static McpClientTransport transportFor(McpServerTarget target) {
        return switch (target) {
            case McpServerTarget.Stdio stdio -> new StdioClientTransport(
                    ServerParameters.builder(stdio.command())
                            .args(stdio.args())
                            .env(stdio.env())
                            .build(),
                    McpJsonDefaults.getMapper());
            case McpServerTarget.StreamableHttp http -> HttpClientStreamableHttpTransport
                    .builder(http.baseUri())
                    .endpoint(http.endpoint())
                    .jsonMapper(McpJsonDefaults.getMapper())
                    .httpRequestCustomizer((request, method, uri, body, context) ->
                            http.headers().forEach(request::header))
                    .build();
        };
    }

    /** The harness's label for this server — not what the server calls itself. */
    public String serverName() {
        return serverName;
    }

    public McpServerTarget target() {
        return target;
    }

    /** The live client, for anything beyond {@code tools/list}. */
    public McpSyncClient client() {
        return client;
    }

    /**
     * What the server claims to be. A claim, not an identity: nothing here is verified, and a
     * hostile server picks these strings freely. Useful in a report, useless as a trust signal.
     */
    public McpSchema.Implementation declaredServerInfo() {
        return client.getServerInfo();
    }

    /**
     * Every tool the server publishes, following pagination ourselves, up to the page cap.
     *
     * <h2>Why this does not call {@code client.listTools()}</h2>
     *
     * <p>The SDK's no-argument overload looks like exactly this method and must not be used here.
     * It expands the cursor chain internally and reduces it into one result, with no bound: given
     * a server that returns a fresh {@code nextCursor} every time, it never returns, and the tools
     * it collects accumulate until the JVM runs out of heap. A caller cannot interrupt it, time it
     * out per page, or find out how far it got. That is fine for a client talking to a server it
     * trusts, and unusable for one whose whole job is talking to servers it does not — so
     * pagination is driven here, one page at a time, through the single-argument overload.
     * {@code McpSchema.FIRST_PAGE} is {@code null}, which is how that overload asks for page one.
     *
     * <p>A repeated cursor ends the walk as well as the cap does. A server that returns the cursor
     * it was just given produces an infinite loop that the page cap alone would only shorten to
     * twenty identical pages, silently multiplying the tool list with duplicates before stopping.
     *
     * @throws IllegalStateException if the server is still paginating at the cap. Deliberately not
     *                               a truncated list: a partial scan that reads as a complete one
     *                               is the quietest way for this tool to be wrong.
     */
    public List<ToolDefinition> listTools() {
        List<ToolDefinition> tools = new ArrayList<>();
        Set<String> seenCursors = new HashSet<>();
        String cursor = McpSchema.FIRST_PAGE;

        for (int page = 0; page < maxPages; page++) {
            McpSchema.ListToolsResult result = client.listTools(cursor);
            tools.addAll(McpToolDefinitions.from(result.tools(), serverName));

            cursor = result.nextCursor();
            if (cursor == null || cursor.isBlank() || !seenCursors.add(cursor)) {
                return List.copyOf(tools);
            }
        }
        throw new IllegalStateException("Server '" + serverName + "' at " + target.describe()
                + " kept returning a pagination cursor after " + maxPages + " pages of tools/list."
                + " Refusing to keep asking; raise maxPages if this server is genuinely that large.");
    }

    /** {@code tools/list}, scanned with the default rule set. The whole point of the module. */
    public ScanReport scan() {
        return scan(MetadataScanner.withDefaultRules());
    }

    public ScanReport scan(McpSecurityScanner scanner) {
        return scanner.scan(listTools());
    }

    /**
     * Records what this server publishes right now, as the trusted state to compare later scans
     * against.
     *
     * <p>Gated: a server that fails the static scan is not baselined, because a fingerprint taken
     * from an already-poisoned server records the poison as trusted. This is a deliberate,
     * occasional act — capture the baseline, read the file, commit it — not something a test
     * should do on the way past. See {@link Baseline}.
     *
     * @throws io.github.harikrishna8121999.mcpredteam.core.fingerprint.UntrustedBaselineException
     *         if the server does not currently pass
     */
    public ServerFingerprint captureBaseline() {
        return Baseline.capture(serverName, listTools());
    }

    public ServerFingerprint captureBaseline(McpSecurityScanner gateScanner, Severity gate) {
        return Baseline.capture(serverName, listTools(), gateScanner, gate);
    }

    /**
     * Scans with the default rules plus a rug-pull check against a baseline.
     *
     * <pre>{@code
     * ServerFingerprint trusted = Baseline.read(Path.of("src/test/resources/finance-baseline.txt"));
     * assertThatScan(vendor.scanAgainst(trusted)).hasNoHighRiskFindings();
     * }</pre>
     */
    public ScanReport scanAgainst(ServerFingerprint baseline) {
        return scan(MetadataScanner.builder().addRule(RugPullRule.against(baseline)).build());
    }

    @Override
    public void close() {
        client.closeGracefully();
    }

    private static void closeQuietly(McpSyncClient client) {
        try {
            client.closeGracefully();
        } catch (RuntimeException suppressed) {
            // The connect failure is the useful one; a close failure on an unusable client is noise.
        }
    }
}
