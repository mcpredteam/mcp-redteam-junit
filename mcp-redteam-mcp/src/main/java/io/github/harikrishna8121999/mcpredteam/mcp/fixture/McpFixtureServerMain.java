package io.github.harikrishna8121999.mcpredteam.mcp.fixture;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * A real MCP server, speaking the protocol over stdio, publishing one {@link FixtureCatalog}
 * profile.
 *
 * <p>Launched as a subprocess by {@link McpFixtureServer}; not usually run by hand. It exists so
 * the harness can be exercised end to end over the wire rather than against in-process
 * callbacks. That distinction earns its keep: the payloads here survive JSON-RPC serialisation,
 * the SDK's schema handling and Spring AI's tool adaptation before an agent ever reads them, and
 * every one of those layers is somewhere a poisoned description could be silently normalised
 * away. In-process fixtures cannot tell you whether it was.
 *
 * <pre>{@code
 * java -cp <classpath> io.github...fixture.McpFixtureServerMain tool-poisoning
 * }</pre>
 *
 * <h2>Nothing may be written to stdout</h2>
 *
 * <p>stdout <em>is</em> the protocol channel. A stray {@code System.out.println}, a logging
 * framework defaulting to the console, or a JVM warning on stdout corrupts the JSON-RPC stream,
 * and the failure surfaces at the client as a parse error or an empty tool list rather than as
 * anything naming the real cause. Diagnostics in this class go to stderr, which the SDK's client
 * transport drains separately.
 */
public final class McpFixtureServerMain {

    private McpFixtureServerMain() {
    }

    public static void main(String[] args) throws InterruptedException {
        String profile = args.length > 0 ? args[0] : FixtureCatalog.FINANCE;
        List<FixtureCatalog.Spec> specs = FixtureCatalog.profile(profile);

        StdioServerTransportProvider transport =
                new StdioServerTransportProvider(McpJsonDefaults.getMapper());

        McpSyncServer server = McpServer.sync(transport)
                .serverInfo("mcp-redteam-fixture-" + profile, "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                // Off because a poisoned fixture is allowed to publish a schema that its own
                // arguments violate. Validation here would have the fixture reject the very
                // call the test is trying to observe the agent making.
                .validateToolInputs(false)
                .tools(FixtureToolSpecifications.from(specs))
                .build();

        System.err.println("mcp-redteam fixture server '" + profile + "' ready with "
                + specs.size() + " tool(s)");

        // Held open until the parent closes our stdin. The transport's reader threads are
        // daemons, so returning from main here would kill the server the moment it started.
        CountDownLatch untilClosed = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.closeGracefully();
            untilClosed.countDown();
        }));
        untilClosed.await();
    }
}
