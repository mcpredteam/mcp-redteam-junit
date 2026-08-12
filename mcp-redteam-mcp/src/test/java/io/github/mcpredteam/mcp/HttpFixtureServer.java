package io.github.mcpredteam.mcp;

import io.github.mcpredteam.mcp.fixture.FixtureCatalog;
import io.github.mcpredteam.mcp.fixture.FixtureToolSpecifications;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/**
 * A {@link FixtureCatalog} profile served over Streamable HTTP, on loopback.
 *
 * <p>Deliberately the SDK's own server transport rather than something hand-rolled that answers
 * JSON-RPC convincingly enough. The point of the HTTP tests is to prove the client speaks the
 * real transport — session headers, protocol negotiation, the SSE-or-JSON response choice — and
 * a fixture written by the same person as the client would agree with it about any detail both
 * got wrong.
 *
 * <p>Binds to an ephemeral port on localhost, so the tests need a loopback interface and nothing
 * else: no network, no fixed port to collide with a developer's own server.
 */
final class HttpFixtureServer implements AutoCloseable {

    private static final String ENDPOINT = "/mcp";

    private final Server jetty;
    private final McpSyncServer server;
    private final int port;

    private HttpFixtureServer(Server jetty, McpSyncServer server, int port) {
        this.jetty = jetty;
        this.server = server;
        this.port = port;
    }

    static HttpFixtureServer start(String profile) {
        HttpServletStreamableServerTransportProvider transport =
                HttpServletStreamableServerTransportProvider.builder()
                        .jsonMapper(McpJsonDefaults.getMapper())
                        .mcpEndpoint(ENDPOINT)
                        .build();

        McpSyncServer server = McpServer.sync(transport)
                .serverInfo("mcp-redteam-fixture-" + profile, "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                // Off for the same reason the stdio fixture turns it off: a poisoned fixture is
                // allowed to publish a schema its own arguments violate.
                .validateToolInputs(false)
                .tools(FixtureToolSpecifications.from(FixtureCatalog.profile(profile)))
                .build();

        Server jetty = new Server(0);
        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        context.addServlet(new ServletHolder(transport), ENDPOINT);
        jetty.setHandler(context);

        try {
            jetty.start();
        } catch (Exception e) {
            throw new IllegalStateException("Could not start the HTTP fixture server", e);
        }

        int port = ((ServerConnector) jetty.getConnectors()[0]).getLocalPort();
        return new HttpFixtureServer(jetty, server, port);
    }

    /** The URL a scan would be pointed at, exactly as a user would write it. */
    String url() {
        return "http://localhost:" + port + ENDPOINT;
    }

    @Override
    public void close() {
        try {
            server.closeGracefully();
        } finally {
            try {
                jetty.stop();
            } catch (Exception e) {
                throw new IllegalStateException("Could not stop the HTTP fixture server", e);
            }
        }
    }
}
