package com.example.notes;

import io.github.mcpredteam.core.ToolDefinition;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * A real MCP server, speaking the protocol over stdio.
 *
 * <p>Written against the MCP SDK directly, with nothing from {@code mcp-redteam} in it. That is
 * the point: {@link LiveServerScanTest} scans a server the library did not build, over the wire,
 * so the scan is not quietly reading the same objects the test constructed.
 *
 * <p>In your project this class does not exist — you point a scan at the server you already run,
 * or at a vendor's URL. It is here so the example has something to connect to.
 *
 * <p><strong>Nothing may be written to stdout.</strong> stdout <em>is</em> the JSON-RPC channel;
 * a stray {@code println} corrupts the stream and surfaces at the client as a server with no
 * tools rather than as any error naming the cause.
 */
final class NotesMcpServer {

    /** Publish {@code delete_note} with no annotations, so MCPRT-CAP has something to say. */
    static final String DROP_ANNOTATIONS = "drop-annotations";

    /** Publish {@link NotesToolCatalog#afterUnreviewedUpdate()}: the same server, changed. */
    static final String COMPROMISED = "compromised";

    private NotesMcpServer() {
    }

    public static void main(String[] args) throws InterruptedException {
        List<String> flags = List.of(args);
        boolean dropAnnotations = flags.contains(DROP_ANNOTATIONS);
        List<ToolDefinition> catalog = flags.contains(COMPROMISED)
                ? NotesToolCatalog.afterUnreviewedUpdate()
                : NotesToolCatalog.all();

        McpSyncServer server = McpServer.sync(new StdioServerTransportProvider(McpJsonDefaults.getMapper()))
                .serverInfo("notes", "1.0.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(catalog.stream()
                        .map(definition -> toTool(definition, dropAnnotations))
                        .toList())
                .build();

        System.err.println("notes MCP server ready");

        CountDownLatch untilClosed = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.closeGracefully();
            untilClosed.countDown();
        }));
        untilClosed.await();
    }

    private static McpServerFeatures.SyncToolSpecification toTool(ToolDefinition definition,
                                                                  boolean dropAnnotations) {
        McpSchema.Tool.Builder tool = McpSchema.Tool.builder()
                .name(definition.name())
                .description(definition.description())
                .inputSchema(definition.inputSchema());

        if (!dropAnnotations && !definition.annotations().isEmpty()) {
            tool.annotations(McpSchema.ToolAnnotations.builder()
                    .destructiveHint(booleanAnnotation(definition, "destructiveHint"))
                    .readOnlyHint(booleanAnnotation(definition, "readOnlyHint"))
                    .build());
        }

        return McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool.build())
                .callHandler((exchange, request) -> McpSchema.CallToolResult.builder()
                        .addTextContent("ok")
                        .build())
                .build();
    }

    /** Null when undeclared, so the wire carries "absent" rather than "false". */
    private static Boolean booleanAnnotation(ToolDefinition definition, String key) {
        Map<String, Object> annotations = definition.annotations();
        return annotations.containsKey(key) ? (Boolean) annotations.get(key) : null;
    }
}
