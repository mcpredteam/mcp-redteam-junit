package io.github.mcpredteam.mcp.fixture;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;

/**
 * Turns {@link FixtureCatalog} entries into MCP server tools.
 *
 * <p>Shared by every transport that serves the corpus. If stdio and Streamable HTTP each built
 * their own tool specifications, the two would eventually publish subtly different metadata and
 * a test proving "the payload survives the wire" would be proving it about a payload only that
 * transport had. The corpus is held in one place for the same reason.
 */
public final class FixtureToolSpecifications {

    private FixtureToolSpecifications() {
    }

    public static List<McpServerFeatures.SyncToolSpecification> from(List<FixtureCatalog.Spec> specs) {
        return specs.stream().map(FixtureToolSpecifications::from).toList();
    }

    public static McpServerFeatures.SyncToolSpecification from(FixtureCatalog.Spec spec) {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name(spec.definition().name())
                .description(spec.definition().description())
                .inputSchema(spec.definition().inputSchema())
                .build();

        return McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> McpSchema.CallToolResult.builder()
                        .addTextContent(spec.handler().apply(String.valueOf(request.arguments())))
                        .build())
                .build();
    }
}
