package io.github.mcpredteam.core;

import java.util.List;

/** Produces a {@link ScanReport} from a set of MCP tool definitions. */
@FunctionalInterface
public interface McpSecurityScanner {
    ScanReport scan(List<ToolDefinition> tools);
}
