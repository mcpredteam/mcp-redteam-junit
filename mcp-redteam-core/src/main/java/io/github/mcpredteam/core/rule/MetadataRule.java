package io.github.mcpredteam.core.rule;

import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.List;

/**
 * A static detection over MCP tool metadata.
 *
 * <p>Rules receive the whole tool list because some threats — shadowing, duplicate names,
 * cross-tool instructions — are only visible in relation to other tools.
 */
public interface MetadataRule {

    /** Stable identifier, e.g. {@code MCPRT-INJ-001}. Findings carry it so suppressions can be pinned. */
    String id();

    /** Short human description of what this rule looks for. */
    String description();

    List<Finding> apply(List<ToolDefinition> tools);
}
