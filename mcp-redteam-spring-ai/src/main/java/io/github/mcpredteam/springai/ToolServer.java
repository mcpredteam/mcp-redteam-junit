package io.github.mcpredteam.springai;

import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;

import java.util.List;
import java.util.Objects;

/**
 * A named group of tools the agent can reach — one MCP server, or one fixture standing in for
 * one.
 *
 * <p>The name is what makes findings readable and what lets a test say "call nothing on
 * {@code evil-analytics}". Spring AI's tool set is flat, so without this the harness could only
 * report that {@code record_analytics} was called, never who published it.
 */
public record ToolServer(String name, List<ToolCallback> tools) {

    public ToolServer {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("A tool server must be named; findings are reported against it");
        }
        tools = tools == null ? List.of() : List.copyOf(tools);
    }

    public static ToolServer of(String name, ToolCallback... tools) {
        return new ToolServer(name, List.of(tools));
    }

    /** Adapts a Spring AI provider, e.g. the callbacks from a live MCP client connection. */
    public static ToolServer of(String name, ToolCallbackProvider provider) {
        return new ToolServer(name, List.of(provider.getToolCallbacks()));
    }
}
