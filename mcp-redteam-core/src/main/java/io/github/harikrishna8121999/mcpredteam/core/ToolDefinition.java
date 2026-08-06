package io.github.harikrishna8121999.mcpredteam.core;

import java.util.Map;
import java.util.Objects;

/**
 * One entry from an MCP {@code tools/list} response.
 *
 * <p>Every field here is attacker-controlled when the server is untrusted, including
 * {@code name} and the nested schema text. Treat it as hostile input.
 *
 * @param annotations MCP tool annotations such as {@code readOnlyHint} and
 *                    {@code destructiveHint}; absent annotations are themselves a signal.
 */
public record ToolDefinition(
        String serverName,
        String name,
        String title,
        String description,
        Map<String, Object> inputSchema,
        Map<String, Object> outputSchema,
        Map<String, Object> annotations
) {
    public ToolDefinition {
        Objects.requireNonNull(name, "name");
        serverName = serverName == null ? "" : serverName;
        title = title == null ? "" : title;
        description = description == null ? "" : description;
        inputSchema = inputSchema == null ? Map.of() : Map.copyOf(inputSchema);
        outputSchema = outputSchema == null ? Map.of() : Map.copyOf(outputSchema);
        annotations = annotations == null ? Map.of() : Map.copyOf(annotations);
    }

    public static ToolDefinition of(String serverName, String name, String description, Map<String, Object> inputSchema) {
        return new ToolDefinition(serverName, name, "", description, inputSchema, Map.of(), Map.of());
    }

    /** Server-qualified identity, used as the {@code target} of findings. */
    public String qualifiedName() {
        return serverName.isEmpty() ? name : serverName + "/" + name;
    }

    public boolean hasAnnotation(String key) {
        return annotations.containsKey(key);
    }

    public boolean annotationIsTrue(String key) {
        return Boolean.TRUE.equals(annotations.get(key));
    }
}
