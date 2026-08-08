package io.github.harikrishna8121999.mcpredteam.springai.fixture;

import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.DefaultToolDefinition;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Objects;
import java.util.function.Function;

/**
 * A tool backed by a fixed script rather than a real service.
 *
 * <p>Fixture tools are inert: they never touch the network or the filesystem, and the
 * "malicious" ones do nothing worse than return a string. The attack is entirely in the
 * metadata and in the output, which is exactly where the real attack lives.
 */
public final class FixtureTool implements ToolCallback {

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    private final org.springframework.ai.tool.definition.ToolDefinition definition;
    private final Function<String, String> handler;

    private FixtureTool(org.springframework.ai.tool.definition.ToolDefinition definition,
                        Function<String, String> handler) {
        this.definition = definition;
        this.handler = handler;
    }

    /**
     * Builds a Spring AI tool from a core {@link ToolDefinition}, so the poisoned metadata the
     * static scanner is tested against is the same text a live agent is given. Two corpora
     * would drift, and the dynamic half would quietly stop testing the documented attack.
     */
    public static FixtureTool from(ToolDefinition definition, String result) {
        return from(definition, arguments -> result);
    }

    public static FixtureTool from(ToolDefinition definition, Function<String, String> handler) {
        Objects.requireNonNull(definition, "definition");
        return new FixtureTool(
                DefaultToolDefinition.builder()
                        .name(definition.name())
                        .description(definition.description())
                        .inputSchema(toJson(definition.inputSchema()))
                        .build(),
                handler);
    }

    @Override
    public org.springframework.ai.tool.definition.ToolDefinition getToolDefinition() {
        return definition;
    }

    @Override
    public String call(String toolInput) {
        return handler.apply(toolInput);
    }

    private static String toJson(Object schema) {
        try {
            return MAPPER.writeValueAsString(schema);
        } catch (Exception e) {
            throw new IllegalStateException("Fixture schema could not be serialised", e);
        }
    }
}
