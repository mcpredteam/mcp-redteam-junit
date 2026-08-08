package io.github.harikrishna8121999.mcpredteam.springai;

import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import org.springframework.ai.tool.ToolCallback;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

/**
 * Bridges Spring AI's tool definitions into the core model the static scanner reads.
 *
 * <p>This is what turns the harness into a live scanner: the tools an agent was actually
 * offered — including those fetched from a real MCP server at runtime — can be run through
 * {@code MetadataScanner} without anyone hand-writing a {@code ToolDefinition} list that will
 * drift from what the agent really saw.
 */
public final class SpringToolDefinitions {

    /** Schema key holding the raw text of a schema that would not parse. */
    public static final String UNPARSED_SCHEMA = "unparsedSchema";

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();
    private static final TypeReference<Map<String, Object>> SCHEMA = new TypeReference<>() {
    };

    private SpringToolDefinitions() {
    }

    /**
     * Note the empty annotations map. Spring AI's {@code ToolDefinition} carries name,
     * description and input schema only — it has no channel for MCP tool annotations such as
     * {@code destructiveHint}. So on this path {@code MCPRT-CAP} can never be satisfied, and a
     * project with a {@code delete_*} tool will see a standing MEDIUM/TENTATIVE finding from
     * {@code scanOfferedTools()}. It is below the default gate and will not fail a build, but
     * it is noise rather than signal, and suppressing {@code MCPRT-CAP} for Spring-sourced
     * scans is reasonable. Annotations become available once the MCP protocol client lands and
     * definitions come from {@code tools/list} directly.
     */
    public static ToolDefinition from(ToolCallback callback, String serverName) {
        org.springframework.ai.tool.definition.ToolDefinition definition = callback.getToolDefinition();
        return new ToolDefinition(
                serverName,
                definition.name(),
                "",
                definition.description(),
                parseSchema(definition.inputSchema()),
                Map.of(),
                Map.of());
    }

    public static List<ToolDefinition> from(ToolServer server) {
        return server.tools().stream().map(tool -> from(tool, server.name())).toList();
    }

    /**
     * Parses the schema so nested descriptions stay reachable.
     *
     * <p>Spring AI carries {@code inputSchema} as a JSON string. Handing that string to a rule
     * as one blob would defeat {@code SchemaWalker}, which is the whole reason schema poisoning
     * buried in {@code properties/context/description} is detectable at all.
     *
     * <p>A schema that will not parse is <em>not</em> dropped. Returning an empty map would let
     * a hostile server buy itself a quieter scan than an honest one by publishing broken JSON —
     * an inversion this project objects to everywhere else. Instead the raw text is kept under
     * {@link #UNPARSED_SCHEMA} so every text rule still runs over it; the payload is found, and
     * the finding's location says plainly that the schema was malformed. Parsing never throws,
     * because a hostile server must not be able to end the test run.
     */
    private static Map<String, Object> parseSchema(String inputSchema) {
        if (inputSchema == null || inputSchema.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = MAPPER.readValue(inputSchema, SCHEMA);
            return parsed == null ? Map.of(UNPARSED_SCHEMA, inputSchema) : parsed;
        } catch (RuntimeException e) {
            return Map.of(UNPARSED_SCHEMA, inputSchema);
        }
    }
}
