package io.github.mcpredteam.mcp;

import io.github.mcpredteam.core.ToolDefinition;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns what a server published into what the rules read.
 *
 * <p>This is the mapping the static scanner has been waiting for. Until now the only live source
 * of tool metadata was Spring AI's {@code ToolDefinition}, which carries name, description and
 * input schema and nothing else — so {@code MCPRT-CAP} could never be satisfied on a real
 * connection, and every project with a {@code delete_*} tool collected a standing finding it
 * could do nothing about. A {@code tools/list} response carries the annotations, so the rule can
 * finally tell "this server declined to declare destructiveHint" from "this path cannot see
 * annotations at all". Those are opposite conclusions and they had the same symptom.
 */
public final class McpToolDefinitions {

    private McpToolDefinitions() {
    }

    public static List<ToolDefinition> from(List<McpSchema.Tool> tools, String serverName) {
        return tools == null ? List.of() : tools.stream().map(tool -> from(tool, serverName)).toList();
    }

    /**
     * @param serverName the harness's label for this server, not anything the server called
     *                   itself. {@code serverInfo.name} is attacker-controlled: a hostile server
     *                   naming itself {@code github-official} is a claim, not an identity, and
     *                   findings that adopted it would launder the lie into the report.
     */
    public static ToolDefinition from(McpSchema.Tool tool, String serverName) {
        return new ToolDefinition(
                serverName,
                tool.name(),
                tool.title() == null ? "" : tool.title(),
                tool.description() == null ? "" : tool.description(),
                tool.inputSchema(),
                tool.outputSchema(),
                annotations(tool.annotations()));
    }

    /**
     * Flattens the SDK's typed annotations, keeping only hints the server actually declared.
     *
     * <p>Absence and {@code false} must stay distinguishable, because they mean different things
     * and {@code DestructiveCapabilityRule} keys on exactly that: it asks
     * {@code hasAnnotation("destructiveHint")}, not whether the hint is true. A server that says
     * "this delete tool is not destructive" has made a checkable claim and the rule stays quiet;
     * a server that says nothing has left the host unable to gate the call behind a confirmation,
     * which is the finding. Mapping a null {@code Boolean} to {@code false} would collapse the two
     * and silence the rule against precisely the servers it exists to flag.
     */
    static Map<String, Object> annotations(McpSchema.ToolAnnotations annotations) {
        if (annotations == null) {
            return Map.of();
        }
        Map<String, Object> declared = new LinkedHashMap<>();
        putIfDeclared(declared, "title", annotations.title());
        putIfDeclared(declared, "readOnlyHint", annotations.readOnlyHint());
        putIfDeclared(declared, "destructiveHint", annotations.destructiveHint());
        putIfDeclared(declared, "idempotentHint", annotations.idempotentHint());
        putIfDeclared(declared, "openWorldHint", annotations.openWorldHint());
        putIfDeclared(declared, "returnDirect", annotations.returnDirect());
        return Map.copyOf(declared);
    }

    private static void putIfDeclared(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
