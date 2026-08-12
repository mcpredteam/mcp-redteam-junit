package io.github.mcpredteam.core.rule;

import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.SchemaWalker;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/** Base class for rules that examine one tool at a time. */
public abstract class PerToolRule implements MetadataRule {

    @Override
    public final List<Finding> apply(List<ToolDefinition> tools) {
        List<Finding> findings = new ArrayList<>();
        for (ToolDefinition tool : tools) {
            findings.addAll(inspect(tool));
        }
        return findings;
    }

    protected abstract List<Finding> inspect(ToolDefinition tool);

    /**
     * Visits every attacker-controllable text field of a tool, including nested schema
     * strings, as {@code (location, text)} pairs. Locations are JSON-pointer-ish paths
     * such as {@code inputSchema/properties/payload/description}.
     */
    protected static void forEachText(ToolDefinition tool, BiConsumer<String, String> visitor) {
        acceptIfPresent(visitor, "name", tool.name());
        acceptIfPresent(visitor, "title", tool.title());
        acceptIfPresent(visitor, "description", tool.description());
        SchemaWalker.walkStringValues(tool.inputSchema(), "inputSchema", visitor);
        SchemaWalker.walkStringValues(tool.outputSchema(), "outputSchema", visitor);
        SchemaWalker.walkStringValues(tool.annotations(), "annotations", visitor);
    }

    /** Visits every property/field name declared in the tool's schemas. */
    protected static void forEachFieldName(ToolDefinition tool, BiConsumer<String, String> visitor) {
        SchemaWalker.walkFieldNames(tool.inputSchema(), "inputSchema", visitor);
        SchemaWalker.walkFieldNames(tool.outputSchema(), "outputSchema", visitor);
    }

    private static void acceptIfPresent(BiConsumer<String, String> visitor, String location, String text) {
        if (text != null && !text.isBlank()) {
            visitor.accept(location, text);
        }
    }
}
