package io.github.harikrishna8121999.mcpredteam.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SchemaWalkerTest {

    @Test
    @DisplayName("reaches strings nested inside maps and lists, with a pointer to each")
    void walksNestedStructures() {
        Map<String, Object> schema = Map.of(
                "type", "object",
                "properties", Map.of(
                        "payload", Map.of(
                                "type", "string",
                                "description", "the payload",
                                "examples", List.of("first", "second"))));

        Map<String, String> seen = new LinkedHashMap<>();
        SchemaWalker.walkStringValues(schema, "inputSchema", seen::put);

        assertTrue(seen.containsValue("the payload"));
        assertTrue(seen.containsKey("inputSchema/properties/payload/description"),
                "Pointer should locate the nested description, saw: " + seen.keySet());
        assertTrue(seen.containsKey("inputSchema/properties/payload/examples/0"),
                "List elements should be indexed, saw: " + seen.keySet());
    }

    @Test
    @DisplayName("visits property names, which are attacker-controlled too")
    void walksFieldNames() {
        Map<String, Object> schema = Map.of(
                "properties", Map.of("__system_instruction", Map.of("type", "string")));

        List<String> names = new ArrayList<>();
        SchemaWalker.walkFieldNames(schema, "inputSchema", (pointer, name) -> names.add(name));

        assertTrue(names.contains("__system_instruction"), "saw: " + names);
    }

    @Test
    void skipsBlankValues() {
        List<String> values = new ArrayList<>();
        SchemaWalker.walkStringValues(Map.of("a", "  ", "b", "real"), "root", (p, v) -> values.add(v));
        assertTrue(values.contains("real"));
        assertTrue(values.stream().noneMatch(String::isBlank));
    }

    /**
     * A hostile server controls the shape of its own schema. Recursing without a depth cap
     * turns a scan into a stack overflow, so the scanner becomes the vulnerability.
     */
    @Test
    @DisplayName("deeply nested hostile input is truncated rather than overflowing the stack")
    void boundsRecursionDepth() {
        Map<String, Object> deep = new LinkedHashMap<>();
        Map<String, Object> cursor = deep;
        for (int i = 0; i < 5_000; i++) {
            Map<String, Object> next = new LinkedHashMap<>();
            cursor.put("nested", next);
            cursor = next;
        }
        cursor.put("description", "bottom");

        List<String> values = new ArrayList<>();
        assertDoesNotThrow(() -> SchemaWalker.walkStringValues(deep, "root", (p, v) -> values.add(v)));
        assertTrue(values.isEmpty(), "Content past the depth cap should not be visited");
    }

    @Test
    void toleratesNullAndScalarRoots() {
        assertDoesNotThrow(() -> SchemaWalker.walkStringValues(null, "root", (p, v) -> { }));
        assertDoesNotThrow(() -> SchemaWalker.walkStringValues(42, "root", (p, v) -> { }));
        assertDoesNotThrow(() -> SchemaWalker.walkFieldNames(null, "root", (p, v) -> { }));
    }
}
