package io.github.mcpredteam.core;

import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * Recursive traversal of decoded JSON schema structures.
 *
 * <p>Replaces the tempting {@code Map.toString()} shortcut, which produces unordered,
 * unescaped output that both misses nested text and invents delimiter characters that
 * confuse pattern matching.
 *
 * <p>Traversal depth is capped: a hostile server can return arbitrarily nested schemas,
 * and a scanner that overflows the stack on hostile input is a denial-of-service vector.
 */
public final class SchemaWalker {
    public static final int MAX_DEPTH = 64;

    private SchemaWalker() {
    }

    /**
     * Visits every string <em>value</em> reachable from {@code root}.
     *
     * @param visitor receives a JSON-pointer-style path and the string value
     */
    public static void walkStringValues(Object root, String rootPointer, BiConsumer<String, String> visitor) {
        walkValues(root, rootPointer, visitor, 0);
    }

    /**
     * Visits every map <em>key</em> reachable from {@code root}. Property names are
     * attacker-controlled too: a parameter called {@code __system_instruction} is a
     * signal even when its description is innocuous.
     */
    public static void walkFieldNames(Object root, String rootPointer, BiConsumer<String, String> visitor) {
        walkNames(root, rootPointer, visitor, 0);
    }

    private static void walkValues(Object node, String pointer, BiConsumer<String, String> visitor, int depth) {
        if (node == null || depth > MAX_DEPTH) {
            return;
        }
        if (node instanceof String s) {
            if (!s.isBlank()) {
                visitor.accept(pointer, s);
            }
            return;
        }
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                walkValues(entry.getValue(), pointer + "/" + entry.getKey(), visitor, depth + 1);
            }
            return;
        }
        if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                walkValues(list.get(i), pointer + "/" + i, visitor, depth + 1);
            }
        }
    }

    private static void walkNames(Object node, String pointer, BiConsumer<String, String> visitor, int depth) {
        if (node == null || depth > MAX_DEPTH) {
            return;
        }
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                String childPointer = pointer + "/" + key;
                visitor.accept(childPointer, key);
                walkNames(entry.getValue(), childPointer, visitor, depth + 1);
            }
            return;
        }
        if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                walkNames(list.get(i), pointer + "/" + i, visitor, depth + 1);
            }
        }
    }
}
