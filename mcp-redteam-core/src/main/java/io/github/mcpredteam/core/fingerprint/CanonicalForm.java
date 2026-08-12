package io.github.mcpredteam.core.fingerprint;

import io.github.mcpredteam.core.SchemaWalker;
import io.github.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A tool definition flattened into a deterministic {@code location -> value} form, which is what
 * a fingerprint is taken over.
 *
 * <h2>Why this is not normalized text</h2>
 *
 * <p>Every rule in this library matches against {@link
 * io.github.mcpredteam.core.TextNormalizer} output, and this deliberately does
 * not. Normalizing first would fold a Cyrillic {@code а} onto Latin {@code a} <em>before</em> the
 * digest, so a server could swap one for the other — renaming {@code send_payment} to a
 * look-alike the agent still selects — and the fingerprint would not move. A rug-pull check that
 * cannot see a homoglyph swap misses the one edit an attacker most wants to make quietly. Raw
 * bytes here; normalization stays where it belongs, in the rules that read the text.
 *
 * <p>Determinism is the other requirement. Two scans of an unchanged server must produce the same
 * lines, so map entries are ordered by key rather than by whatever order the JSON decoder handed
 * back, and values carry a type tag so {@code "1"} and {@code 1} cannot fingerprint alike.
 */
public final class CanonicalForm {

    /**
     * Recorded in place of a subtree deeper than {@link SchemaWalker#MAX_DEPTH}.
     *
     * <p>The cap exists for the same reason {@code SchemaWalker}'s does — a hostile server
     * chooses the nesting depth — but dropping the subtree silently would make every schema
     * below the cap fingerprint identically, which is a free hiding place. The marker records
     * that something was cut, so two differently-truncated schemas at least agree that they
     * were truncated at the same place.
     */
    public static final String DEPTH_CAPPED = "!depth-capped";

    private CanonicalForm() {
    }

    /**
     * Flattens one tool. Keys are JSON-pointer-ish paths ({@code inputSchema/properties/apiKey/
     * description}); values are type-tagged scalars.
     *
     * <p>Pointer segments escape {@code ~} and {@code /} the way RFC 6901 does, because property
     * names are attacker-controlled and a parameter literally named {@code a/b} would otherwise
     * be indistinguishable from a nested one.
     */
    public static Map<String, String> of(ToolDefinition tool) {
        Map<String, String> lines = new TreeMap<>();
        // Always emitted, even when blank: a description that is deleted has to differ from one
        // that was never there, and an absent line would just vanish from the comparison.
        lines.put("name", "s:" + tool.name());
        lines.put("title", "s:" + tool.title());
        lines.put("description", "s:" + tool.description());
        walk(tool.inputSchema(), "inputSchema", lines, 0);
        walk(tool.outputSchema(), "outputSchema", lines, 0);
        walk(tool.annotations(), "annotations", lines, 0);
        return lines;
    }

    /** The string a canonical value carries, or empty for values that are not text. */
    public static String textOf(String canonicalValue) {
        return canonicalValue != null && canonicalValue.startsWith("s:") ? canonicalValue.substring(2) : "";
    }

    private static void walk(Object node, String pointer, Map<String, String> lines, int depth) {
        if (depth > SchemaWalker.MAX_DEPTH) {
            lines.put(pointer, DEPTH_CAPPED);
            return;
        }
        if (node == null) {
            lines.put(pointer, "z:");
            return;
        }
        if (node instanceof String s) {
            lines.put(pointer, "s:" + s);
            return;
        }
        if (node instanceof Boolean b) {
            lines.put(pointer, "b:" + b);
            return;
        }
        if (node instanceof Number n) {
            // Rendered by Java's own toString, so 1 and 1.0 differ. Both sides of a comparison
            // come from the same decoder, so that is a distinction it can actually make.
            lines.put(pointer, "n:" + n);
            return;
        }
        if (node instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                // An empty object is a fact about the schema; without this line it would leave
                // no trace at all, and gaining its first property would read as an addition
                // rather than as a change.
                lines.put(pointer, "{}");
                return;
            }
            // Decoded JSON objects have string keys, so ordering by the key's text is total.
            List<? extends Map.Entry<?, ?>> entries = new ArrayList<>(map.entrySet());
            entries.sort(Comparator.comparing(e -> String.valueOf(e.getKey())));
            for (Map.Entry<?, ?> entry : entries) {
                walk(entry.getValue(), pointer + "/" + escapeSegment(String.valueOf(entry.getKey())),
                        lines, depth + 1);
            }
            return;
        }
        if (node instanceof List<?> list) {
            if (list.isEmpty()) {
                lines.put(pointer, "[]");
                return;
            }
            for (int i = 0; i < list.size(); i++) {
                walk(list.get(i), pointer + "/" + i, lines, depth + 1);
            }
            return;
        }
        lines.put(pointer, "?:" + node);
    }

    private static String escapeSegment(String segment) {
        return segment.replace("~", "~0").replace("/", "~1");
    }
}
