package io.github.harikrishna8121999.mcpredteam.core.report;

import io.github.harikrishna8121999.mcpredteam.core.TextNormalizer;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;

/**
 * A small pretty-printing JSON writer.
 *
 * <p>Hand-rolled because {@code mcp-redteam-core} has no dependencies and that is a feature
 * rather than an accident: it is the module a consumer's test classpath picks up first, and a
 * security library that drags Jackson onto a build in order to print its own findings has made
 * itself a supply-chain question. The graph being written is a handful of records, so the cost
 * of not having a mapper is this file.
 *
 * <p>Output is indented two spaces and one field per line, because these files are read in pull
 * requests. Compactness would be the wrong trade for an artifact whose purpose is review.
 */
final class JsonWriter {

    private final StringBuilder out = new StringBuilder();
    private int depth;
    private boolean needsComma;

    String render() {
        return out.toString();
    }

    JsonWriter startObject() {
        separate();
        out.append('{');
        depth++;
        needsComma = false;
        return this;
    }

    JsonWriter endObject() {
        depth--;
        // needsComma is still false when nothing was written into this container, so an empty
        // one closes as "{}" on one line rather than as a bracket pair straddling two.
        if (needsComma) {
            newline();
        }
        out.append('}');
        needsComma = true;
        return this;
    }

    JsonWriter startObject(String key) {
        separate();
        writeKey(key);
        out.append('{');
        depth++;
        needsComma = false;
        return this;
    }

    JsonWriter startArray(String key) {
        separate();
        writeKey(key);
        out.append('[');
        depth++;
        needsComma = false;
        return this;
    }

    JsonWriter endArray() {
        depth--;
        if (needsComma) {
            newline();
        }
        out.append(']');
        needsComma = true;
        return this;
    }

    JsonWriter field(String key, String value) {
        separate();
        writeKey(key);
        writeString(value);
        needsComma = true;
        return this;
    }

    JsonWriter field(String key, long value) {
        separate();
        writeKey(key);
        out.append(value);
        needsComma = true;
        return this;
    }

    /**
     * Writes a rate in {@code [0.0, 1.0]} at fixed precision.
     *
     * <p>Formatted rather than handed to {@code Double.toString} so the output does not depend on
     * the platform's shortest-round-trip rendering, and pinned to {@code Locale.ROOT} because a
     * machine reading this file will not accept the decimal comma a European default would write.
     */
    JsonWriter rate(String key, double value) {
        separate();
        writeKey(key);
        out.append(String.format(Locale.ROOT, "%.4f", value));
        needsComma = true;
        return this;
    }

    /** Writes {@code null} for a null enum, so the field is present and its absence is explicit. */
    JsonWriter field(String key, Enum<?> value) {
        return value == null ? nullField(key) : field(key, value.name());
    }

    JsonWriter nullField(String key) {
        separate();
        writeKey(key);
        out.append("null");
        needsComma = true;
        return this;
    }

    /**
     * Writes an arbitrary evidence value.
     *
     * <p>Evidence is typed {@code Map<String, Object>} so that a rule can attach whatever it
     * observed without every new kind of detail needing a schema change. Everything the rules
     * currently put there is a string, a number, a boolean or a list of strings; anything else
     * is rendered through {@code toString} rather than dropped, because a report that silently
     * omits a rule's evidence is worse than one that renders it awkwardly.
     */
    JsonWriter value(String key, Object value) {
        switch (value) {
            case null -> nullField(key);
            case String s -> field(key, s);
            case Boolean b -> {
                separate();
                writeKey(key);
                out.append(b.booleanValue());
                needsComma = true;
            }
            // Only integral types are emitted unquoted. A double could be NaN or an infinity,
            // neither of which JSON can represent, and Java would happily print both.
            case Byte b -> field(key, b.longValue());
            case Short s -> field(key, s.longValue());
            case Integer i -> field(key, i.longValue());
            case Long l -> field(key, l.longValue());
            case Collection<?> collection -> {
                startArray(key);
                for (Object element : collection) {
                    separate();
                    if (element == null) {
                        out.append("null");
                    } else {
                        writeString(String.valueOf(element));
                    }
                    needsComma = true;
                }
                endArray();
            }
            case Map<?, ?> map -> {
                startObject(key);
                map.forEach((k, v) -> value(String.valueOf(k), v));
                endObject();
            }
            default -> field(key, String.valueOf(value));
        }
        return this;
    }

    /** Opens an element of the enclosing array. */
    JsonWriter startElement() {
        separate();
        out.append('{');
        depth++;
        needsComma = false;
        return this;
    }

    private void writeKey(String key) {
        writeString(key);
        out.append(": ");
    }

    private void separate() {
        if (needsComma) {
            out.append(',');
        }
        newline();
    }

    private void newline() {
        if (out.isEmpty()) {
            return;
        }
        // '\n' rather than the platform separator. The file is a build artifact that gets
        // committed, diffed and compared across machines, so it must not differ between a
        // Windows developer and a Linux CI runner.
        out.append('\n');
        out.append("  ".repeat(depth));
    }

    /**
     * Writes a JSON string, escaping what the grammar requires and what a reader needs to see.
     *
     * <p>The second half is the part worth explaining. Every string here — tool names,
     * descriptions, matched excerpts — is attacker-controlled, and this project exists partly
     * because some of those characters are invisible. A zero-width space or a bidi override
     * written raw into a report renders as nothing at all in the pull request reviewing it,
     * which is precisely the property the attacker chose it for. Escaping is lossless: a parser
     * restores the character, while a human sees {@code ​} and knows it is there. The same
     * reasoning is why baselines escape to printable ASCII.
     *
     * <p>Ordinary non-ASCII is left alone. A Japanese tool description is not an evasion attempt,
     * and mangling it into escape sequences would make the common case unreadable to defend
     * against the rare one.
     */
    private void writeString(String value) {
        out.append('"');
        // Iterated by code point, not by char, so that the Unicode Tags block is recognised.
        // Those live above the basic plane, and a char-wise loop sees only surrogate halves,
        // neither of which is invisible on its own — so the one payload most worth escaping
        // would be the one that slipped through written raw.
        value.codePoints().forEach(cp -> {
            switch (cp) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (cp < 0x20 || TextNormalizer.isInvisible(cp)) {
                        appendEscaped(cp);
                    } else {
                        out.appendCodePoint(cp);
                    }
                }
            }
        });
        out.append('"');
    }

    /** JSON has no {@code \\U} escape, so anything above the basic plane goes out as a pair. */
    private void appendEscaped(int codePoint) {
        for (char unit : Character.toChars(codePoint)) {
            out.append(String.format("\\u%04x", (int) unit));
        }
    }
}
