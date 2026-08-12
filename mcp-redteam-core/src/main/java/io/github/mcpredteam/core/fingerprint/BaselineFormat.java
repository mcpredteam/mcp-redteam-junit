package io.github.mcpredteam.core.fingerprint;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The on-disk baseline: one digest per line, sorted, plain text.
 *
 * <p>Fields are tab-separated, written below as {@code <TAB>} because a literal tab in Java
 * source is a whitespace-hook failure and, in a javadoc sample, indistinguishable from indentation:
 *
 * <pre>
 * !mcp-redteam-baseline&lt;TAB&gt;1
 * !server&lt;TAB&gt;finance
 * !capturedAt&lt;TAB&gt;2026-08-11T09:14:02.113Z
 * list_invoices&lt;TAB&gt;description&lt;TAB&gt;3f2a...
 * list_invoices&lt;TAB&gt;inputSchema/properties/status/description&lt;TAB&gt;9ab1...
 * </pre>
 *
 * <p>A line per location rather than a blob per tool, because the file is read by people. When a
 * server changes one parameter description, the diff in the pull request is one line naming that
 * parameter, and a reviewer can see whether the change is the vendor shipping a feature or the
 * vendor being compromised. A single hash per tool would render every change as the same
 * unreadable line, and JSON would render it as a reformatting.
 *
 * <p>Tool names and locations are attacker-controlled, so they are escaped on the way out. Two
 * reasons, and the second is the serious one: a property name containing a tab or a newline could
 * otherwise forge extra lines in a file this class parses back, and a name containing a Cyrillic
 * look-alike would sit in the diff looking exactly like the ASCII one it replaced. Everything
 * outside printable ASCII is written as {@code \\uXXXX}, so what a reviewer sees is what is there.
 */
final class BaselineFormat {

    static final String VERSION = "1";

    private static final String VERSION_DIRECTIVE = "!mcp-redteam-baseline";
    private static final String SERVER_DIRECTIVE = "!server";
    private static final String CAPTURED_AT_DIRECTIVE = "!capturedAt";
    private static final char FIELD = '\t';

    private BaselineFormat() {
    }

    static String render(ServerFingerprint fingerprint) {
        List<String> dataLines = new ArrayList<>();
        for (ToolFingerprint tool : fingerprint.tools()) {
            tool.fieldDigests().forEach((location, digest) ->
                    dataLines.add(escape(tool.toolName()) + FIELD + escape(location) + FIELD + digest));
        }
        dataLines.sort(String::compareTo);

        StringBuilder sb = new StringBuilder()
                .append(VERSION_DIRECTIVE).append(FIELD).append(VERSION).append('\n')
                .append(SERVER_DIRECTIVE).append(FIELD).append(escape(fingerprint.serverName())).append('\n')
                .append(CAPTURED_AT_DIRECTIVE).append(FIELD).append(fingerprint.capturedAt()).append('\n')
                .append("# tool<TAB>location<TAB>sha256 of the raw metadata at that location.\n")
                .append("# Review changes to this file as you would a dependency bump: a line that moves\n")
                .append("# means the server changed what it told the agent after it was trusted.\n");
        for (String line : dataLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    /**
     * Parses a baseline, strictly.
     *
     * <p>Nothing here is repaired or guessed. A baseline that cannot be read exactly is a
     * baseline whose meaning is unknown, and continuing on a best-effort reading would compare
     * a live server against a file this code has silently reinterpreted.
     *
     * @param source where the text came from, for error messages
     */
    static ServerFingerprint parse(String content, String source) {
        String version = null;
        String server = null;
        Instant capturedAt = null;
        // tool name -> location -> digest, keeping tools in first-seen order.
        Map<String, TreeMap<String, String>> byTool = new LinkedHashMap<>();

        // A leading byte-order mark is not corruption, it is a Windows editor. PowerShell's
        // Set-Content, Notepad and several IDEs write one, and UTF-8 decoding keeps it as a
        // character — which would otherwise turn a perfectly good baseline into "data before the
        // version directive", a message pointing at the wrong problem entirely.
        String[] lines = stripByteOrderMark(content).split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            int lineNumber = i + 1;
            String line = lines[i].endsWith("\r") ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }

            if (line.startsWith("!")) {
                String[] directive = line.split(String.valueOf(FIELD), -1);
                if (directive.length != 2) {
                    throw fail(source, lineNumber, "a directive must be '!name<TAB>value'");
                }
                switch (directive[0]) {
                    case VERSION_DIRECTIVE -> version = directive[1];
                    case SERVER_DIRECTIVE -> server = unescape(directive[1], source, lineNumber);
                    case CAPTURED_AT_DIRECTIVE -> capturedAt = parseInstant(directive[1], source, lineNumber);
                    default -> throw fail(source, lineNumber, "unknown directive '" + directive[0] + "'");
                }
                continue;
            }

            if (version == null) {
                throw fail(source, lineNumber, "data before the " + VERSION_DIRECTIVE + " directive");
            }
            String[] fields = line.split(String.valueOf(FIELD), -1);
            if (fields.length != 3) {
                throw fail(source, lineNumber, "expected tool<TAB>location<TAB>digest but found "
                        + fields.length + " field(s)");
            }
            String toolName = unescape(fields[0], source, lineNumber);
            String location = unescape(fields[1], source, lineNumber);
            if (!Digests.isDigest(fields[2])) {
                throw fail(source, lineNumber, "'" + fields[2] + "' is not a lowercase hex SHA-256 digest");
            }
            String previous = byTool.computeIfAbsent(toolName, k -> new TreeMap<>()).put(location, fields[2]);
            if (previous != null) {
                throw fail(source, lineNumber, "location '" + location + "' recorded twice for tool '"
                        + toolName + "'; which digest is the baseline is undefined");
            }
        }

        if (version == null) {
            throw fail(source, 0, "missing the " + VERSION_DIRECTIVE + " directive");
        }
        if (!VERSION.equals(version)) {
            throw fail(source, 0, "baseline format version '" + version + "' is not supported by this release"
                    + " (expected " + VERSION + "); re-capture the baseline");
        }
        if (server == null || capturedAt == null) {
            throw fail(source, 0, "missing the " + SERVER_DIRECTIVE + " or " + CAPTURED_AT_DIRECTIVE + " directive");
        }

        String serverName = server;
        List<ToolFingerprint> tools = new ArrayList<>();
        byTool.forEach((toolName, digests) -> tools.add(new ToolFingerprint(serverName, toolName, digests)));
        if (tools.isEmpty()) {
            throw fail(source, 0, "no tools recorded; a baseline of nothing checks nothing");
        }
        return new ServerFingerprint(server, capturedAt, tools);
    }

    /** U+FEFF, written as a code point because a literal would be invisible in review. */
    private static final char BYTE_ORDER_MARK = (char) 0xFEFF;

    private static String stripByteOrderMark(String content) {
        return !content.isEmpty() && content.charAt(0) == BYTE_ORDER_MARK ? content.substring(1) : content;
    }

    /** Escapes to printable ASCII, so a diff shows what the bytes are rather than how they render. */
    private static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\') {
                sb.append("\\\\");
            } else if (c >= 0x20 && c <= 0x7E) {
                sb.append(c);
            } else {
                sb.append(String.format("\\u%04x", (int) c));
            }
        }
        return sb.toString();
    }

    private static String unescape(String value, String source, int lineNumber) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (i + 1 >= value.length()) {
                throw fail(source, lineNumber, "a value ends with a dangling backslash");
            }
            char next = value.charAt(++i);
            if (next == '\\') {
                sb.append('\\');
            } else if (next == 'u' && i + 4 < value.length()) {
                String hex = value.substring(i + 1, i + 5);
                try {
                    sb.append((char) Integer.parseInt(hex, 16));
                } catch (NumberFormatException e) {
                    throw fail(source, lineNumber, "'\\u" + hex + "' is not a valid escape");
                }
                i += 4;
            } else {
                throw fail(source, lineNumber, "'\\" + next + "' is not a valid escape");
            }
        }
        return sb.toString();
    }

    private static Instant parseInstant(String value, String source, int lineNumber) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw fail(source, lineNumber, "'" + value + "' is not an ISO-8601 instant");
        }
    }

    private static IllegalArgumentException fail(String source, int lineNumber, String problem) {
        String where = lineNumber > 0 ? source + ":" + lineNumber : source;
        return new IllegalArgumentException("Malformed MCP baseline at " + where + ": " + problem);
    }
}
