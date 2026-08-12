package io.github.mcpredteam.core.fingerprint;

import io.github.mcpredteam.core.ToolDefinition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BaselineFormatTest {

    private static final Instant CAPTURED = Instant.parse("2026-08-11T09:14:02.113Z");

    private static ServerFingerprint fingerprintOf(ToolDefinition... tools) {
        return new ServerFingerprint("finance", CAPTURED,
                Arrays.stream(tools).map(ToolFingerprint::of).toList());
    }

    private static ToolDefinition listInvoices() {
        return ToolDefinition.of("finance", "list_invoices", "Lists the user's invoices.",
                Map.of("type", "object",
                        "properties", Map.of("status", Map.of("type", "string", "description", "e.g. open"))));
    }

    @Test
    @DisplayName("a baseline survives a round trip through the file format")
    void roundTrips() {
        ServerFingerprint original = fingerprintOf(listInvoices());
        ServerFingerprint parsed = BaselineFormat.parse(BaselineFormat.render(original), "test");

        assertEquals(original, parsed);
    }

    @Test
    @DisplayName("data lines are sorted, so a change shows up as a diff of the lines that changed")
    void sortsDataLines() {
        String rendered = BaselineFormat.render(fingerprintOf(
                ToolDefinition.of("finance", "send_payment", "Sends a payment.", Map.of()),
                listInvoices()));

        List<String> dataLines = rendered.lines()
                .filter(line -> !line.startsWith("!") && !line.startsWith("#") && !line.isBlank())
                .toList();
        assertEquals(dataLines.stream().sorted().toList(), dataLines);
        assertTrue(dataLines.stream().allMatch(line -> line.split("\t").length == 3));
    }

    @Test
    @DisplayName("a tool name carrying a newline cannot forge extra lines in the file")
    void escapesLineBreaksInNames() {
        ServerFingerprint forged = fingerprintOf(ToolDefinition.of("finance",
                "innocent\nevil_tool\tdescription\t" + "0".repeat(64), "Looks fine.", Map.of()));

        String rendered = BaselineFormat.render(forged);
        assertTrue(rendered.contains("\\u000a"), "The newline must be escaped, not written raw");

        ServerFingerprint parsed = BaselineFormat.parse(rendered, "test");
        assertEquals(1, parsed.size(), "The forged line must not parse as a second tool");
        assertEquals(forged, parsed);
    }

    @Test
    @DisplayName("a look-alike character in a tool name is visible in the file")
    void escapesNonAsciiSoDiffsAreReadable() {
        String cyrillicA = new String(Character.toChars(0x0430));
        String rendered = BaselineFormat.render(fingerprintOf(
                ToolDefinition.of("finance", "send_p" + cyrillicA + "yment", "Sends a payment.", Map.of())));

        assertTrue(rendered.contains("send_p\\u0430yment"),
                "A homoglyph that renders as ASCII must not render as ASCII in the baseline");
    }

    @Test
    @DisplayName("an unsupported format version is refused rather than guessed at")
    void rejectsUnknownVersion() {
        String rendered = BaselineFormat.render(fingerprintOf(listInvoices()))
                .replace("!mcp-redteam-baseline\t1", "!mcp-redteam-baseline\t2");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> BaselineFormat.parse(rendered, "baseline.txt"));
        assertTrue(e.getMessage().contains("version '2'"), e.getMessage());
    }

    @Test
    @DisplayName("a malformed line is refused, with the line number")
    void rejectsMalformedLine() {
        String rendered = BaselineFormat.render(fingerprintOf(listInvoices())) + "list_invoices\tdescription\n";

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> BaselineFormat.parse(rendered, "baseline.txt"));
        assertTrue(e.getMessage().contains("baseline.txt:"), e.getMessage());
    }

    @Test
    @DisplayName("a value where a digest belongs is refused")
    void rejectsNonDigest() {
        String rendered = "!mcp-redteam-baseline\t1\n!server\tfinance\n!capturedAt\t" + CAPTURED + "\n"
                + "list_invoices\tdescription\tnot-a-digest\n";

        assertThrows(IllegalArgumentException.class, () -> BaselineFormat.parse(rendered, "baseline.txt"));
    }

    @Test
    @DisplayName("the same location recorded twice is refused, because the baseline would be ambiguous")
    void rejectsDuplicateLocation() {
        String digest = "0".repeat(64);
        String rendered = "!mcp-redteam-baseline\t1\n!server\tfinance\n!capturedAt\t" + CAPTURED + "\n"
                + "list_invoices\tdescription\t" + digest + "\n"
                + "list_invoices\tdescription\t" + "1".repeat(64) + "\n";

        assertThrows(IllegalArgumentException.class, () -> BaselineFormat.parse(rendered, "baseline.txt"));
    }

    @Test
    @DisplayName("an empty baseline is refused: it would compare against nothing forever")
    void rejectsEmptyBaseline() {
        String rendered = "!mcp-redteam-baseline\t1\n!server\tfinance\n!capturedAt\t" + CAPTURED + "\n";

        assertThrows(IllegalArgumentException.class, () -> BaselineFormat.parse(rendered, "baseline.txt"));
    }

    @Test
    @DisplayName("a byte-order mark from a Windows editor does not invalidate the baseline")
    void toleratesAByteOrderMark() {
        // Found in the pilot: PowerShell's Set-Content -Encoding utf8 writes a BOM, and the
        // parser reported it as "data before the version directive" — a true statement about
        // the wrong problem, on a file whose contents were fine.
        ServerFingerprint original = fingerprintOf(listInvoices());
        String withBom = new String(Character.toChars(0xFEFF)) + BaselineFormat.render(original);

        assertEquals(original, BaselineFormat.parse(withBom, "test"));
    }

    @Test
    @DisplayName("a file written on Windows parses the same as one written on Linux")
    void toleratesCarriageReturns() {
        ServerFingerprint original = fingerprintOf(listInvoices());
        String crlf = BaselineFormat.render(original).replace("\n", "\r\n");

        assertEquals(original, BaselineFormat.parse(crlf, "test"));
    }
}
