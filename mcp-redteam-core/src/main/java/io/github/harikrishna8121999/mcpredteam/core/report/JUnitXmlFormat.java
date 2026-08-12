package io.github.harikrishna8121999.mcpredteam.core.report;

import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.TextNormalizer;
import io.github.harikrishna8121999.mcpredteam.core.ThreatType;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * The scan as a JUnit XML test suite, so findings show up in a CI build UI.
 *
 * <p>Surefire already writes JUnit XML for the tests themselves, so this only earns its place by
 * being finer-grained than "one assertion failed with a long message". <strong>Each finding
 * becomes its own {@code <testcase>}</strong>, grouped by the tool it was found on:
 *
 * <pre>{@code
 * evil-analytics/record_analytics
 *     MCPRT-INJ-001 @ description                    failed
 *     MCPRT-EXF-002 @ inputSchema/properties/url     failed
 * }</pre>
 *
 * <p>which is a list a developer can work through, and which lets a CI system track a single
 * finding appearing and disappearing across builds.
 *
 * <p>The suite also carries a {@code scan executed} case, which <em>fails</em> when no tools
 * were scanned. A scan of nothing reports no findings, and in this format that would render as
 * a green suite — indistinguishable from a server that was examined and found clean. The same
 * reasoning produces {@code MCPRT-RUN-001} on the dynamic side: a security check that reports
 * safety it never established is the failure this project is built around, and a new output
 * format is a new place for it to hide. Note this affects the artifact only; the build gate is
 * still whatever the test asserts.
 */
final class JUnitXmlFormat {

    private static final String SUITE = "mcp-redteam";

    /**
     * Local date-time with no offset. The JUnit schema's {@code timestamp} is an {@code
     * xs:dateTime} that several consumers reject when it carries a zone, so the instant is
     * rendered at UTC and the marker dropped.
     */
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss").withZone(ZoneOffset.UTC);

    private JUnitXmlFormat() {
    }

    static String render(ScanReport report) {
        List<Finding> findings = report.byRisk();
        boolean scanExecuted = report.toolsScanned() > 0;
        int tests = findings.size() + 1;
        int failures = findings.size() + (scanExecuted ? 0 : 1);

        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<testsuite name=\"").append(SUITE).append('"')
                .append(" tests=\"").append(tests).append('"')
                .append(" failures=\"").append(failures).append('"')
                .append(" errors=\"0\" skipped=\"0\"")
                .append(" time=\"").append(seconds(report.duration().toMillis())).append('"')
                .append(" timestamp=\"").append(TIMESTAMP.format(report.startedAt())).append("\">\n");

        xml.append("  <properties>\n");
        property(xml, "producer", BuildInfo.NAME + " " + BuildInfo.version());
        property(xml, "taxonomy", ThreatType.TAXONOMY + " " + ThreatType.TAXONOMY_VERSION);
        property(xml, "toolsScanned", String.valueOf(report.toolsScanned()));
        xml.append("  </properties>\n");

        xml.append("  <testcase classname=\"").append(SUITE).append("\" name=\"scan executed\" time=\"0\"");
        if (scanExecuted) {
            xml.append("/>\n");
        } else {
            xml.append(">\n")
                    .append("    <failure message=\"")
                    .append(attribute("No tools were scanned, so this report establishes nothing"))
                    .append("\" type=\"empty-scan\">")
                    .append(text("A scan over zero tools finds zero problems. That is not a clean result, it is"
                            + " an absent one. Check that the tool list reached the scanner - a server-name typo"
                            + " and a server that published nothing both look like this."))
                    .append("</failure>\n")
                    .append("  </testcase>\n");
        }

        for (Finding finding : findings) {
            writeFinding(xml, finding);
        }

        return xml.append("</testsuite>\n").toString();
    }

    private static void writeFinding(StringBuilder xml, Finding finding) {
        String name = finding.location() == null || finding.location().isBlank()
                ? finding.ruleId()
                : finding.ruleId() + " @ " + finding.location();

        xml.append("  <testcase classname=\"").append(attribute(finding.target())).append('"')
                .append(" name=\"").append(attribute(name)).append('"')
                .append(" time=\"0\">\n")
                .append("    <failure message=\"")
                .append(attribute("[" + finding.severity() + "] " + finding.message()))
                .append("\" type=\"").append(attribute(finding.ruleId())).append("\">")
                .append(text(finding.describe()))
                .append("</failure>\n")
                .append("  </testcase>\n");
    }

    private static void property(StringBuilder xml, String name, String value) {
        xml.append("    <property name=\"").append(attribute(name))
                .append("\" value=\"").append(attribute(value)).append("\"/>\n");
    }

    private static String seconds(long millis) {
        return String.format(Locale.ROOT, "%.3f", millis / 1000.0);
    }

    /**
     * Escapes an attribute value, additionally folding the line breaks a hostile description can
     * contain. XML says an attribute's newlines are normalized to spaces on parse, so leaving
     * them raw makes a file whose meaning changes when it is read back.
     */
    private static String attribute(String value) {
        return escape(value, true);
    }

    /**
     * Escapes body text, first folding CRLF to LF.
     *
     * <p>{@code Finding#describe} builds its lines with the platform separator, which is correct
     * for a console and wrong for an artifact: the same scan would otherwise produce different
     * bytes on a Windows developer's machine and on a Linux CI runner. An XML parser normalizes
     * the difference away on read, so nothing is lost by settling it on write.
     */
    private static String text(String value) {
        return escape(value.replace("\r\n", "\n"), false);
    }

    /**
     * XML escaping, plus the part that is easy to miss: <strong>most C0 control characters
     * cannot appear in an XML 1.0 document at all</strong>, not even as a numeric reference.
     * Only tab, newline and carriage return are legal. A tool description carrying a {@code 0x01}
     * — and hostile ones do, which is why {@code MCPRT-UNI} exists — would therefore produce a
     * report file that no CI system can parse, turning a detected attack into a broken build with
     * an unrelated-looking error.
     *
     * <p>Illegal code points are rendered as visible {@code \\uXXXX} text rather than dropped.
     * Dropping is how a payload becomes invisible in the artifact that is supposed to be the
     * evidence for it. The same is done to the invisible-but-legal characters, for the same
     * reason baselines escape them: what a reviewer sees should be what is there.
     */
    private static String escape(String value, boolean isAttribute) {
        StringBuilder sb = new StringBuilder(value.length());
        value.codePoints().forEach(cp -> {
            switch (cp) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&apos;");
                default -> {
                    if (isAttribute && (cp == '\n' || cp == '\r' || cp == '\t')) {
                        sb.append(switch (cp) {
                            case '\t' -> "&#9;";
                            case '\n' -> "&#10;";
                            default -> "&#13;";
                        });
                    } else if (isLegalInXml(cp) && !TextNormalizer.isInvisible(cp)) {
                        sb.appendCodePoint(cp);
                    } else {
                        for (char unit : Character.toChars(cp)) {
                            sb.append(String.format("\\u%04x", (int) unit));
                        }
                    }
                }
            }
        });
        return sb.toString();
    }

    /** The {@code Char} production of XML 1.0, fifth edition. */
    private static boolean isLegalInXml(int cp) {
        return cp == 0x9 || cp == 0xA || cp == 0xD
                || (cp >= 0x20 && cp <= 0xD7FF)
                || (cp >= 0xE000 && cp <= 0xFFFD)
                || (cp >= 0x10000 && cp <= 0x10FFFF);
    }
}
