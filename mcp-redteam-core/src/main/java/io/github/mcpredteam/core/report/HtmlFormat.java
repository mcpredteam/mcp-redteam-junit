package io.github.mcpredteam.core.report;

import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.TextNormalizer;
import io.github.mcpredteam.core.ThreatType;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The scan as a single self-contained HTML page, for reading rather than parsing.
 *
 * <p>This is the format for a human who has been handed a build artifact: a CI job uploads it, a
 * reviewer opens it, and the findings are legible without a JSON viewer or a Java toolchain. It
 * is deliberately the <em>least</em> capable of the three formats — use {@link Reports#json} when
 * something is going to parse the result, and {@code junitXml} when a CI UI should track findings
 * as individual cases.
 *
 * <p>Three constraints shape the output, and all three are security properties rather than taste:
 *
 * <ul>
 *   <li><strong>One file, no external references.</strong> No CDN stylesheet, no web font, no
 *       remote image. A report that fetches a resource in order to display itself is a security
 *       artifact that phones out when opened, from a machine that has just been told it may be
 *       compromised — and it renders wrong from {@code file://} or an offline CI viewer, which is
 *       where these are actually read.
 *   <li><strong>No JavaScript.</strong> Nothing here needs it, many artifact viewers strip or
 *       sandbox it, and a page that renders attacker-controlled strings has no business also
 *       carrying a script for them to end up inside.
 *   <li><strong>Deterministic.</strong> Same scan in, same bytes out. Everything that moves
 *       between two scans of an unchanged server is confined to the one {@code scan} block near
 *       the top, so a diff of two reports shows the findings changing or shows nothing.
 * </ul>
 *
 * <p>Like the JUnit XML format, this one carries an explicit <strong>empty-scan banner</strong>.
 * Zero tools scanned produces zero findings, which would otherwise render as a reassuring page
 * with an empty findings list — visually identical to a server that was examined and found clean.
 * That is the vacuous pass wearing a new costume, and every output surface this project adds gets
 * a guard against it.
 */
final class HtmlFormat {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    /** Highest first, so the band reads in the order a reader triages in. */
    private static final List<Severity> BAND =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO);

    private HtmlFormat() {
    }

    static String render(ScanReport report) {
        List<Finding> findings = report.byRisk();
        Map<Severity, Long> counts = report.countsBySeverity();
        boolean scanExecuted = report.toolsScanned() > 0;

        StringBuilder html = new StringBuilder(4096);
        html.append("<!doctype html>\n<html lang=\"en\">\n<head>\n")
                .append("<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>").append(text(BuildInfo.NAME + " scan — " + report.summary()))
                .append("</title>\n<style>\n").append(css()).append("</style>\n</head>\n<body>\n");

        html.append("<header>\n<h1>").append(text(BuildInfo.NAME)).append("</h1>\n")
                .append("<p class=\"summary\">").append(text(report.summary())).append("</p>\n</header>\n");

        if (!scanExecuted) {
            html.append("<div class=\"banner\" role=\"alert\">\n")
                    .append("<strong>No tools were scanned, so this report establishes nothing.</strong>\n")
                    .append("<p>A scan over zero tools finds zero problems. That is not a clean result, it is"
                            + " an absent one. Check that the tool list reached the scanner — a server-name"
                            + " typo and a server that published nothing both look like this.</p>\n")
                    .append("</div>\n");
        }

        html.append("<section class=\"band\">\n");
        for (Severity severity : BAND) {
            long count = counts.getOrDefault(severity, 0L);
            html.append("<div class=\"tile sev-").append(severity.name())
                    .append(count == 0 ? " zero" : "").append("\">")
                    .append("<span class=\"count\">").append(count).append("</span>")
                    .append("<span class=\"label\">").append(severity.name()).append("</span>")
                    .append("</div>\n");
        }
        html.append("</section>\n");

        // Everything volatile lives here and nowhere else, so re-scanning an unchanged server
        // moves these lines and leaves every finding below byte-identical.
        html.append("<section class=\"scan\">\n<dl>\n");
        detail(html, "Scanned", report.toolsScanned() + " tool(s)");
        detail(html, "Started", TIMESTAMP.format(report.startedAt()));
        detail(html, "Duration", String.format(Locale.ROOT, "%.3f s", report.duration().toMillis() / 1000.0));
        detail(html, "Producer", BuildInfo.NAME + " " + BuildInfo.version());
        detail(html, "Taxonomy", ThreatType.TAXONOMY + " " + ThreatType.TAXONOMY_VERSION);
        html.append("</dl>\n</section>\n");

        html.append("<main>\n");
        if (findings.isEmpty()) {
            html.append("<p class=\"none\">No findings.</p>\n");
        } else {
            for (Finding finding : findings) {
                writeFinding(html, finding);
            }
        }
        html.append("</main>\n</body>\n</html>\n");

        return html.toString();
    }

    private static void writeFinding(StringBuilder html, Finding finding) {
        html.append("<article class=\"finding sev-").append(finding.severity().name()).append("\">\n")
                .append("<h2>")
                .append("<span class=\"chip\">").append(finding.severity().name()).append("</span> ")
                .append("<span class=\"rule\">").append(text(finding.ruleId())).append("</span>")
                .append("</h2>\n")
                .append("<p class=\"owasp\">")
                .append(text(finding.threatType().owaspId() + " " + finding.threatType().owaspTitle()))
                .append(" · confidence ").append(finding.confidence().name())
                .append("</p>\n<dl>\n");

        String where = finding.location() == null || finding.location().isBlank()
                ? finding.target()
                : finding.target() + " @ " + finding.location();
        detail(html, "Where", where);
        detail(html, "What", finding.message());
        if (finding.remediation() != null && !finding.remediation().isBlank()) {
            detail(html, "Fix", finding.remediation());
        }
        html.append("</dl>\n");

        if (!finding.evidence().isEmpty()) {
            html.append("<dl class=\"evidence\">\n");
            // Insertion order, which Finding preserves deliberately: rules put the matched text
            // first, and that is the line a reader wants before any of the supporting detail.
            for (Map.Entry<String, Object> entry : finding.evidence().entrySet()) {
                detailPre(html, entry.getKey(), String.valueOf(entry.getValue()));
            }
            html.append("</dl>\n");
        }

        html.append("</article>\n");
    }

    private static void detail(StringBuilder html, String term, String value) {
        html.append("<dt>").append(text(term)).append("</dt><dd>").append(text(value)).append("</dd>\n");
    }

    /**
     * A detail whose value is rendered in a monospaced, wrapping block.
     *
     * <p>Used for evidence, because that is the attacker's text verbatim: escape sequences,
     * padding and runs of whitespace are the content, and proportional type quietly collapses
     * exactly the detail that matters.
     */
    private static void detailPre(StringBuilder html, String term, String value) {
        html.append("<dt>").append(text(term)).append("</dt><dd><pre>")
                .append(text(value)).append("</pre></dd>\n");
    }

    /**
     * Escapes text for HTML, and renders control and invisible characters as visible
     * {@code \\uXXXX} instead of passing them through.
     *
     * <p>The escaping half is ordinary. The visibility half is the point: every string on this
     * page — tool names, descriptions, matched excerpts — is attacker-controlled, and a
     * zero-width space, a bidi override or a Unicode tag character written raw into HTML renders
     * as <em>nothing at all</em>. That is the property the attacker picked it for, and this page
     * is the evidence for a finding that exists because the character is there. A reader must be
     * able to see it. The same reasoning governs the JSON writer and the fingerprint baselines.
     *
     * <p>Ordinary non-ASCII is left alone. A Japanese tool description is not an evasion attempt.
     */
    private static String text(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        // By code point rather than by char, so the Unicode Tags block is seen. Those live above
        // the basic plane, and a char-wise loop sees only surrogate halves - neither invisible on
        // its own, so the payload most worth escaping is the one that would slip through raw.
        value.codePoints().forEach(cp -> {
            switch (cp) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                case '\n' -> sb.append('\n');
                default -> {
                    if (cp < 0x20 || cp == 0x7F || TextNormalizer.isInvisible(cp)) {
                        for (char unit : Character.toChars(cp)) {
                            sb.append(String.format("\\u%04x", (int) unit));
                        }
                    } else {
                        sb.appendCodePoint(cp);
                    }
                }
            }
        });
        return sb.toString();
    }

    private static String css() {
        return """
                :root {
                  --bg: #ffffff; --fg: #1f2328; --muted: #656d76; --line: #d0d7de;
                  --card: #f6f8fa; --banner-bg: #fff8c5; --banner-fg: #7d4e00;
                  --CRITICAL: #8b0000; --HIGH: #d1242f; --MEDIUM: #bc4c00;
                  --LOW: #0969da; --INFO: #656d76;
                }
                @media (prefers-color-scheme: dark) {
                  :root {
                    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #30363d;
                    --card: #161b22; --banner-bg: #341a00; --banner-fg: #f0b72f;
                    --CRITICAL: #ff7b72; --HIGH: #ff7b72; --MEDIUM: #d29922;
                    --LOW: #58a6ff; --INFO: #9198a1;
                  }
                }
                * { box-sizing: border-box; }
                body {
                  margin: 0 auto; padding: 2rem 1.25rem; max-width: 60rem;
                  background: var(--bg); color: var(--fg);
                  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                }
                h1 { font-size: 1.35rem; margin: 0; }
                .summary { color: var(--muted); margin: .35rem 0 1.5rem; }
                .banner {
                  background: var(--banner-bg); color: var(--banner-fg);
                  border: 1px solid currentColor; border-radius: 6px;
                  padding: .9rem 1.1rem; margin-bottom: 1.5rem;
                }
                .banner p { margin: .5rem 0 0; }
                .band { display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.5rem; }
                .tile {
                  flex: 1 1 6rem; display: flex; flex-direction: column; align-items: center;
                  padding: .8rem .5rem; border: 1px solid var(--line); border-radius: 6px;
                  background: var(--card);
                }
                .tile .count { font-size: 1.6rem; font-weight: 700; line-height: 1; }
                .tile .label { font-size: .7rem; letter-spacing: .06em; color: var(--muted); margin-top: .3rem; }
                .tile.zero .count { color: var(--muted); opacity: .5; }
                .tile.sev-CRITICAL .count { color: var(--CRITICAL); }
                .tile.sev-HIGH .count { color: var(--HIGH); }
                .tile.sev-MEDIUM .count { color: var(--MEDIUM); }
                .tile.sev-LOW .count { color: var(--LOW); }
                .tile.sev-INFO .count { color: var(--INFO); }
                .scan { border: 1px solid var(--line); border-radius: 6px; padding: .5rem 1rem; margin-bottom: 2rem; }
                .none { color: var(--muted); }
                dl { display: grid; grid-template-columns: 6.5rem 1fr; gap: .35rem 1rem; margin: .6rem 0; }
                dt { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; padding-top: .15rem; }
                dd { margin: 0; min-width: 0; }
                .finding {
                  border: 1px solid var(--line); border-left: 4px solid var(--INFO);
                  border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1rem;
                }
                .finding.sev-CRITICAL { border-left-color: var(--CRITICAL); }
                .finding.sev-HIGH { border-left-color: var(--HIGH); }
                .finding.sev-MEDIUM { border-left-color: var(--MEDIUM); }
                .finding.sev-LOW { border-left-color: var(--LOW); }
                .finding h2 { font-size: 1rem; margin: 0; display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
                .chip {
                  font-size: .68rem; font-weight: 700; letter-spacing: .06em;
                  border: 1px solid currentColor; border-radius: 999px; padding: .1rem .55rem;
                }
                .sev-CRITICAL .chip { color: var(--CRITICAL); }
                .sev-HIGH .chip { color: var(--HIGH); }
                .sev-MEDIUM .chip { color: var(--MEDIUM); }
                .sev-LOW .chip { color: var(--LOW); }
                .sev-INFO .chip { color: var(--INFO); }
                .rule { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
                .owasp { color: var(--muted); font-size: .85rem; margin: .4rem 0 0; }
                .evidence { border-top: 1px solid var(--line); padding-top: .7rem; margin-top: .9rem; }
                pre {
                  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                  font-size: .82rem; background: var(--card); border-radius: 4px;
                  padding: .45rem .6rem; margin: 0;
                  white-space: pre-wrap; overflow-wrap: anywhere;
                }
                @media (max-width: 34rem) {
                  dl { grid-template-columns: 1fr; gap: .1rem; }
                  dt { margin-top: .5rem; }
                }
                """;
    }
}
