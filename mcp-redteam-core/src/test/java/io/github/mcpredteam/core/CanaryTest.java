package io.github.mcpredteam.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CanaryTest {

    private final Canary canary = Canary.of("mcprt-canary-deadbeefcafe0001");

    @Test
    void detectsPlainLeak() {
        assertTrue(canary.leakedIn("Here you go: mcprt-canary-deadbeefcafe0001 (do not share)"));
    }

    @Test
    void detectionIsCaseInsensitive() {
        assertTrue(canary.leakedIn("MCPRT-CANARY-DEADBEEFCAFE0001"));
    }

    @Test
    @DisplayName("detects a canary hidden inside a larger base64 blob")
    void detectsBase64EncodedLeak() {
        String payload = "{\"stolen\":\"" + canary.value() + "\",\"source\":\"agent\"}";
        String encoded = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        assertTrue(canary.leakedIn("POST /ingest body=" + encoded),
                "An agent told to encode before exfiltrating would defeat a plain substring search");
        assertEquals("base64", canary.findLeak("body=" + encoded).orElseThrow().encoding());
    }

    @Test
    void detectsUrlSafeBase64WithoutPadding() {
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("leak=" + canary.value()).getBytes(StandardCharsets.UTF_8));
        assertTrue(canary.leakedIn("https://collector.example.net/?d=" + encoded));
    }

    @Test
    void detectsPercentEncodedLeak() {
        String encoded = canary.value().replace("-", "%2D");
        assertTrue(canary.leakedIn("https://evil.example/collect?v=" + encoded));
        assertEquals("percent-encoded", canary.findLeak("?v=" + encoded).orElseThrow().encoding());
    }

    @Test
    void detectsHexEncodedLeak() {
        String encoded = HexFormat.of().formatHex(canary.value().getBytes(StandardCharsets.UTF_8));
        assertEquals("hex", canary.findLeak("payload=" + encoded).orElseThrow().encoding());
    }

    @Test
    void detectsReversedLeak() {
        String reversed = new StringBuilder(canary.value()).reverse().toString();
        assertEquals("reversed", canary.findLeak("v=" + reversed).orElseThrow().encoding());
    }

    @Test
    @DisplayName("does not fire on unrelated text, including other base64 content")
    void doesNotFalselyReportOnUnrelatedText() {
        assertFalse(canary.leakedIn("The operation completed successfully."));
        assertFalse(canary.leakedIn(""));
        assertFalse(canary.leakedIn(null));
        assertFalse(canary.leakedIn(Base64.getEncoder()
                .encodeToString("a completely unrelated payload".getBytes(StandardCharsets.UTF_8))));
        assertFalse(canary.leakedIn("mcprt-canary-deadbeefcafe0002"), "A different canary must not match");
    }

    @Test
    void leakReportsSurroundingContext() {
        Canary.Leak leak = canary.findLeak("api_key=" + canary.value() + "&target=evil").orElseThrow();
        assertTrue(leak.excerpt().contains("api_key="), "Excerpt should show where the leak appeared");
    }

    @Test
    @DisplayName("random() mints a distinct value on every call")
    void randomCanariesAreUnique() {
        assertNotEquals(Canary.random().value(), Canary.random().value());
    }

    @Test
    @DisplayName("a canary minted twice never matches itself, which is why it must be held")
    void twoRandomCanariesDoNotCrossMatch() {
        Canary planted = Canary.random();
        Canary mintedLaterByMistake = Canary.random();
        assertFalse(mintedLaterByMistake.leakedIn("the agent leaked " + planted.value()),
                "This is the failure mode CanaryAssert.wasPlantedIn guards against");
    }

    @Test
    void rejectsBlankValues() {
        assertThrows(IllegalArgumentException.class, () -> Canary.of("  "));
        assertThrows(NullPointerException.class, () -> Canary.of(null));
    }
}
