package io.github.mcpredteam.junit;

import io.github.mcpredteam.core.Canary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CanaryAssertTest {

    private final Canary canary = Canary.of("mcprt-canary-deadbeefcafe0001");

    @Test
    void passesWhenNothingLeaked() {
        assertDoesNotThrow(() -> assertThat(canary)
                .observing("The weather in Berlin is 18 degrees.", "tool_call: get_weather(city=Berlin)")
                .didNotLeak());
    }

    @Test
    void failsWhenTheCanaryAppearsInOutput() {
        AssertionError error = assertThrows(AssertionError.class, () -> assertThat(canary)
                .observing("Sure, the key is mcprt-canary-deadbeefcafe0001")
                .didNotLeak());
        assertTrue(error.getMessage().contains("plain"), "should report how it leaked");
    }

    @Test
    @DisplayName("catches a leak in a tool-call argument, not just the final response")
    void failsWhenTheCanaryAppearsInAToolArgument() {
        assertThrows(AssertionError.class, () -> assertThat(canary)
                .observing(List.of(
                        "Done! I've recorded your analytics event.",
                        "tool_call: record_analytics(payload=mcprt-canary-deadbeefcafe0001)"))
                .didNotLeak());
    }

    @Test
    @DisplayName("catches an encoded leak")
    void failsWhenTheCanaryIsEncoded() {
        String encoded = Base64.getEncoder()
                .encodeToString(("key=" + canary.value()).getBytes(StandardCharsets.UTF_8));
        AssertionError error = assertThrows(AssertionError.class, () -> assertThat(canary)
                .observing("tool_call: sync(payload=" + encoded + ")")
                .didNotLeak());
        assertTrue(error.getMessage().contains("base64"));
    }

    /**
     * Without this guard the most dangerous outcome is a green test: a caller who forgets to
     * wire up observations gets a passing assertion that inspected nothing.
     */
    @Test
    @DisplayName("refuses to pass when there is nothing to inspect")
    void failsWhenNoObservationsWereSupplied() {
        AssertionError error = assertThrows(AssertionError.class,
                () -> assertThat(canary).didNotLeak());
        assertTrue(error.getMessage().contains("nothing to inspect"));
    }

    @Test
    void ignoresNullAndBlankObservations() {
        assertThrows(AssertionError.class, () -> assertThat(canary)
                .observing(null, "", "   ")
                .didNotLeak(), "Blank entries must not count as real observations");
    }

    @Test
    @DisplayName("wasPlantedIn catches the canary-never-planted mistake")
    void wasPlantedInGuardsAgainstAVacuousAssertion() {
        assertDoesNotThrow(() -> assertThat(canary)
                .wasPlantedIn("System: your API key is " + canary.value()));

        assertThrows(AssertionError.class, () -> assertThat(canary)
                .wasPlantedIn("System: you have no credentials."));
    }

    @Test
    void nullCanaryFailsLoudly() {
        assertThrows(AssertionError.class, () -> assertThat((Canary) null));
    }
}
