package io.github.harikrishna8121999.mcpredteam.mcp;

import io.github.harikrishna8121999.mcpredteam.core.ToolDefinition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the client does when the server is not merely poisoned but actively uncooperative.
 *
 * <p>The rest of the suite points the client at servers that publish an attack honestly. These
 * point it at servers attacking the client itself, which is the failure mode a scanner has to
 * survive to be worth running against something untrusted.
 *
 * <p>The timeout is load-bearing. Every failure here is a hang rather than an assertion error —
 * that is what the attack is — so without it a regression does not turn CI red, it turns CI
 * permanently yellow, which is worse.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class HostileServerTest {

    private static McpServerConnection connect(EndlessPaginationServer fixture, int maxPages) {
        return McpServerConnection.connect("hostile",
                McpServerTarget.streamableHttp(fixture.url()), Duration.ofSeconds(10), maxPages);
    }

    @Test
    @DisplayName("a server that paginates forever is abandoned, not followed forever")
    void endlessPaginationIsCapped() {
        try (EndlessPaginationServer fixture = EndlessPaginationServer.start(false);
             McpServerConnection connection = connect(fixture, 5)) {

            IllegalStateException thrown = assertThrows(IllegalStateException.class, connection::listTools);

            assertEquals(5, fixture.pagesServed().get(), "the cap should be what stopped it");
            assertTrue(thrown.getMessage().contains("pagination cursor"), thrown.getMessage());
            assertTrue(thrown.getMessage().contains("maxPages"),
                    "the message should say how to proceed if the server is genuinely that large: "
                            + thrown.getMessage());
        }
    }

    @Test
    @DisplayName("failing loudly beats returning the pages it did manage to read")
    void cappedPaginationDoesNotReturnPartialResults() {
        // Returning a truncated list would be the worse bug by far: the scan would report on a
        // slice of the server's tools and nothing in the result would say which slice, so a
        // clean report would mean "the first five pages looked fine" while reading as "clean".
        try (EndlessPaginationServer fixture = EndlessPaginationServer.start(false);
             McpServerConnection connection = connect(fixture, 3)) {

            assertThrows(IllegalStateException.class, connection::listTools);
        }
    }

    @Test
    @DisplayName("a server repeating one cursor ends the walk instead of duplicating its tools")
    void repeatedCursorEndsTheWalk() {
        try (EndlessPaginationServer fixture = EndlessPaginationServer.start(true);
             McpServerConnection connection = connect(fixture, 20)) {

            List<ToolDefinition> tools = connection.listTools();

            // Two requests: the first page, then one more that returns the cursor already seen.
            assertEquals(2, fixture.pagesServed().get());
            assertEquals(2, tools.size());
        }
    }
}
