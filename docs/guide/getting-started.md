# Getting started

Fifteen minutes, no model, no API key. At the end you will have an MCP security check that fails
your build when a connected server publishes poisoned tool metadata.

## Prerequisites

- **JDK 21 or newer.** The library is built and tested on 21 and 25.
- **JUnit 5.** JUnit 6 is not supported yet — see [Versioning](#versioning-and-stability).
- Maven or Gradle.

## 1. Add the dependencies

```xml
<dependency>
    <groupId>io.github.mcpredteam</groupId>
    <artifactId>mcp-redteam-junit</artifactId>
    <version>0.2.0</version>
    <scope>test</scope>
</dependency>

<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.11.4</version>
    <scope>test</scope>
</dependency>
```

The library ships only `junit-jupiter-api`, never the engine, so it cannot drag your test runtime
onto a version you did not choose. If you already have JUnit 5 configured, the second block is
already in your build.

Gradle and the other modules are covered in [Choosing your modules](installation.md).

## 2. Write the test

`MetadataScanner` takes a list of `ToolDefinition` and returns a `ScanReport`. Where the
definitions come from is up to you — a hand-written catalog, your MCP client's `tools/list`
response, or a [live server connection](scanning-a-live-server.md).

```java
import io.github.mcpredteam.core.Confidence;
import io.github.mcpredteam.core.MetadataScanner;
import io.github.mcpredteam.core.ScanReport;
import io.github.mcpredteam.core.ToolDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.github.mcpredteam.junit.McpSecurityAssertions.assertThat;

class McpSecurityTest {

    @Test
    void connectedMcpServersExposeNoPoisonedToolMetadata() {
        List<ToolDefinition> tools = List.of(
                ToolDefinition.of("notes", "search_notes",
                        "Full-text search over the user's notes, ranked by relevance.",
                        Map.of("type", "object",
                                "properties", Map.of(
                                        "query", Map.of("type", "string", "description", "Search query")))));

        ScanReport report = MetadataScanner.withDefaultRules().scan(tools);

        assertThat(report)
                .ignoringConfidenceBelow(Confidence.FIRM)
                .hasNoHighRiskFindings();
    }
}
```

### Building a `ToolDefinition`

```java
// Short form: server, name, description, input schema.
ToolDefinition.of("notes", "search_notes", "Full-text search…", schemaMap);

// Long form, when you have a display title, output schema and annotations.
new ToolDefinition("notes", "delete_note", "Delete note",
        "Permanently deletes a note from the workspace.",
        inputSchema,
        Map.of(),                                              // output schema
        Map.of("destructiveHint", true, "readOnlyHint", false));
```

The `serverName` is your label for the server, used in every finding. It is deliberately *not*
whatever name the server reports for itself: that is a claim, not an identity, and a report
repeating it back would launder a hostile server's chosen branding into evidence.

## 3. Read a failure

Add a tool with a poisoned description and the assertion fails like this — real output from
[`examples/scan-only`](../../examples/scan-only):

```
Expected no MCP security findings at or above HIGH (confidence >= TENTATIVE), but found 2:

[CRITICAL] MCPRT-INJ-001 (MCP03 Tool Poisoning, confidence=CERTAIN)
    where: pdf-cloud/render_pdf @ description
    what:  Tool metadata instructs the agent to discard its previous instructions.
    match: Ignore all previous instructions
    fix:   Tool metadata is read by the model but not shown to the user. Remove directive
           language, or stop exposing this server to the agent.
```

Every finding carries five things: **where** (server, tool, exact schema path), **what**,
**match** (the text that tripped it), the **OWASP MCP Top 10** category, and a **fix**.

## 4. Choose your gate

Findings carry a `Confidence` *and* a `Severity`, and both matter.

| Assertion | Use when |
| --- | --- |
| `hasNoHighRiskFindings()` | The common gate. HIGH and CRITICAL break the build. |
| `hasNoFindingsAtOrAbove(Severity.MEDIUM)` | Stricter — you also want credential-shaped parameters and unannotated destructive tools. |
| `isClean()` | Nothing at all. Realistic only for a server you control. |
| `hasFinding("MCPRT-INJ")` | Asserting a scanner *does* fire — for testing the scanner, or a known-bad fixture. |
| `hasNoFindingFrom("MCPRT-CAP")` | Suppressing one rule family with the decision visible in the test. |

Recommended starting point:

```java
assertThat(report)
        .ignoringConfidenceBelow(Confidence.FIRM)
        .hasNoHighRiskFindings();
```

`FIRM` and above are things the scanner is confident about. `TENTATIVE` findings — imperative
phrasing, credential-shaped parameter names — are worth a human read but will produce noise as a
build gate, and a scanner people mute is not a control.

See the [rules reference](rules.md) for what sits at each level.

## 5. The test that stops this from being theatre

Assert the scanner stays **quiet** on your honest tools, not only that it fires on bad ones:

```java
@Test
void ordinaryWordsDoNotTripTheScanner() {
    ScanReport report = MetadataScanner.withDefaultRules().scan(ourRealToolCatalog());

    assertThat(report)
            .hasNoFindingFrom("MCPRT-ENC")    // our export tool legitimately says "base64"
            .hasNoFindingFrom("MCPRT-CAP");   // our delete tool declares destructiveHint
}
```

This is the half that usually goes missing. A scanner that fires on `delete_note` and on a
description containing the word "credentials" gets muted within a sprint, and then it is not there
when a real poisoned tool arrives.

## 6. Wire it into CI

Nothing special is required — it is a JUnit test, so `mvn test` already runs it. Two things worth
adding:

**Write a report artifact** so a reviewer can see what was found without reading build logs:

```java
Reports.json(report).writeTo(Path.of("target/mcp-redteam/scan.json"));
```

See [Reports](reports.md).

**Assert the scan examined something.** A scan over zero tools finds zero findings, which renders
as a green build indistinguishable from a clean server:

```java
assertFalse(tools.isEmpty(), "no tools were scanned — this proved nothing");
```

The library takes the same precaution internally: the JUnit XML report carries a `scan executed`
case that fails in that state, and the dynamic side raises `MCPRT-RUN-001`.

## Where to go next

- Your tool list should come from the real server, not a hand-written copy →
  **[Scanning a live server](scanning-a-live-server.md)**
- The server was clean when you approved it; is it still? →
  **[Catching a rug pull](rug-pull.md)**
- You run a Spring AI agent and want to know if a model can be talked into it →
  **[Testing an agent](agent-testing.md)**

## Versioning and stability

`0.2.0` is current; `0.1.0` was the first release. Before 1.0 the public API may break in a
minor release.

Detection rules are treated differently: a rule that starts catching something it used to miss is
a *fix*, not a break, and can land in a patch release. If a new rule turning your build red
without warning is unacceptable, gate on `hasNoFindingsAtOrAbove(...)` with an explicit severity
rather than on a finding count, and pin an exact version.

JUnit 5 is the baseline deliberately. The point of this library is that it drops into a build a
team already runs, which fails if it forces a JUnit major upgrade. JUnit 6 support is a later
question, not an oversight.
