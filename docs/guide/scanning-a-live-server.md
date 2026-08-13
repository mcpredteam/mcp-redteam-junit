# Scanning a live server

Nobody maintains a hand-written copy of their tool catalog, and a copy that drifts from the server
is worse than no check at all. `McpServerConnection` fetches `tools/list` over the real protocol
and hands you the same `ToolDefinition` objects the scanner takes.

Needs `mcp-redteam-mcp` **and** the MCP SDK — see [Choosing your modules](installation.md). Still
no model, no agent, no API key.

## Streamable HTTP

```java
try (McpServerConnection vendor = McpServerConnection.connect(
        "invoice-insights", McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp"))) {

    assertThat(vendor.scan()).hasNoFindingsAtOrAbove(Severity.HIGH);
}
```

Add headers when the server needs auth:

```java
McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp")
        .withHeader("Authorization", "Bearer " + token);
```

## stdio

```java
try (McpServerConnection local = McpServerConnection.connect(
        "vendor-tools", McpServerTarget.stdio("npx", "-y", "@vendor/mcp-server"))) {

    assertThat(local.scan()).hasNoFindingsAtOrAbove(Severity.HIGH);
}
```

`.withEnv(key, value)` adds environment variables for the child process.

> **Launching a stdio server runs an arbitrary program with your privileges**, before `tools/list`
> can tell you anything about it. Scanning a stdio server is a strictly weaker safeguard than not
> running it. For an untrusted vendor, prefer the HTTP transport or a sandbox.

## What the name means

```java
McpServerConnection.connect("invoice-insights", target);
//                           ^^^^^^^^^^^^^^^^^ your label, not the server's claim
```

The first argument is *your* label, used in every finding and every baseline line. It is
deliberately not the name the server reports for itself: that is a claim, not an identity, and a
report that repeated it back would launder a hostile server's chosen branding into evidence. The
server's self-reported identity is still available via `declaredServerInfo()` if you want to
assert on it.

## The API

| Method | Returns |
| --- | --- |
| `listTools()` | `List<ToolDefinition>` — the raw catalog |
| `scan()` | `ScanReport` from the default rules |
| `scan(McpSecurityScanner)` | `ScanReport` from a scanner you configured (suppressions, custom rules) |
| `captureBaseline()` | `ServerFingerprint` — see [Catching a rug pull](rug-pull.md) |
| `scanAgainst(ServerFingerprint)` | `ScanReport` including drift findings |
| `declaredServerInfo()` | What the server claims to be |

`connect` also takes a timeout and a page limit:

```java
McpServerConnection.connect(name, target, Duration.ofSeconds(10), 5);
```

Defaults are `DEFAULT_TIMEOUT` (30s) and `DEFAULT_MAX_PAGES` (20).

**The page limit is a safety control, not tuning.** The MCP SDK's no-argument `listTools()` follows
the whole cursor chain internally, so a server that keeps returning a next-cursor will expand it
until the heap goes — a hostile server can hang your build with no payload at all. This client
paginates itself and stops.

## Tool annotations

This path is the only one that sees tool annotations such as `destructiveHint`. They exist on the
wire, and Spring AI's tool model has no field for them — so on the Spring path an unannotated
destructive tool looks identical to an annotated one, and `MCPRT-CAP` cannot be satisfied there.

If you care about `MCPRT-CAP`, scan over `McpServerConnection`.

## Suppressing a rule

When a finding is understood and accepted, suppress it where a reviewer can see the decision:

```java
McpSecurityScanner scanner = MetadataScanner.builder()
        .suppress("MCPRT-CAP-001",    // an exact rule id
                  "MCPRT-EXF")        // or a whole family
        .build();

assertThat(vendor.scan(scanner)).hasNoFindingsAtOrAbove(Severity.HIGH);
```

`MetadataScanner.builder()` starts with the default rule set already loaded. `rules(...)` replaces
it entirely and `addRule(...)` appends, but suppression is what you want for an accepted finding —
it keeps the decision in the code rather than in a rule set nobody can diff against the default.

Suppress the narrowest thing that works, and leave a comment saying why. A suppression with no
rationale is indistinguishable from a rule that was turned off because it was inconvenient.

## Putting it in CI

Scanning a third-party server in CI means your build now depends on that vendor being up. Decide
deliberately which failure you want:

- **Vendor down should fail the build.** Simple, and correct for a server you must trust to ship.
- **Vendor down should not fail the build.** Then catch the connection failure and skip — but make
  the skip loud, because a check that silently stops running is the failure mode this library
  exists to avoid.

A middle path many teams prefer: scan the vendor on a schedule rather than per commit, and keep
the per-commit gate on a [committed baseline](rug-pull.md), which needs no network.

## Complete example

[`examples/scan-only/src/test/java/com/example/notes/LiveServerScanTest.java`](../../examples/scan-only/src/test/java/com/example/notes/LiveServerScanTest.java)
scans a real MCP server process over stdio, asserts the catalog is non-empty, shows `MCPRT-CAP`
firing and staying quiet, and writes report artifacts. Run it with `mvn test` in
`examples/scan-only`.
