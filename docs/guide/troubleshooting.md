# Troubleshooting

The errors people actually hit, and what they really mean.

## `NoClassDefFoundError` at test time

```
java.lang.NoClassDefFoundError: io/modelcontextprotocol/client/McpSyncClient
java.lang.NoClassDefFoundError: org/springframework/ai/chat/client/ChatClient
```

**Cause:** `mcp-redteam-mcp` and `mcp-redteam-spring-ai` declare the MCP SDK and Spring AI as
`provided`, so this library never overrides a version you pinned. `provided` dependencies are not
transitive — supplying them is your job. The build resolves cleanly without them and fails only
when a test runs.

**Fix:** add the missing dependency. [Choosing your modules](installation.md) has the full list
per module.

## No tests ran, but the build is green

```
Tests run: 0, Failures: 0, Errors: 0
```

Two common causes:

**You have `junit-jupiter-api` but no engine.** The library ships only the API, deliberately, so
it cannot drag your test runtime onto a version you did not choose. Add:

```xml
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.11.4</version>
    <scope>test</scope>
</dependency>
```

**Your tests are tagged and excluded.** If you followed the `live` tag pattern, `mvn test` skips
them by design. Run `mvn test -Plive`.

## `-DexcludedGroups=` is ignored

You ran `mvn test -DexcludedGroups=` expecting the live tests to run, and got a green build that
ran nothing.

**Cause:** Surefire's POM `<configuration>` beats a command-line `-D`. A literal inside
`<configuration>` cannot be overridden from the command line at all.

**Fix:** indirect through a property and activate a profile — see
[Choosing your modules](installation.md#keeping-model-backed-tests-out-of-the-default-build).
Use `-Plive`, which also avoids PowerShell mangling a `-D` argument that contains a dot or ends in
a bare `=`.

## The server connected but published no tools

**A stray write to stdout.** For a stdio server, **stdout is the JSON-RPC channel**. A single
`System.out.println` in the server corrupts the stream, and it surfaces at the client as an empty
tool list rather than as any error naming the cause. Log to stderr.

**A protocol version mismatch** between your MCP SDK and the server shows up the same way. Pin the
SDK version explicitly rather than letting it be resolved transitively.

Guard against both by asserting the catalog is non-empty:

```java
assertFalse(connection.listTools().isEmpty(), "the scan proved nothing");
```

## `Could not initialize an MCP session` after 30 seconds

The client connected but the handshake never completed.

- For **stdio**, the command probably failed to start. Check it runs standalone. If you are
  launching a class from your own test classpath, note that `System.getProperty("java.class.path")`
  is *Maven's* classpath under `exec:java` — use `exec:exec` with a `<classpath/>` argument
  instead, or the child JVM cannot find your main class.
- For **Streamable HTTP**, check the URL includes the MCP endpoint path and that auth headers are
  set via `.withHeader(...)`.

Raise the timeout with the four-argument `connect(name, target, timeout, maxPages)` if the server
is genuinely slow to start.

## The build hangs when scanning a server

**Cause:** the MCP SDK's no-argument `listTools()` expands the whole cursor chain internally, so a
server that keeps returning a next-cursor will run until the heap goes.

`McpServerConnection` paginates itself and stops at `DEFAULT_MAX_PAGES` (20), so this should not
happen through this library. If you are calling the SDK directly, do not use the no-arg overload
against a server you do not control.

## `UntrustedBaselineException` when capturing a baseline

Working as intended. Capture refuses a server that already fails the static scan, because a
baseline taken from a poisoned server records the poison as the approved state — after which drift
detection fires only if the attacker cleans up.

The exception carries the report that refused it. Read the findings. If one is understood and
accepted, suppress that rule id on the gate scanner:

```java
connection.captureBaseline(
        MetadataScanner.builder().suppress("MCPRT-CAP-001").build(),
        Severity.HIGH);
```

## `data before the version directive` reading a baseline

The file has a byte-order mark, or something else, before `!mcp-redteam-baseline`.

A leading UTF-8 BOM is tolerated. Anything else is not. On Windows, `Set-Content -Encoding utf8`
writes a BOM — use `Out-File -Encoding utf8` carefully, or better, regenerate the file with the
capture tool rather than editing it by hand.

## The drift test fails and I just want it green

Do not re-capture the baseline to make it pass. That is the one action the whole feature exists to
prevent — it records whatever is being served now as the approved state.

Read the diff first. If the change is one the vendor announced and you have reviewed, re-capture
deliberately as its own commit, with the review in the commit message.

## Failure messages show `?` or `�` instead of `—`

A console encoding artifact on Windows, not a corrupted finding. The JSON report carries the
correct characters. Set `JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8` and use a UTF-8 capable terminal
if it bothers you.

## Live agent tests fail with a connection error

```
No Ollama at http://localhost:11434 (ConnectException). Start it with: ollama serve
```

This preflight is deliberate. Without it a stopped model surfaces as an error *inside* the
tool-calling loop, the harness records a failed run, and the output reads as though something
about the agent went wrong rather than as "nothing was tested".

## A hijack test passes and I do not believe it

You are right to be suspicious. Check, in this order:

1. **Did the canary actually enter the context?** `assertThat(canary).wasPlantedIn(run.systemPrompt())`
2. **Did the run complete?** `run.completed()` — a provider error is not a security result
3. **Did the agent call anything at all?** `run.hasObservations()`
4. **If a trust policy is applied, did it withhold anything?** `harness.withheldTools()` — an empty
   set means the assertions passed with no defence in play
5. **Is the payload realistic?** The caricatured
   `<IMPORTANT>Ignore all previous instructions</IMPORTANT>` scored 0/20 against qwen3:8b. A test
   that only fires that one measures the payload, not the agent. Use `credentialPhish()`.

And then: one run is one sample. [Measure a rate](agent-testing.md#measuring-a-rate).

## Still stuck

Open an issue with the rule id, the metadata that produced it (redacted if needed), and the
version. For a **detection bypass** — a payload a rule should catch and doesn't — do not open a
public issue; see [SECURITY.md](../../SECURITY.md).
