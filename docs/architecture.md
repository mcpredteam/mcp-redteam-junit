# Architecture

## Pipeline

```text
Live server -> tools/list -> ToolDefinition                             (protocol, built)
Tool definitions -> MetadataRule -> Finding -> ScanReport -> Assertion   (static, built)
Fixture server -> Agent -> AgentRun -> BehaviorRule -> ScanReport        (dynamic, built)
ScanReport -> Reports.json / Reports.junitXml -> artifact                (reporting, built)
TrialReport -> Reports.json().measuring(...) -> rate + traces            (reporting, built)
```

Both halves converge on `ScanReport`, so findings from either sort, threshold and render
through one set of assertions. A team already gating on a scan report gets the dynamic gate
without learning a second vocabulary — and, because reporting hangs off the same type, a hijack
and a poisoned description serialize into one schema rather than two.

| Concept | Meaning |
| --- | --- |
| `ToolDefinition` | One entry from `tools/list`. Every field is attacker-controlled. |
| `MetadataRule` | A static detection. Receives the whole tool list, since shadowing is relational. |
| `Finding` | Normalized result: rule id, threat type, severity, confidence, location, evidence, remediation. |
| `ScanReport` | Findings plus timing and counts, with severity/confidence thresholds. |
| `Canary` | A planted secret whose reappearance proves exfiltration. |
| `ToolCallObservation` | One recorded call: server, tool, raw arguments, result, outcome, order. |
| `AgentRun` | A whole execution: task, system prompt, calls, messages, tools offered. |
| `BehaviorRule` | A detection over what the agent did. Receives the whole run, since the signals are sequential. |

## Two modes

### Static metadata scan — built

Inspects tool definitions before an agent ever sees them. No LLM, no network.

Implemented rule families: instruction injection (`MCPRT-INJ`), hidden Unicode and homoglyphs
(`MCPRT-UNI`), encoded payloads (`MCPRT-ENC`), exfiltration channels (`MCPRT-EXF`), credential-shaped
parameters (`MCPRT-CRED`), shadowing and cross-tool redirection (`MCPRT-SHD`), undeclared
destructive capability (`MCPRT-CAP`).

### Schema fingerprinting — built

`core.fingerprint` records what a server published when it was approved and compares later scans
against it. `ToolFingerprint` flattens a tool into `location -> digest` pairs over a canonical
form (`CanonicalForm`): map keys sorted, values type-tagged, traversal depth-capped the way
`SchemaWalker` is, so two scans of an unchanged server agree and a JSON decoder's key order
cannot make them disagree.

Three decisions carry the design:

- **The digest is over raw metadata.** Everything else in the library matches normalized text;
  hashing normalized text here would fold a Cyrillic `а` onto `a` before the digest, so a
  homoglyph rename of a trusted tool would leave the fingerprint unmoved.
- **The baseline is a committed text file, one sorted line per location.** It is a review
  artifact: a changed parameter description is one line in a pull request diff. Tool names and
  locations are attacker-controlled, so they are escaped to printable ASCII on the way out — a
  property name carrying a tab or a newline would otherwise forge lines in a file this code
  parses back, and a look-alike character would sit in the diff impersonating the name it
  replaced. `BaselineFormat` parses strictly and repairs nothing.
- **Capture is gated.** `Baseline.capture` runs the static scan and refuses a server that fails
  it, because a fingerprint taken on first sight is trust on first use and a baseline of a
  poisoned server certifies the poison.

`RugPullRule` (`MCPRT-RUG`) is an ordinary `MetadataRule` holding a baseline, so it composes into
`MetadataScanner` beside the others. Drift is MEDIUM; drift is re-scanned by the static text
rules over the *changed locations only*, and anything they flag is reported at their severity
under `MCPRT-RUG-001/<rule id>` — the same delegation `MCPRT-TRI` uses, for the same reason.
`MCPRT-RUG-000` reports a baseline that matched no tool in the scan, since a comparison that
compared nothing must not pass quietly.

### Protocol client — built

`McpServerConnection` connects to a real server over stdio or Streamable HTTP, completes the
`initialize` handshake and turns `tools/list` into `ToolDefinition`s. `connection.scan()` is the
static scan of a server nobody wrote down by hand — the point of the module.

This is also the only path on which MCP tool annotations are visible. Spring AI's tool model has
no field for `destructiveHint`, so `MCPRT-CAP` could never be satisfied there; from `tools/list`
it can, and absence stays distinguishable from `false`. Those mean opposite things — a server
that declined to declare a hint versus one that made a checkable claim — and until now they had
the same symptom.

### Dynamic agent-in-the-loop — built

Runs a real agent against fixture servers and observes behavior: was the malicious tool
called, did a canary appear in a tool argument, did a tool result carry instructions, did the
agent act on a trusted server right after an untrusted one told it to.

Implemented rules: forbidden tool call (`MCPRT-HIJ`), canary exfiltration (`MCPRT-LEAK`), tool
result injection (`MCPRT-TRI`), confused deputy (`MCPRT-DEP`).

`MCPRT-TRI` delegates to the static text rules rather than growing a second copy of the same
signatures — instruction text is instruction text wherever it appears, and one corpus that
drifts is worse than none. Only findings raised against the injected text are kept; a homoglyph
in the tool's own name is a static finding and is reported as one.

`MCPRT-DEP` is the only dynamic rule that infers rather than records, so it is capped at
`FIRM` confidence and names its trigger in the evidence. The rest are `CERTAIN`, because a
recorded call and a canary hit are facts.

**A pointing rule must not point at everything.** `MCPRT-DEP` originally fired on any trusted
call following an injected untrusted result. That flagged the agent doing the task it was
asked to do, at `HIGH`, failing the default gate on clean runs. Confidence was the wrong dial —
confidence does not gate, severity does. It now requires the injected text to *name* the tool
that was subsequently called, matched on word boundaries and after normalization so a
zero-width space in the name does not defeat it. That trades a real false negative for a rule
people will leave switched on.

This was the product wedge, and it came before the protocol client because it carried all the
technical risk — if it could not be made to work, a static scanner alone would not justify the
project.

## Package shape

```text
io.github.harikrishna8121999.mcpredteam.core
  ThreatType  Severity  Confidence  Finding  ScanReport
  ToolDefinition  Canary
  AgentRun  ToolCallObservation  ToolCallOutcome
  SchemaWalker      // recursive JSON traversal, depth-capped
  TextNormalizer    // NFKC + invisible-strip + homoglyph fold
  McpSecurityScanner  MetadataScanner

io.github.harikrishna8121999.mcpredteam.core.rule
  MetadataRule  PerToolRule
  InstructionInjectionRule  HiddenUnicodeRule  EncodedPayloadRule
  ExfiltrationChannelRule   ToolShadowingRule  DestructiveCapabilityRule

io.github.harikrishna8121999.mcpredteam.core.behavior
  BehaviorRule  BehaviorScanner
  ForbiddenToolCallRule  CanaryLeakRule
  ToolResultInjectionRule  ConfusedDeputyRule

io.github.harikrishna8121999.mcpredteam.core.fixture
  PoisonedToolFixtures  BenignToolFixtures

io.github.harikrishna8121999.mcpredteam.core.report
  Reports  Report        // json / junitXml, render() or writeTo(Path)
  TrialJson             // rates + per-run traces; .measuring(name, predicate)
  JsonFormat  JUnitXmlFormat  JsonWriter  BuildInfo

io.github.harikrishna8121999.mcpredteam.junit
  McpSecurityAssertions  ScanReportAssert  CanaryAssert  AgentRunAssert

io.github.harikrishna8121999.mcpredteam.mcp             // MCP Java SDK 2.0, provided scope
  McpServerTarget  McpServerConnection  McpToolDefinitions
io.github.harikrishna8121999.mcpredteam.mcp.fixture
  FixtureCatalog  FixtureToolSpecifications  McpFixtureServerMain

io.github.harikrishna8121999.mcpredteam.springai        // Spring AI 2.0, provided scope
  McpRedTeam  ToolServer  RecordingToolCallback
  ToolCallRecorder  SpringToolDefinitions
io.github.harikrishna8121999.mcpredteam.springai.fixture
  FixtureServers  FixtureTool  McpFixtureServer
```

**The protocol client is its own module, not part of the Spring AI one.** The consumers of a
`tools/list` scan are the *static* tests: someone who wants to stop hand-writing tool
definitions and point the scanner at their real server, with no agent and no model anywhere in
it. Folding this into `mcp-redteam-spring-ai` would bill that person four extra dependency
declarations — everything there is `provided`, including a model provider — to run a scan that
never calls a model.

The fixture corpus moved down with it, because none of it was ever about Spring: a poisoned tool
description is a fact about MCP. That keeps one corpus behind stdio, Streamable HTTP and the
in-process Spring fixtures, and `McpFixtureServer` now connects through `McpServerConnection`
rather than opening a second connection path — when there were two, only one of them was
exercised by the tests that mattered.

## Design decisions worth preserving

**Traverse schemas, never `Map.toString()`.** The first scaffold scanned
`inputSchema.toString()`. That output is unordered, unescaped, invents delimiter characters
that corrupt pattern matching, and gives no path to point a developer at. `SchemaWalker`
yields `(jsonPointer, text)` pairs instead, and caps recursion depth — a hostile server
controls its own schema nesting, so an uncapped walk turns the scanner into a denial-of-service
target.

**Normalize before matching.** Rules match `TextNormalizer.normalize(...)` output, so a
zero-width space spliced into a payload does not defeat detection. Obfuscation *raises* a
finding's confidence: hiding something is evidence of intent.

**Severity and confidence are separate axes.** Severity is how bad it would be; confidence is
how sure the rule is. Collapsing them forces a choice between a noisy scanner and a blind one.
CI gates on `FIRM` and above; `TENTATIVE` findings stay visible in the report.

**Assertions must be able to fail.** The first scaffold shipped a scanner that only emitted
`HIGH` and an assertion that only tripped on `CRITICAL` — a pair that could never fail. The
default gate is now `HIGH`, `CanaryAssert` refuses to pass with zero observations, and both
behaviours have regression tests.

**Keep `core` dependency-free.** It has no dependencies at all, so a static scan cannot drag
Spring or an HTTP client into a consumer's test classpath. The observation model lives there
too, which is why `AgentRun` is a plain record and not a Spring type: the LangChain4j harness
will only have to produce observations, and every detector and assertion is already shared.
Spring AI is `provided` in its own module, because a test library that overrides a team's
pinned framework version is a rude one.

**Record at the `ToolCallback`, not the advisor.** `call(String toolInput)` receives the input
as the model produced it, before parsing — the only place an exfiltrated canary is guaranteed
to appear verbatim. It is also a public interface rather than an internal of the tool-calling
loop. See [integration-plan.md](integration-plan.md), which also records that the advisor this
project originally planned to use does not exist.

**Never call the SDK's no-argument `listTools()`.** It looks like exactly what a scanner wants
and is the one method it must not use. Internally it expands the pagination cursor chain and
reduces it into a single result, with no bound — so a server that returns a fresh `nextCursor`
every time makes it never return, while the tools it collects accumulate until the JVM runs out
of heap. The caller cannot interrupt it, time it out per page, or find out how far it got. That
is a reasonable default for a client talking to a server it trusts and unusable for one whose
entire job is talking to servers it does not. `McpServerConnection` drives pagination itself
through the single-argument overload, caps the pages, and stops early if a cursor repeats.

It fails rather than returning the pages it did read. A truncated list would be the worse bug by
far: the scan would cover a slice of the server's tools, nothing in the result would say which
slice, and a clean report would mean "the first few pages looked fine" while reading as "clean".
`HostileServerTest` pins all of this, under a class-level timeout — every failure mode there is
a hang rather than an assertion error, and without the timeout a regression would not turn CI
red, it would turn CI permanently yellow.

**Tool results are inbound, not emitted.** `AgentRun#allEmittedText` covers the response,
intermediate messages and tool-call arguments, and deliberately excludes tool results. A
malicious server can echo back a secret it was handed, or one it guessed, and a leak rule that
read results would fire on runs where the agent leaked nothing. Every path by which the agent
itself discloses a canary is still covered.
