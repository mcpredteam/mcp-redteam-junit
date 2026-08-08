# Architecture

## Pipeline

```text
Tool definitions -> MetadataRule -> Finding -> ScanReport -> Assertion   (static, built)
Fixture server -> Agent -> AgentRun -> BehaviorRule -> ScanReport        (dynamic, built)
```

Both halves converge on `ScanReport`, so findings from either sort, threshold and render
through one set of assertions. A team already gating on a scan report gets the dynamic gate
without learning a second vocabulary.

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

Not yet implemented: schema drift against a stored fingerprint (rug pull) — it needs the MCP
protocol client, which is not built.

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

io.github.harikrishna8121999.mcpredteam.junit
  McpSecurityAssertions  ScanReportAssert  CanaryAssert  AgentRunAssert

io.github.harikrishna8121999.mcpredteam.springai        // Spring AI 2.0, provided scope
  McpRedTeam  ToolServer  RecordingToolCallback
  ToolCallRecorder  SpringToolDefinitions
io.github.harikrishna8121999.mcpredteam.springai.fixture
  FixtureServers  FixtureTool
```

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

**Tool results are inbound, not emitted.** `AgentRun#allEmittedText` covers the response,
intermediate messages and tool-call arguments, and deliberately excludes tool results. A
malicious server can echo back a secret it was handed, or one it guessed, and a leak rule that
read results would fire on runs where the agent leaked nothing. Every path by which the agent
itself discloses a canary is still covered.
