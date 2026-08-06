# Architecture

## Pipeline

```text
Tool definitions -> Rule -> Finding -> ScanReport -> Assertion        (static, built)
Fixture server   -> Agent -> Observation -> Detector -> Finding       (dynamic, next)
```

| Concept | Meaning |
| --- | --- |
| `ToolDefinition` | One entry from `tools/list`. Every field is attacker-controlled. |
| `MetadataRule` | A static detection. Receives the whole tool list, since shadowing is relational. |
| `Finding` | Normalized result: rule id, threat type, severity, confidence, location, evidence, remediation. |
| `ScanReport` | Findings plus timing and counts, with severity/confidence thresholds. |
| `Canary` | A planted secret whose reappearance proves exfiltration. |
| Observation | *(planned)* What a real agent did: tool calls, arguments, results, messages. |

## Two modes

### Static metadata scan — built

Inspects tool definitions before an agent ever sees them. No LLM, no network.

Implemented rule families: instruction injection (`MCPRT-INJ`), hidden Unicode and homoglyphs
(`MCPRT-UNI`), encoded payloads (`MCPRT-ENC`), exfiltration channels (`MCPRT-EXF`), shadowing
and cross-tool redirection (`MCPRT-SHD`), undeclared destructive capability (`MCPRT-CAP`).

Not yet implemented: schema drift against a stored fingerprint (rug pull) — it needs the MCP
protocol client, which is not built.

### Dynamic agent-in-the-loop — next

Runs a real agent against fixture servers and observes behavior: was the malicious tool
called, was a trusted tool shadowed, did a canary appear in a tool argument, did a tool result
change later tool selection.

This is the product wedge, and it comes before the protocol client because it carries all the
technical risk — if it cannot be made to work, a static scanner alone does not justify the
project.

## Package shape

```text
io.github.harikrishna8121999.mcpredteam.core
  ThreatType  Severity  Confidence  Finding  ScanReport
  ToolDefinition  Canary
  SchemaWalker      // recursive JSON traversal, depth-capped
  TextNormalizer    // NFKC + invisible-strip + homoglyph fold
  McpSecurityScanner  MetadataScanner

io.github.harikrishna8121999.mcpredteam.core.rule
  MetadataRule  PerToolRule
  InstructionInjectionRule  HiddenUnicodeRule  EncodedPayloadRule
  ExfiltrationChannelRule   ToolShadowingRule  DestructiveCapabilityRule

io.github.harikrishna8121999.mcpredteam.core.fixture
  PoisonedToolFixtures  BenignToolFixtures

io.github.harikrishna8121999.mcpredteam.junit
  McpSecurityAssertions  ScanReportAssert  CanaryAssert
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
Spring or an HTTP client into a consumer's test classpath. Framework adapters get their own
modules — once they contain something.
