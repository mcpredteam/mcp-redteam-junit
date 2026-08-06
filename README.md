# MCP RedTeam JUnit

JUnit-native security testing for MCP servers and MCP-connected Java agents.

Tool poisoning, schema poisoning, tool shadowing and canary exfiltration — checked in
`mvn test`, with no Python sidecar and no LLM API key for the static half.

> **Not published yet.** There is no Maven Central release, so this coordinate will not
> resolve. Build from source with `mvn install` (JDK 21+) if you want to try it today.
> Publishing comes once the dynamic harness lands.

```xml
<dependency>
    <groupId>io.github.harikrishna8121999</groupId>
    <artifactId>mcp-redteam-junit</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

```java
import static io.github.harikrishna8121999.mcpredteam.junit.McpSecurityAssertions.assertThat;

@Test
void connectedMcpServersExposeNoPoisonedToolMetadata() {
    List<ToolDefinition> tools = loadFromToolsList();   // your MCP client's tools/list

    ScanReport report = MetadataScanner.withDefaultRules().scan(tools);

    assertThat(report)
        .ignoringConfidenceBelow(Confidence.FIRM)
        .hasNoHighRiskFindings();
}
```

A failure names the rule, the tool, the exact schema path, the matched text, the OWASP MCP
Top 10 category, and the fix:

```
[CRITICAL] MCPRT-INJ-001 (MCP03 Tool Poisoning, confidence=CERTAIN)
    where: evil-analytics/record_analytics @ description
    what:  Tool metadata instructs the agent to discard its previous instructions.
    match: Ignore all previous instructions
    fix:   Tool metadata is read by the model but not shown to the user. Remove directive
           language, or stop exposing this server to the agent.
```

## Why this exists

MCP tool metadata is a high-trust input channel. The agent reads every tool description and
parameter schema, and the user sees none of it. The
[MCPTox benchmark](https://arxiv.org/abs/2508.14925) (AAAI) measured a **36.5% average
attack success rate** across 20 agents on 45 real MCP servers — and found that ordinary
indirect-prompt-injection payloads are largely ineffective here, so this is a distinct attack
surface needing distinct tests.

The JVM has good coverage of the *prompt* layer
([Tiberius](https://github.com/tiberius-security/tiberius)) and of MCP *authentication*
([Spring AI MCP Security](https://github.com/spring-ai-community/mcp-security)). The MCP
*tool* layer is the gap this fills.

## What is honest about the positioning

Static metadata scanning is table stakes, not a moat.
[mcp-scan](https://invariantlabs.ai/blog/introducing-mcp-scan),
[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) and
[mcp-shield](https://github.com/riseandignite/mcp-shield) (unrelated Node project) all do it,
some of them well. Dynamic MCP red teaming is not unclaimed either —
[promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) already builds
malicious MCP servers and tests whether agents cascade unauthorized actions, and it can point
at a Java agent over HTTP.

The narrower, real advantage:

- **In-process observation.** Spring AI 2.0 puts the tool-calling loop in the advisor chain,
  so a test can see the actual `ToolCallback` invocation and its arguments rather than
  inferring intent from HTTP traffic.
- **`mvn test` ergonomics.** A CI gate in the build a Java team already runs, with failure
  output a Java developer can act on, and no second toolchain to install.

That is an ergonomics-and-fidelity advantage, not a capability one. It is worth building; it
is not a reason to claim nobody else can test MCP.

## Status

Honest state of the project, because a security tool that overstates its coverage is worse
than no tool.

| Capability | State |
| --- | --- |
| Static metadata scanner (6 rule families, 15 signatures) | **Working**, 108 tests |
| Canary exfiltration detection (plain, base64, hex, percent, reversed) | **Working** |
| JUnit assertions with severity + confidence gating | **Working** |
| MCP protocol client (`tools/list` over stdio/HTTP) | Not built — you supply `ToolDefinition`s |
| Malicious fixture MCP server process | Not built |
| Dynamic Spring AI agent-in-the-loop test | Not built — **this is the next milestone** |
| JSON / SARIF reports, CLI | Not built |

Until the dynamic harness lands, this is a good static scanner with an honest API. A clean
report means nothing *looked* malicious, not that a real agent resists the server.

## Detection rules

| Rule | Detects | Max severity |
| --- | --- | --- |
| `MCPRT-INJ` | Agent-directed instructions in metadata (8 signatures) | CRITICAL |
| `MCPRT-UNI` | Zero-width, bidi and Unicode-tag characters; homoglyph names | CRITICAL |
| `MCPRT-ENC` | Base64 runs that *decode* to instruction text | HIGH |
| `MCPRT-EXF` | Hard-coded egress URLs, sensitive local paths, sink parameters | HIGH |
| `MCPRT-SHD` | Cross-server name collisions and cross-tool redirection | HIGH |
| `MCPRT-CAP` | Destructive tools with no `destructiveHint` annotation | MEDIUM |

Two design choices worth knowing about:

**Evasion is normalized away before matching.** Rules run against NFKC-normalized text with
invisible characters stripped and homoglyphs folded, so splicing a zero-width space into
`ignore previous instructions` does not defeat detection. Obfuscation raises a finding's
confidence rather than lowering it — hiding a payload is evidence of intent.

**False positives are treated as build failures.** `BenignToolFixtures` is a corpus of honest
tools that deliberately contain the words a lazy rule keys on — "base64", "system prompt",
"credentials", "delete", "webhook" — in their ordinary sense, and a test asserts none of them
produce a high-severity finding. Teams mute a scanner that cries wolf, and then it is not
there when a real poisoned tool arrives.

Findings carry a `Confidence` alongside `Severity`. Gate CI on `FIRM` and above; review
`TENTATIVE` findings by hand.

## Modules

| Module | Purpose |
| --- | --- |
| `mcp-redteam-core` | Threat model, rules, canaries, findings, reports. Zero dependencies. |
| `mcp-redteam-junit` | JUnit 5 assertions. |

Framework adapters and a CLI will be separate modules once there is something real to put in
them. Empty placeholder modules are structure pretending to be architecture.

## Roadmap

Dynamic first. The static scanner is the commoditized half, so the agent-in-the-loop test is
the next milestone rather than a later one — a real Spring AI agent, a malicious fixture
server, a planted canary, and a test that passes only if the agent is not hijacked. If that
cannot be made to work, it is worth learning in week one rather than month two.

After that, in order: an MCP protocol client so `tools/list` can be scanned live (which also
turns the existing rules into rug-pull detection via schema fingerprinting), JSON and JUnit
XML reports, then a Maven Central release. LangChain4j, SARIF, tool-result injection probes
and a CLI are deliberately later — each is a different surface, and starting one before the
dynamic test works would be scope creep dressed as progress.

Issues and milestones carry the current state.

## Docs

- [Strategy](docs/strategy.md) — positioning, and what is honestly defensible about it
- [Threat Model](docs/threat-model.md) — what is covered, and the three threats that are not
- [Architecture](docs/architecture.md) — pipeline, package shape, design decisions worth keeping
- [Integration Plan](docs/integration-plan.md) — JUnit today, Spring AI next
- [References](docs/references.md) — specs, standards and research each rule is built against

## Contributing

Build and test with `mvn verify` on JDK 21+. CI runs the same on JDK 21 and 25.

New detection rules must ship with **both** a poisoned fixture and a benign one — the
false-positive corpus is a build gate. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a PR, particularly the scope section: the project is deliberately narrow, and some reasonable
ideas are out of bounds by design.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Never report a vulnerability in a public issue — including a **detection bypass**, a payload a
rule should catch and doesn't. See [SECURITY.md](SECURITY.md) for private disclosure, scope,
and the responsible-use rules.

Use this only against MCP servers and agents you own, operate, or are explicitly authorized to
test. A vulnerability you find in someone else's MCP server is theirs to fix and disclose;
report it to them, not here.

## License

Apache 2.0 — see [LICENSE](LICENSE).
