# MCP RedTeam JUnit

JUnit-native security testing for MCP servers and MCP-connected Java agents.

Tool poisoning, schema poisoning, tool shadowing, rug pulls and canary exfiltration — checked in
`mvn test`, with no Python sidecar and no LLM API key for the static half.

[![Maven Central](https://img.shields.io/maven-central/v/io.github.mcpredteam/mcp-redteam-junit)](https://central.sonatype.com/artifact/io.github.mcpredteam/mcp-redteam-junit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**[Getting started](docs/guide/getting-started.md)** ·
**[Runnable examples](examples)** ·
**[Documentation](docs)**

![A scan report listing 3 critical, 13 high and 2 medium findings across 8 MCP tools. The first finding, MCPRT-INJ-001, is a tool description that instructs the agent to ignore its previous instructions, hidden with invisible characters and matched after normalization.](docs/assets/sample-scan.png)

Every scan can write that page next to the JSON and JUnit XML —
`Reports.html(report).writeTo(...)`. One self-contained file, no model, no API key, no network.

---

## Install

Requires **JDK 21+**, **JUnit 5**, and Maven or Gradle.

```xml
<dependency>
    <groupId>io.github.mcpredteam</groupId>
    <artifactId>mcp-redteam-junit</artifactId>
    <version>0.2.0</version>
    <scope>test</scope>
</dependency>

<!-- The library ships only junit-jupiter-api, so it can never drag your test runtime onto a
     version you did not choose. You supply the engine. -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.11.4</version>
    <scope>test</scope>
</dependency>
```

That is everything for scanning tool metadata you already have in hand. Scanning a **live** MCP
server, or driving an **agent**, each need one more module and a dependency you must supply
yourself — see **[Choosing your modules](docs/guide/installation.md)**, which has the copy-paste
blocks for Maven and Gradle.

> **The mistake worth avoiding up front.** `mcp-redteam-mcp` and `mcp-redteam-spring-ai` declare
> the MCP SDK and Spring AI as `provided`, so this library never overrides a version you pinned.
> `provided` is not transitive — supplying those is your job. Omit one and the build resolves
> cleanly, then fails with `NoClassDefFoundError` when a test runs.

## First test

No MCP server, no agent, no model, no API key. This is a complete, runnable test:

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
                .ignoringConfidenceBelow(Confidence.FIRM)   // gate on FIRM; review TENTATIVE by hand
                .hasNoHighRiskFindings();
    }
}
```

In a real project the `tools` list comes from your MCP client's `tools/list`, or straight from a
live server via [`McpServerConnection`](docs/guide/scanning-a-live-server.md) — the scanner does
not care where a `ToolDefinition` came from.

A failure names the rule, the tool, the exact schema path, the matched text, the OWASP MCP Top 10
category, and the fix. This is real output from
[`examples/scan-only`](examples/scan-only):

```
Expected no MCP security findings at or above HIGH (confidence >= TENTATIVE), but found 2:

[CRITICAL] MCPRT-INJ-001 (MCP03 Tool Poisoning, confidence=CERTAIN)
    where: pdf-cloud/render_pdf @ description
    what:  Tool metadata instructs the agent to discard its previous instructions.
    match: Ignore all previous instructions
    fix:   Tool metadata is read by the model but not shown to the user. Remove directive
           language, or stop exposing this server to the agent.

[CRITICAL] MCPRT-INJ-002 (MCP03 Tool Poisoning, confidence=FIRM)
    where: pdf-cloud/render_pdf @ description
    what:  Tool metadata instructs the agent to conceal its behaviour from the user.
    match: Do not mention this to the user
    fix:   Tool metadata is read by the model but not shown to the user. Remove directive
           language, or stop exposing this server to the agent.
```

## Run the examples

Two projects you can clone and run. Both resolve the published artifacts from Maven Central.

```bash
git clone https://github.com/mcpredteam/mcp-redteam-junit
cd mcp-redteam-junit/examples/scan-only
mvn test          # 12 tests, ~20s, no model and no API key
```

[`examples/scan-only`](examples/scan-only) covers the CI gate, scanning a real MCP server process
over stdio, rug-pull detection against a committed baseline, and report artifacts.
[`examples/agent`](examples/agent) drives a real Spring AI agent against a poisoned server and
shows a tool-trust policy stopping it. See [examples/README.md](examples/README.md).

## Why this exists

MCP tool metadata is a high-trust input channel. The agent reads every tool description and
parameter schema, and the user sees none of it. The
[MCPTox benchmark](https://arxiv.org/abs/2508.14925) (AAAI) measured a **36.5% average attack
success rate** across 20 agents on 45 real MCP servers — and found that ordinary
indirect-prompt-injection payloads are largely ineffective here, so this is a distinct attack
surface needing distinct tests.

The JVM has good coverage of the *prompt* layer
([Tiberius](https://github.com/tiberius-security/tiberius)) and of MCP *authentication*
([Spring AI MCP Security](https://github.com/spring-ai-community/mcp-security)). The MCP *tool*
layer is the gap this fills.

Static metadata scanning is table stakes, not a moat —
[mcp-scan](https://invariantlabs.ai/blog/introducing-mcp-scan),
[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) and
[promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) all cover parts of this
ground. The narrower, real advantage is in-process observation (a test decorates the actual
`ToolCallback`, so it sees the invocation and its raw arguments rather than inferring intent from
HTTP traffic) and `mvn test` ergonomics. That is an ergonomics-and-fidelity advantage, not a
capability one. [docs/strategy.md](docs/strategy.md) argues it honestly.

## What it detects

| Rule | Detects | Max severity |
| --- | --- | --- |
| `MCPRT-INJ` | Agent-directed instructions in metadata (8 signatures) | CRITICAL |
| `MCPRT-UNI` | Zero-width, bidi and Unicode-tag characters; homoglyph names | CRITICAL |
| `MCPRT-ENC` | Base64 runs that *decode* to instruction text | HIGH |
| `MCPRT-EXF` | Hard-coded egress URLs, sensitive local paths, sink parameters | HIGH |
| `MCPRT-SHD` | Cross-server name collisions and cross-tool redirection | HIGH |
| `MCPRT-CRED` | Credential-shaped parameters (`apiKey`, `token`, …) that invite a leak | MEDIUM |
| `MCPRT-CAP` | Destructive tools with no `destructiveHint` annotation | MEDIUM |
| `MCPRT-RUG` | Metadata that changed since the server was baselined | inherits the rule the change tripped |

Over a recorded agent run: `MCPRT-HIJ` (called a forbidden tool), `MCPRT-LEAK` (a planted canary
reached a tool argument or the output), `MCPRT-TRI` (a tool *result* carried instructions),
`MCPRT-DEP` (confused deputy), `MCPRT-RUN` (nothing was actually tested).

Full reference with severities, confidence and rationale: **[docs/guide/rules.md](docs/guide/rules.md)**.

Two design choices worth knowing:

**Evasion is normalized away before matching.** Rules run against NFKC-normalized text with
invisible characters stripped and homoglyphs folded, so splicing a zero-width space into
`ignore previous instructions` does not defeat detection. Obfuscation *raises* a finding's
confidence — hiding a payload is evidence of intent.

**False positives are treated as build failures.** A corpus of honest tools deliberately contains
the words a lazy rule keys on — "base64", "system prompt", "credentials", "delete", "webhook" — in
their ordinary sense, and a test asserts none produce a high-severity finding. Teams mute a
scanner that cries wolf, and then it is not there when a real poisoned tool arrives.

## Status

Honest state of the project, because a security tool that overstates its coverage is worse than
no tool. 364 tests, green with no network beyond loopback and no API key.

| Capability | State |
| --- | --- |
| Static metadata scanner (7 rule families, plus opt-in rug-pull) | **Working** |
| Canary exfiltration detection (plain, base64, hex, percent, reversed) | **Working** |
| JUnit assertions with severity + confidence gating | **Working** |
| MCP protocol client for scanning a live server | **Working** — stdio and Streamable HTTP |
| Rug-pull detection (schema fingerprint diffing) | **Working** — against a committed baseline |
| Dynamic Spring AI agent-in-the-loop harness | **Working** — Spring AI 2.0, `ToolCallback` recording |
| Tool-trust policy (the remediation half) | **Working** |
| Multi-trial hijack *rate* measurement | **Working** — `runTrials` + `TrialReport` |
| JSON, HTML and JUnit XML reports | **Working** — same schema for static and dynamic findings |
| Intermediate assistant turns | **Not captured** — Spring AI exposes no per-iteration text |
| Tool annotations on the Spring path | **Not available** — scan over `McpServerConnection` instead |
| SSE transport | **Not built** — deprecated in the MCP spec |
| SARIF, CLI, LangChain4j | **Not built** |

Two things a green build does **not** mean. A clean static report means nothing *looked*
malicious, not that a real agent resists the server. And a passing dynamic test means *this*
model, with *this* wording, against *this* payload, on that run — models are non-deterministic, so
treat a single pass as an observation and [measure a rate](docs/guide/agent-testing.md#measuring-a-rate)
before treating it as a gate.

## Modules

| Module | Purpose | Extra dependencies you supply |
| --- | --- | --- |
| `mcp-redteam-core` | Threat model, rules, canaries, findings, reports. **Zero dependencies.** | — |
| `mcp-redteam-junit` | JUnit 5 assertions. | JUnit engine |
| `mcp-redteam-mcp` | Protocol client: `tools/list` over stdio or Streamable HTTP. | MCP SDK |
| `mcp-redteam-spring-ai` | Agent-in-the-loop harness. | Spring AI, MCP SDK |

A CLI and a LangChain4j adapter will be separate modules once there is something real to put in
them. Empty placeholder modules are structure pretending to be architecture.

## Documentation

**Using the library**

- [Getting started](docs/guide/getting-started.md) — install, first test, wiring it into CI
- [Choosing your modules](docs/guide/installation.md) — dependency blocks for Maven and Gradle
- [Scanning a live server](docs/guide/scanning-a-live-server.md) — stdio and Streamable HTTP
- [Catching a rug pull](docs/guide/rug-pull.md) — baselines and drift detection
- [Testing an agent](docs/guide/agent-testing.md) — the Spring AI harness, canaries, trust policies
- [Reports](docs/guide/reports.md) — JSON, HTML and JUnit XML artifacts
- [Rules reference](docs/guide/rules.md) — every rule id, what trips it, and how to suppress it
- [Troubleshooting](docs/guide/troubleshooting.md) — the errors people actually hit

**Writeups**

- [The payload decided the outcome, not the model](docs/blog/the-payload-decided-the-outcome.md) —
  why a hijack test that only fires the caricatured payload is measuring the payload, not the agent

**Design and background**

- [Strategy](docs/strategy.md) — positioning, and what is honestly defensible about it
- [Threat model](docs/threat-model.md) — what is covered, and what a green build still does not mean
- [Architecture](docs/architecture.md) — pipeline, package shape, decisions worth keeping
- [Integration plan](docs/integration-plan.md) — what is built, in what order, and why
- [References](docs/references.md) — specs, standards and research each rule is built against

## Versioning

`0.2.0` is current; `0.1.0` was the first release. Before 1.0 the public API may break in a minor
release. Detection
rules are a different matter: a rule that starts catching something it used to miss is a fix, not
a break, and will land in a patch. If that would turn your build red without warning, gate on
`hasNoFindingsAtOrAbove(...)` with an explicit severity rather than on a finding count.

See [CHANGELOG.md](CHANGELOG.md).

**Next:** a LangChain4j harness. SARIF and a CLI are deliberately later. The
observation model is framework-agnostic, so a second harness only has to produce observations and
inherits every detector. Issues and milestones carry the current state.

## Contributing

Build and test with `mvn verify` on JDK 21+. CI runs the same on JDK 21 and 25.

New detection rules must ship with **both** a poisoned fixture and a benign one — the
false-positive corpus is a build gate. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, particularly
the scope section: the project is deliberately narrow, and some reasonable ideas are out of bounds
by design.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Never report a vulnerability in a public issue — including a **detection bypass**, a payload a
rule should catch and doesn't. See [SECURITY.md](SECURITY.md) for private disclosure, scope, and
the responsible-use rules.

Use this only against MCP servers and agents you own, operate, or are explicitly authorized to
test. A vulnerability you find in someone else's MCP server is theirs to fix and disclose; report
it to them, not here.

## License

Apache 2.0 — see [LICENSE](LICENSE).
