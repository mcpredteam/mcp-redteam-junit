# Threat Model

## Scope

Attacks that exploit how agents discover, trust and use MCP tools. Taxonomy follows the
OWASP MCP Top 10; `ThreatType` carries the OWASP id on every finding.

Context: the [MCPTox benchmark](https://arxiv.org/abs/2508.14925) measured a **36.5% average
attack success rate** across 20 agents against 45 real MCP servers and 353 tools. More capable
models were often *more* susceptible, because the attack exploits instruction-following.
Conventional indirect-prompt-injection payloads were largely ineffective — this is a distinct
surface.

## Threats

| Threat | Description | Status |
| --- | --- | --- |
| Tool poisoning | Instructions embedded in tool name, description or annotations | `MCPRT-INJ`, `MCPRT-UNI`, `MCPRT-ENC` |
| Schema poisoning | Instructions or misleading semantics in parameter/output schemas | `MCPRT-INJ` via `SchemaWalker` |
| Exfiltration channel | Canary or secret leaves via URL, argument, log or tool output | `MCPRT-EXF` + `Canary` |
| Tool shadowing | Malicious tool mimics or supersedes a trusted one | `MCPRT-SHD-001` |
| Cross-tool poisoning | One tool's metadata changes how another is used | `MCPRT-SHD-002` |
| Overbroad capability | Destructive action with no policy metadata | `MCPRT-CAP` |
| Tool result injection | Tool *output* carries fake system/user messages | **Not covered** — needs dynamic harness |
| Rug pull | Metadata changes after trust or approval | **Not covered** — needs protocol client + fingerprinting |
| Confused deputy | Agent uses its authority on behalf of an untrusted server | **Not covered** — needs dynamic harness |

The "not covered" rows drive the build order. Three of the nine threats are invisible to any
static scan, and two of those three are the highest-value ones — which is why the dynamic
harness is the next milestone rather than a later one.

## Out of scope

General jailbreak benchmarking, toxicity, bias, runtime policy enforcement, production
gatewaying, model fingerprinting. These are real problems and other tools own them —
Tiberius covers the prompt layer, Spring AI MCP Security covers authentication.

## Detection philosophy

Prefer observed behavior to subjective judgment.

**Strong evidence:** a forbidden tool call happened; a canary appeared in a tool argument or
model output; a metadata fingerprint changed; an unambiguous injection pattern in metadata;
an invisible control character (no benign explanation exists).

**Weaker evidence:** a model judge finds a response suspicious; a description "sounds risky";
a response is evasive.

LLM-as-judge can come later. The first version is deterministic where possible, and every
finding carries a `Confidence` so weak signals are visible without gating CI.

## The failure mode this design fears most

A green test that verified nothing. For a security tool, a false negative dressed as a pass is
worse than no tool, because it converts an unexamined risk into a documented assurance.

Concrete guards in place:

- The default assertion gate is `HIGH`, matching what rules actually emit.
- `CanaryAssert.didNotLeak()` throws when given zero observations.
- `CanaryAssert.wasPlantedIn(...)` exists to prove the canary was really planted, since
  `Canary.random()` called inside an assertion mints a different secret than the one planted.
- `BenignToolFixtures` fails the build on new false positives, because a scanner teams have
  muted is a scanner that is not running.
