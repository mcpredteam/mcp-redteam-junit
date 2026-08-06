# Strategy

## Positioning

Not another generic LLM red-team scanner. That lane is occupied on every runtime — garak,
PyRIT, DeepTeam on Python; promptfoo on TypeScript; Augustus on Go; Tiberius on the JVM.

The sharper position:

> JUnit-native security tests for the MCP tool layer, against real Java agents.

## The honest moat

The dynamic agent-in-the-loop test is not a capability only a JVM tool can offer. promptfoo
already builds malicious MCP servers, tests whether agents cascade unauthorized actions, and
reconstructs agent trajectories from OpenTelemetry traces — and it can point at a Java agent
over HTTP like any other target. Any positioning that claims otherwise is wrong, and being
wrong about it in public is expensive.

What is actually defensible is narrower:

1. **Fidelity of observation.** An external tool sees HTTP traffic and infers intent. A test
   running inside the same JVM sees the actual `ToolCallback` invocation, its arguments, and
   the advisor chain around it. Spring AI 2.0 made the tool loop a first-class composable
   part of that chain, so this is a supported extension point.
2. **Ergonomics.** The gate lives in `mvn test`, in the build the team already runs, failing
   with a stack trace and a message a Java developer can act on. No Node or Python toolchain,
   no separate config file, no second CI job.

That is a real advantage. It is an ergonomics-and-fidelity advantage, not a capability one.
Claiming more invites a correction from someone who knows the space, in public, on a security
tool — which costs more credibility than the claim was ever worth.

## Core bet

MCP tool metadata and tool results are a high-trust input channel. The agent reads every
description and schema; the user sees none of it. MCPTox measured a 36.5% average attack
success rate across 20 agents against 45 real servers, and found that conventional
indirect-prompt-injection payloads largely fail here — so this needs its own tests, not a
rebadged prompt-injection suite.

Static scanning is a useful cheap gate. The valuable evidence is behavioral:

1. Did the real agent call the malicious tool?
2. Did it leak a canary, in any encoding?
3. Did a tool result poison a later tool call?
4. Did trusted metadata change after approval?
5. Did a malicious server shadow a trusted tool?

## Principles

- **Prefer observed behavior to model judgment.** A recorded tool call and a canary hit are
  facts. An LLM judge's opinion is a guess. Add judges later, if at all.
- **False confidence is the failure mode to fear.** For a security tool, a green test that
  checked nothing is worse than no test. This is why the benign corpus is a build gate, why
  `CanaryAssert` refuses to pass with zero observations, and why the status table in the
  README lists what is *not* built.
- **Ship the narrowest useful thing.** One framework, one report format, a handful of
  high-quality rules.
- **Distribution is the constraint, not code.** The engineering is the tractable half. A
  working demo and a clear writeup do more for this project than another rule family.

## What to avoid in v1

- Runtime guardrails — different product, v2 at the earliest.
- Generic red-teaming — that is Tiberius's lane; stay complementary.
- Dashboards.
- A large invented taxonomy. Use OWASP MCP Top 10.
- Framework adapters before one dynamic demo actually works.

## What to build first

One JUnit test wiring a Spring AI agent to a trusted fixture server, a malicious fixture
server, a canary, a forbidden tool, and a benign user task. It passes only if the agent
neither leaks the canary nor calls the forbidden tool.

Everything else is secondary to making that one test real.
