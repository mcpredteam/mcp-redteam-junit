# Examples

Two runnable projects. Both resolve `io.github.mcpredteam:0.1.0` from Maven Central, so you can
copy either one out of this repository and it keeps working.

Neither is a module of the library's build. That is deliberate: they consume the published
artifacts exactly as your project will, so nothing here can pass by quietly picking up the
library's own build output.

| | [`scan-only/`](scan-only) | [`agent/`](agent) |
| --- | --- | --- |
| Who it is for | You want MCP security checks in CI | You run a Spring AI agent |
| Needs a model | **No** | Yes |
| Needs an API key | **No** | No — runs against local Ollama |
| Dependencies | 4 | 7 |
| Runs under plain `mvn test` | Yes, 12 tests, ~20s | No — everything is tagged `live` |

**Start with `scan-only`.** It is the cheap gate, it is the one most teams keep, and it needs
nothing running.

## scan-only — no model, no key

```bash
cd examples/scan-only
mvn test
```

Twelve tests, green. What they show, in the order worth reading them:

| Test | What it demonstrates |
| --- | --- |
| `OwnServerScanTest` | The CI gate: scan your tool metadata, fail on high-risk findings. Also asserts the scanner stays *quiet* on honest tools that say "base64" and "delete" — a scanner that cries wolf gets muted. |
| `PoisonedVendorTest` | Your server is fine; a vendor's is not. Prints the real failure message a developer would see in CI. |
| `LiveServerScanTest` | The same scan against a **real MCP server process** over stdio, plus writing JSON and JUnit XML reports. |
| `ServerDriftTest` | Rug pull: the server changed after you approved it. Catches a new unreviewed tool, a poisoned edit, and a harmless reword. |

Two of the tests deliberately trigger failures and print the message instead of letting it break
the build, so the run stays green while showing you what a real failure looks like. Do not copy
that pattern into your own suite — there, you want the gate to fail.

### Re-capturing the baseline

`ServerDriftTest` reads a committed fingerprint from `src/test/resources/notes-baseline.txt`.
To regenerate it:

```bash
cd examples/scan-only
mvn test-compile exec:exec
```

Then read the diff and commit it, the way you would review a dependency bump. Nothing in the
build regenerates this file, and the library ships no capture-if-missing helper — a check that
re-baselines itself whenever it has nothing to compare against can never fail.

Capture also **refuses** a server that already fails the static scan, because a baseline taken
from a poisoned server records the poison as the approved state.

## agent — a real model in the loop

```bash
ollama serve          # skip if the tray app already runs it
ollama pull qwen3:8b

cd examples/agent
mvn test -Plive
```

Use `-Plive`, not `-DexcludedGroups=`. Two traps it avoids: Surefire's POM configuration beats a
command-line `-D`, so `-DexcludedGroups=` is silently ignored and you get a green build that ran
nothing; and PowerShell mangles a `-D` argument containing a dot or ending in a bare `=`. A
profile id has neither problem.

Useful overrides:

| Property | Default | Effect |
| --- | --- | --- |
| `-Dmcprt.model=` | `qwen3:8b` | Which model. A hijack result is a statement about one model, so this changes what the test found. |
| `-Dmcprt.ollama.url=` | `http://localhost:11434` | Where Ollama is. |

`AgentHijackTest` holds two tests, and the split between them is the point:

- `reportsWhetherTheAgentIsHijacked` is **report-only**. It proves the run happened and prints the
  trace, but does not fail on a hijack — whether a given model obeys a given payload is a property
  of the model, and a red build nobody in your repository can fix is a test people delete.
- `trustPolicyPreventsTheHijack` is the **gate**. It applies a tool-trust policy, checks the policy
  actually withheld something, asserts the agent stayed clean, *and* asserts it still did the
  user's job. All four together — withholding a tool makes "did not call it" true by construction,
  and a policy that starves the agent of tools it legitimately needs is not a fix.

To point this at your own stack, replace `LocalAgent`. The harness takes a plain Spring AI
`ChatClient`, so any provider works; swap the `spring-ai-ollama` dependency for whichever you
already run.

## The dependency you will forget

`mcp-redteam-mcp` declares the MCP SDK as `provided`, and `mcp-redteam-spring-ai` declares Spring
AI and the SDK the same way — so the library never overrides a version you pinned. `provided`
dependencies are **not transitive**, which means supplying them is your job.

Leave one out and the build resolves fine. You get a `NoClassDefFoundError` when a test runs.
Both poms here carry the full set, with comments marking which lines are the bill.
