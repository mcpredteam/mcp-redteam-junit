# Documentation

## Using the library

Read in order if you are new:

1. **[Getting started](guide/getting-started.md)** — install, write your first test, wire it into CI
2. **[Choosing your modules](guide/installation.md)** — what each module costs, Maven and Gradle blocks
3. **[Scanning a live server](guide/scanning-a-live-server.md)** — point a scan at a real MCP server
4. **[Catching a rug pull](guide/rug-pull.md)** — baselines, drift, and why capture refuses
5. **[Testing an agent](guide/agent-testing.md)** — the Spring AI harness, canaries, trust policies, rates
6. **[Reports](guide/reports.md)** — JSON and JUnit XML artifacts
7. **[Rules reference](guide/rules.md)** — every rule id, what trips it, how to suppress it
8. **[Troubleshooting](guide/troubleshooting.md)** — the errors people actually hit

Runnable code for all of it lives in **[examples/](../examples)**.

## Writeups

- **[The payload decided the outcome, not the model](blog/the-payload-decided-the-outcome.md)** —
  the caricatured `Ignore all previous instructions` payload every MCP demo uses scored 0/20
  against a local model; a tool that merely declared an `apiKey` parameter scored 20/20. Why a
  hijack test that only fires the caricature is measuring the payload, not the agent.

## Design and background

These explain *why* the library is shaped the way it is. Not needed to use it.

- **[Strategy](strategy.md)** — positioning, and what is honestly defensible about it
- **[Threat model](threat-model.md)** — what is covered, and what a green build still does not mean
- **[Architecture](architecture.md)** — pipeline, package shape, decisions worth keeping
- **[Integration plan](integration-plan.md)** — what is built, in what order, and why
- **[References](references.md)** — specs, standards and research each rule is built against
