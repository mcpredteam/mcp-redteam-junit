# Security Policy

This project is a security testing tool. That cuts two ways: it has its own attack surface,
and it ships material that describes attacks. This page covers both, plus the rules for using
it against systems.

## Reporting a vulnerability in this project

Do **not** open a public issue for a security problem.

- Preferred: [GitHub private security advisory](https://github.com/mcpredteam/mcp-redteam-junit/security/advisories/new)
- Alternative: harikrishnavshetty@gmail.com

Please include the affected version or commit, a description of the impact, and the smallest
reproduction you can manage — ideally a failing JUnit test.

This is a single-maintainer project, so response is best-effort rather than contractual:

| Stage | Target |
| --- | --- |
| Acknowledgement | 5 business days |
| Initial assessment | 10 business days |
| Fix or documented mitigation | 90 days, coordinated with you |

Credit is given in the advisory and release notes unless you ask otherwise.

### In scope

- Denial of service in the scanner — pathological schemas, unbounded recursion, catastrophic
  backtracking in a rule's pattern matching. A hostile MCP server controls its own tool
  metadata, so anything an attacker-supplied `ToolDefinition` can do to the scanning process
  is a real vulnerability, not a robustness nit.
- **Detection bypasses.** A payload that a rule should catch and does not — for example a
  normalization gap in `TextNormalizer` that lets an injection string through. For a security
  tool a false negative is the core failure, so these are treated as vulnerabilities rather
  than as feature requests.
- Anything in `mcp-redteam-core` that reaches the network or filesystem. It is meant to do
  neither.
- Supply-chain problems in what the published artifacts pull in.

### Out of scope

- Vulnerabilities in third-party MCP servers you discovered *using* this tool. See below.
- Findings against the deliberately malicious fixtures in `PoisonedToolFixtures`. They are
  supposed to look malicious.
- False *positives*. Report those as ordinary issues — they matter (see `CONTRIBUTING.md`),
  but they are not a disclosure.
- Results from scanning a hosted deployment of this project. There isn't one; it is a library.

## Reporting a vulnerability you found *with* this tool

If a scan or a canary test exposes a flaw in someone else's MCP server, that is their
vulnerability to fix and their disclosure to coordinate. Report it to that project or vendor,
not here — we cannot triage or fix it, and we will not act as an intermediary.

Do not open an issue here naming an unpatched third-party server. Once a finding is public and
fixed, a regression fixture demonstrating the *pattern* (not the vendor) is very welcome.

## Responsible use

This project builds poisoned tool metadata, plants canary secrets, and tries to make agents
misbehave. Use it only against:

- MCP servers you own or operate,
- agents and applications you own or operate, or
- third-party systems where you hold **explicit written authorization** to test.

Running this against someone else's production MCP server without permission may be illegal in
your jurisdiction regardless of intent. That is on you, not on this project — see the "AS IS,
without warranties" clause in `LICENSE`.

Canaries are real planted secrets in the run they belong to. Mint them per test with
`Canary.random()`; never plant a live credential as a canary.

## About the attack payloads in this repository

`PoisonedToolFixtures` contains original payloads written against the public
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) categories and the attack shapes
described in the [MCPTox benchmark](https://arxiv.org/abs/2508.14925). They are test fixtures:
strings designed to be *detected*, illustrating publicly documented attack classes. They are
not copied from another tool's corpus, and they are not weaponized exploits against any
specific product.

Contributions of new payloads must meet the same bar — original, mapped to a published
taxonomy, and paired with benign fixtures. See `CONTRIBUTING.md`.

## What a passing test does and does not mean

Worth stating in a security policy, because the opposite assumption is the most likely way
this tool causes harm:

A clean `ScanReport` means nothing in the supplied tool metadata *matched a rule*. It is not
an assurance that a server is safe, that an agent resists it, or that the metadata has not
changed since you scanned it. Rug-pull detection, tool-result injection and confused-deputy
coverage are **not built** — see the status table in `README.md`. Do not represent a green
build from this tool as a security sign-off.
