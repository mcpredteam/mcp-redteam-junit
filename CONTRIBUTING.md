# Contributing

Thanks for looking. This is a small, deliberately narrow project — reading the scope section
before writing code will save you the most time.

Security problems do not go in the issue tracker. See [SECURITY.md](SECURITY.md).

## Build and test

Requirements: **JDK 21+** and Maven 3.9+.

```bash
mvn verify          # build both modules and run all tests
mvn -pl mcp-redteam-core test
mvn -Dtest=InstructionInjectionRuleTest test
```

There is no code generation, no profile to activate and no network access needed. If
`mvn verify` needs anything beyond a JDK and a Maven cache, that is a bug worth reporting.

CI runs the same `mvn verify` on JDK 21 and 25. A red build blocks merge.

## Scope

The project is one sentence: **JUnit-native security tests for the MCP tool layer, against
real Java agents.** Contributions that sharpen that are welcome. Contributions that widen it
generally are not, and it is kinder to say so here than in a review of finished work.

**Welcome**

- New detection rules and new signatures for existing rules, with fixtures (see below).
- Normalization gaps — anything that lets a payload evade `TextNormalizer`.
- False-positive reports, with the benign tool metadata that triggered them. These are as
  valuable as missed detections; a scanner teams have muted is a scanner that is not running.
- Failure-message improvements. A finding should tell a developer what to do next.
- Work on the current milestone — see the Roadmap section of [README.md](README.md), and the
  open issues and milestones for what is actually in flight.
- Documentation fixes, including ones that make the project sound less impressive than it is.

**Likely to be declined**

- Runtime guardrails, gateways or proxies. Different product.
- Generic LLM red teaming — jailbreaks, toxicity, bias. Other projects own that lane;
  see [docs/strategy.md](docs/strategy.md).
- A new threat taxonomy. Everything maps onto the OWASP MCP Top 10.
- Dependencies in `mcp-redteam-core`. It has zero, and that is a feature: a static scan must
  not drag Spring or an HTTP client onto a consumer's test classpath.
- Empty placeholder modules or annotations with nothing to manage. Structure pretending to be
  architecture.
- LLM-as-judge detection, for now. Observed behavior first; see the detection philosophy in
  [docs/threat-model.md](docs/threat-model.md).

If you are unsure, open an issue before building. Nobody enjoys declining a finished PR.

## Contributing a detection rule

This is the most common contribution, and it has a hard requirement.

**Every new rule or signature must ship with both a poisoned fixture and a benign fixture.**

- Add the attack case to `PoisonedToolFixtures` and assert it is detected.
- Add at least one *honest* tool to `BenignToolFixtures` that contains the words your rule
  keys on, used in their ordinary sense — a real tool legitimately named `delete_draft`, a
  real description that mentions "base64" or "credentials". Assert it produces no
  high-severity finding.

The benign corpus is a build gate, not decoration. A rule that cannot survive contact with
honest tools that look like it will be reverted the first time it costs a user a red build.

Checklist for a rule PR:

- [ ] Rule id follows `MCPRT-XXX-NNN` and the family is documented in `README.md`.
- [ ] `ThreatType` maps to an existing OWASP MCP Top 10 category.
- [ ] `Severity` reflects impact; `Confidence` reflects certainty. They are separate axes —
      do not raise one to compensate for the other.
- [ ] Matching runs against `TextNormalizer.normalize(...)` output, not raw text.
- [ ] Obfuscation raises confidence rather than lowering it. Hiding a payload is evidence of
      intent.
- [ ] Schema traversal goes through `SchemaWalker`, never `Map.toString()`, and stays
      depth-capped. Hostile servers control their own schema nesting.
- [ ] Patterns are linear-time. No nested quantifiers a hostile description could stall on.
- [ ] The finding carries a location (JSON pointer), the matched evidence, and a remediation
      line a developer can act on.
- [ ] Payloads are original, written against public taxonomy — never lifted from another
      tool's corpus. Check the source's license before borrowing even a pattern.

### Assertions must be able to fail

An earlier scaffold shipped a scanner that only emitted `HIGH` and an assertion that only
tripped on `CRITICAL` — a pair that could never fail. If you touch severity thresholds or
assertion defaults, add a regression test proving the assertion still fails on the input it is
supposed to catch. A green test that verified nothing is the failure mode this project fears
most.

## Pull requests

- Branch from `main`. One logical change per PR.
- Keep the diff to what the PR title claims. Unrelated reformatting makes review harder.
- Tests are expected. New behaviour without a test will be asked for one.
- Update `README.md` if you change the rule table or the status table. The status table must
  keep listing what is **not** built — that honesty is load-bearing.
- Fill in the PR template. The "how this was verified" box is not rhetorical.
- Squash-merge is the default, so write the PR title as the commit message you want.

Style: standard Java conventions, 4-space indent, no wildcard imports. There is no formatter
plugin — match the surrounding code.

## Licensing of contributions

By submitting a pull request you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the same terms as the project. Inbound equals outbound; there
is no CLA to sign.

If your contribution includes anything derived from another project, say so in the PR and name
its license. Architecture and taxonomy can be borrowed from compatible sources with
attribution — see the prior-art table in [docs/references.md](docs/references.md).
**Payloads are written from scratch**, against the public
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) categories and the attack shapes
described in the [MCPTox benchmark](https://arxiv.org/abs/2508.14925) — never lifted from
another tool's corpus, whatever its license.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
