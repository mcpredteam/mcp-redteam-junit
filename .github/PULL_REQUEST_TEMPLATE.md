<!--
Security vulnerabilities do not belong in a pull request. See SECURITY.md.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one: Fixes #123 -->

## Why

<!-- What was wrong, or what this makes possible. -->

## How this was verified

<!-- Not rhetorical. Name the tests you added or ran, and paste the relevant output
     if a failure message changed. "mvn verify passes" alone is not enough for a
     detection change. -->

## Checklist

- [ ] `mvn verify` passes locally on JDK 21
- [ ] Tests added for new behaviour, or an explanation below of why none apply
- [ ] Scope matches the PR title — no unrelated reformatting in the diff
- [ ] `README.md` updated if the rule table or status table changed
- [ ] No new dependency added to `mcp-redteam-core` (it stays at zero)

### If this adds or changes a detection rule

- [ ] Poisoned fixture added to `PoisonedToolFixtures`, asserted as detected
- [ ] **Benign fixture added to `BenignToolFixtures`** — an honest tool containing the words
      this rule keys on, asserted to produce no high-severity finding
- [ ] `ThreatType` maps to an existing OWASP MCP Top 10 category (no new taxonomy)
- [ ] Matching runs on `TextNormalizer.normalize(...)` output; obfuscation raises confidence
- [ ] Schema traversal uses `SchemaWalker` and stays depth-capped
- [ ] Patterns are linear-time — no nested quantifiers a hostile description could stall on
- [ ] Payloads are original, not lifted from another tool's corpus

### If this touches severity, confidence or assertion defaults

- [ ] A regression test proves the assertion still **fails** on input it is meant to catch

## Anything a reviewer should push back on

<!-- Shortcuts taken, things you are unsure about, coverage you knowingly skipped.
     Saying so here is cheaper than it being found later. -->
