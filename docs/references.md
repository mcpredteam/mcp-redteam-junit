# References

The specifications, standards and research this project is built against. Each entry says
which part of the codebase it backs, so a reader can check the implementation against the
source rather than taking a rule's word for it.

## Threat taxonomy

- **OWASP MCP Top 10** — https://owasp.org/www-project-mcp-top-10/

  The taxonomy this project uses. `ThreatType` maps onto these ids and carries one on every
  `Finding`; no parallel taxonomy is invented. Tool poisoning is **MCP03**, with rug pulls,
  schema poisoning and tool shadowing as sub-techniques.

- **MCPTox: A Benchmark for Tool Poisoning on Real-World MCP Servers** (AAAI)
  - https://arxiv.org/abs/2508.14925
  - https://ojs.aaai.org/index.php/AAAI/article/view/40895

  Source of the 36.5% average attack success rate quoted in `README.md` and
  [threat-model.md](threat-model.md), measured across 20 agents against 45 real MCP servers and
  353 tools. Also the source of two design assumptions: that more capable models are often
  *more* susceptible because the attack exploits instruction-following, and that conventional
  indirect-prompt-injection payloads are largely ineffective against this surface — which is
  why this is not a rebadged prompt-injection suite. The attack *shapes* described here
  informed `PoisonedToolFixtures`; none of the payloads are copied.

## Model Context Protocol

- **MCP specification** — https://modelcontextprotocol.io/specification

  Defines `tools/list` and the tool metadata fields that `ToolDefinition` models: name,
  description, `inputSchema`, and annotations including `destructiveHint`. Every one of those
  fields is server-controlled, which is the premise the threat model rests on.

- **MCP Java SDK** — https://java.sdk.modelcontextprotocol.io/latest/server/

  The server-side API the planned fixture MCP servers are built on. STDIO, SSE and Streamable
  HTTP transports ship in the core module with no web framework required.

- **JSON Schema** — https://json-schema.org/

  What an MCP `inputSchema` is. `SchemaWalker` traverses it structurally rather than
  stringifying it, and caps recursion depth because a hostile server controls its own nesting.

- **RFC 6901 — JSON Pointer** — https://datatracker.ietf.org/doc/html/rfc6901

  The location format on every `Finding`. A finding points at
  `inputSchema/properties/callback/description`, not at a line of stringified map output.

## Unicode evasion

These back `TextNormalizer` and `HiddenUnicodeRule` (`MCPRT-UNI`). Detection runs on
normalized text, so splicing invisible characters into a payload does not defeat matching.

- **UAX #15 — Unicode Normalization Forms** — https://unicode.org/reports/tr15/

  NFKC is the normalization applied before any rule matches.

- **UTS #39 — Unicode Security Mechanisms** — https://unicode.org/reports/tr39/

  Confusables and mixed-script detection: the basis for folding homoglyphs so a Cyrillic-`а`
  tool name cannot impersonate a trusted ASCII-`a` one.

- **UAX #9 — Unicode Bidirectional Algorithm** — https://unicode.org/reports/tr9/

  Bidi override characters, which can make tool metadata render differently from how a model
  reads it.

- **Tags block (U+E0000–U+E007F)** — https://www.unicode.org/charts/PDF/UE0000.pdf

  Invisible tag characters, usable to smuggle instructions that a human reviewer never sees.

- **Trojan Source** (CVE-2021-42574) — https://trojansource.codes/

  Prior demonstration of the same class of attack against source code. Useful background for
  why "invisible character present" is treated as high-confidence evidence: there is no benign
  reason for one to appear in a tool description.

- **RFC 4648 — Base16, Base32, Base64 encodings** —
  https://datatracker.ietf.org/doc/html/rfc4648

  Backs `EncodedPayloadRule` (`MCPRT-ENC`), which decodes candidate runs and re-scans the
  result rather than flagging on the presence of encoded-looking text.

## JVM and framework integration

- **Spring AI reference documentation** — https://docs.spring.io/spring-ai/reference/
- **Spring AI observability** — https://docs.spring.io/spring-ai/reference/observability/index.html

  The tool-calling loop is part of the advisor chain, which is the supported interception point
  for the planned dynamic harness — see [integration-plan.md](integration-plan.md).

- **Spring AI MCP Security** — https://github.com/spring-ai-community/mcp-security

  Complementary, not overlapping: it secures MCP transport and authentication, this project
  tests tool semantics. Both are worth having.

- **LangChain4j MCP** — https://docs.langchain4j.dev/tutorials/model-context-protocol/

  Target for a second harness once the Spring AI one demonstrably works.

## Prior art

Structure borrowed with thanks; payloads never. All fixtures in `PoisonedToolFixtures` are
original, written against the OWASP MCP03 categories and the attack shapes described in
MCPTox. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rule contributors are held to.

| Project | What this project learned from it |
| --- | --- |
| [garak](https://github.com/NVIDIA/garak) (NVIDIA, Apache 2.0) | Probe / detector / report separation; structured scan logs. |
| [PyRIT](https://microsoft.github.io/PyRIT/) (Microsoft) | Target and scorer as distinct concepts. |
| [DeepTeam](https://github.com/confident-ai/deepteam) (Apache 2.0) | Vulnerability-first UX; separating attacks from vulnerabilities. |
| [promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) (MIT) | CI and report ergonomics; dynamic MCP scenario design. |

Existing MCP scanners — [mcp-scan](https://invariantlabs.ai/blog/introducing-mcp-scan),
[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) and the unrelated Node
[mcp-shield](https://github.com/riseandignite/mcp-shield) — cover static metadata scanning,
and cover it well. `README.md` says plainly where this project overlaps with them and where
it does not.
