# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Before 1.0 the public API may break in a minor release. Detection rules are a different matter:
a rule that starts catching something it used to miss is a fix, not a break, and will land in a
patch. If that would turn your build red without warning, gate on
`hasNoFindingsAtOrAbove(...)` with an explicit severity rather than on a finding count.

## [Unreleased]

### Changed

- **Namespace is now `io.github.mcpredteam`** — both the Maven coordinate and the Java packages.
  Imports shorten from `io.github.harikrishna8121999.mcpredteam.mcp.McpServerConnection` to
  `io.github.mcpredteam.mcp.McpServerConnection`. Nothing had been published under the old
  coordinate, so no released version is affected.

### Added

- Maven Central publishing: a `release` profile producing sources, javadoc and GPG signatures,
  and a tag-driven [release workflow](.github/workflows/release.yml) that checks the tag against
  the pom version before uploading anything.

### Fixed

- Two javadoc references and one heading level that broke the docs build, which blocked the
  javadoc jar Central requires.

[Unreleased]: https://github.com/mcpredteam/mcp-redteam-junit/commits/main
