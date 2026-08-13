# Example: scanning, no model required

MCP security checks for a team that has no agent. No model, no API key, nothing to install
beyond a JDK 21 and Maven.

```bash
mvn test
```

Twelve tests, green in about twenty seconds. Start with `OwnServerScanTest` — it is the whole
library in one test.

See [../README.md](../README.md) for what each test demonstrates and how to re-capture the
drift baseline.
