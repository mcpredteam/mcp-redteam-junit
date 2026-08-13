# Example: agent in the loop

A real Spring AI agent, a real model, a poisoned MCP server, and a benign user request — then a
tool-trust policy stopping it.

```bash
ollama serve
ollama pull qwen3:8b

mvn test -Plive
```

Everything here is tagged `live`, so a plain `mvn test` runs nothing and stays green on a machine
with no model. Replace `LocalAgent` to point it at your own provider.

See [../README.md](../README.md) for the report-versus-gate split, which is the part worth
reading carefully.
