package io.github.harikrishna8121999.mcpredteam.core;

/**
 * Threat taxonomy, mapped onto the OWASP MCP Top 10 rather than invented here.
 *
 * @see <a href="https://owasp.org/www-project-mcp-top-10/">OWASP MCP Top 10</a>
 */
public enum ThreatType {
    TOOL_POISONING("MCP03", "Tool Poisoning"),
    SCHEMA_POISONING("MCP03", "Tool Poisoning / Schema Poisoning"),
    TOOL_SHADOWING("MCP03", "Tool Poisoning / Tool Shadowing"),
    RUG_PULL("MCP03", "Tool Poisoning / Rug Pull"),
    TOOL_RESULT_INJECTION("MCP01", "Prompt Injection via Tool Output"),
    CROSS_TOOL_POISONING("MCP03", "Tool Poisoning / Cross-Tool"),
    CROSS_SERVER_ATTACK("MCP08", "Cross-Server Escalation"),
    CONFUSED_DEPUTY("MCP02", "Excessive Agency"),
    EXFILTRATION_CHANNEL("MCP06", "Sensitive Data Exposure"),
    OVERBROAD_CAPABILITY("MCP02", "Excessive Agency");

    private final String owaspId;
    private final String owaspTitle;

    ThreatType(String owaspId, String owaspTitle) {
        this.owaspId = owaspId;
        this.owaspTitle = owaspTitle;
    }

    public String owaspId() {
        return owaspId;
    }

    public String owaspTitle() {
        return owaspTitle;
    }
}
