package io.github.harikrishna8121999.mcpredteam.core;

/**
 * Threat taxonomy, mapped onto the OWASP MCP Top 10 rather than invented here.
 *
 * <p>Only categories some rule can actually produce appear below. The enum deliberately does not
 * mirror the whole OWASP list: a constant no detector emits is a claim of coverage that does not
 * exist, and it reaches a reader as one — in an exhaustive switch, in a report schema, in the
 * javadoc. MCP08 Cross-Server Escalation was carried here unused from the first taxonomy pass and
 * has been removed for that reason. Add the constant back in the same change as the rule that
 * raises it; widening an enum is a compatible change, and narrowing one after a release is not.
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
    CONFUSED_DEPUTY("MCP02", "Excessive Agency"),
    EXFILTRATION_CHANNEL("MCP06", "Sensitive Data Exposure"),
    OVERBROAD_CAPABILITY("MCP02", "Excessive Agency"),

    /**
     * Not an attack: the test itself proved nothing, because the agent produced no observable
     * behaviour to judge.
     *
     * <p>It carries no OWASP id because it is not an OWASP threat, and inventing one would be
     * exactly the parallel taxonomy this enum exists to avoid. It is a finding rather than a
     * silent pass because an inconclusive security test that reports clean is the failure mode
     * this project fears most — see {@code BehaviorScanner}.
     */
    INCONCLUSIVE_RUN("-", "Inconclusive Run (not an OWASP category)");

    /** Human name of the taxonomy every {@link #owaspId()} belongs to. */
    public static final String TAXONOMY = "OWASP MCP Top 10";

    /**
     * Which revision of the taxonomy the ids above are read against.
     *
     * <p>Stamped onto every report, because the ids alone do not survive time. The OWASP MCP
     * Top 10 is still in beta — the categories are stable enough to cite, but the rankings are
     * explicitly expected to move at the next release, and a category that is {@code MCP03}
     * today may not be {@code MCP03} then. A report artifact that recorded only "MCP03" would
     * quietly change meaning after a renumbering, while sitting unchanged in someone's
     * repository. Recording the revision costs one line and makes an old report re-readable.
     *
     * <p>Bump this, and the ids in this enum, when the taxonomy is re-released.
     */
    public static final String TAXONOMY_VERSION = "0.1 (2025)";

    public static final String TAXONOMY_URL = "https://owasp.org/www-project-mcp-top-10/";

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
