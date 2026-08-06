package io.github.harikrishna8121999.mcpredteam.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A single normalized security observation.
 *
 * @param ruleId      stable identifier of the rule that produced this, e.g. {@code MCPRT-INJ-001}
 * @param location    where in the tool definition the evidence sits, e.g. {@code inputSchema/properties/payload/description}
 * @param evidence    the matched excerpt and supporting detail; keys are rule-specific
 */
public record Finding(
        String ruleId,
        ThreatType threatType,
        Severity severity,
        Confidence confidence,
        String target,
        String location,
        String message,
        String remediation,
        Map<String, Object> evidence
) {
    public Finding {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(threatType, "threatType");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        evidence = evidence == null ? Map.of() : Map.copyOf(evidence);
    }

    /** Identity for de-duplication: the same rule firing at the same place is one finding. */
    public String dedupeKey() {
        return ruleId + "|" + target + "|" + location + "|" + evidence.getOrDefault("match", "");
    }

    public String describe() {
        StringBuilder sb = new StringBuilder()
                .append('[').append(severity).append("] ")
                .append(ruleId).append(' ')
                .append('(').append(threatType.owaspId()).append(' ').append(threatType.owaspTitle()).append(", ")
                .append("confidence=").append(confidence).append(")")
                .append(System.lineSeparator())
                .append("    where: ").append(target);
        if (location != null && !location.isBlank()) {
            sb.append(" @ ").append(location);
        }
        sb.append(System.lineSeparator()).append("    what:  ").append(message);
        Object match = evidence.get("match");
        if (match != null) {
            sb.append(System.lineSeparator()).append("    match: ").append(truncate(String.valueOf(match)));
        }
        if (remediation != null && !remediation.isBlank()) {
            sb.append(System.lineSeparator()).append("    fix:   ").append(remediation);
        }
        return sb.toString();
    }

    private static String truncate(String value) {
        String collapsed = value.replaceAll("\\s+", " ").trim();
        return collapsed.length() <= 160 ? collapsed : collapsed.substring(0, 157) + "...";
    }

    public static Builder builder(String ruleId) {
        return new Builder(ruleId);
    }

    public static final class Builder {
        private final String ruleId;
        private ThreatType threatType;
        private Severity severity;
        private Confidence confidence = Confidence.FIRM;
        private String target = "";
        private String location = "";
        private String message = "";
        private String remediation = "";
        private final Map<String, Object> evidence = new LinkedHashMap<>();

        private Builder(String ruleId) {
            this.ruleId = ruleId;
        }

        public Builder threatType(ThreatType value) {
            this.threatType = value;
            return this;
        }

        public Builder severity(Severity value) {
            this.severity = value;
            return this;
        }

        public Builder confidence(Confidence value) {
            this.confidence = value;
            return this;
        }

        public Builder target(String value) {
            this.target = value;
            return this;
        }

        public Builder location(String value) {
            this.location = value;
            return this;
        }

        public Builder message(String value) {
            this.message = value;
            return this;
        }

        public Builder remediation(String value) {
            this.remediation = value;
            return this;
        }

        public Builder evidence(String key, Object value) {
            this.evidence.put(key, value);
            return this;
        }

        public Finding build() {
            return new Finding(ruleId, threatType, severity, confidence, target, location, message, remediation, evidence);
        }
    }
}
