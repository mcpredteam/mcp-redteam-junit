package io.github.harikrishna8121999.mcpredteam.core;

import java.time.Instant;
import java.util.Objects;

/**
 * One tool invocation an agent actually made, recorded as it happened.
 *
 * <p>This is the unit of evidence the dynamic harness produces. Unlike a static finding it
 * asserts nothing — it is a fact about what the agent did, and detectors interpret it later.
 *
 * @param sequence  0-based position in the run, so a report can say which call came first
 * @param arguments the tool input <em>exactly as the model produced it</em>, normally a JSON
 *                  object. It is kept as raw text on purpose: this is the field a canary
 *                  usually leaks through, and re-serializing it through a parser can drop or
 *                  reorder the very characters the leak is hiding in.
 * @param result    what the tool returned, or empty when the call did not succeed. This is
 *                  agent <em>input</em>, not agent output — see {@link AgentRun#allEmittedText()}.
 * @param failure   the error text when {@code outcome} is {@link ToolCallOutcome#FAILED}
 */
public record ToolCallObservation(
        int sequence,
        String serverName,
        String toolName,
        String arguments,
        String result,
        ToolCallOutcome outcome,
        String failure,
        Instant at
) {
    public ToolCallObservation {
        Objects.requireNonNull(toolName, "toolName");
        Objects.requireNonNull(outcome, "outcome");
        serverName = serverName == null ? "" : serverName;
        arguments = arguments == null ? "" : arguments;
        result = result == null ? "" : result;
        failure = failure == null ? "" : failure;
        at = at == null ? Instant.EPOCH : at;
    }

    /** Server-qualified identity, matching {@link ToolDefinition#qualifiedName()}. */
    public String qualifiedName() {
        return serverName.isEmpty() ? toolName : serverName + "/" + toolName;
    }

    /**
     * Whether this call refers to {@code name}, given either bare ({@code record_analytics})
     * or server-qualified ({@code evil-analytics/record_analytics}).
     *
     * <p>Matching is case-sensitive. Tool names are protocol identifiers the model reproduces
     * verbatim, and case-folding them would let a shadowing tool named {@code Send_Email}
     * satisfy an assertion written against {@code send_email}.
     */
    public boolean matches(String name) {
        return name != null && (name.equals(toolName) || name.equals(qualifiedName()));
    }

    /** Short one-line rendering for failure messages. */
    public String describe() {
        StringBuilder sb = new StringBuilder()
                .append('#').append(sequence + 1).append(' ')
                .append(qualifiedName())
                .append('(').append(Excerpts.truncate(arguments)).append(')');
        if (outcome != ToolCallOutcome.SUCCEEDED) {
            sb.append(" -> ").append(outcome);
            if (!failure.isBlank()) {
                sb.append(": ").append(Excerpts.truncate(failure));
            }
        }
        return sb.toString();
    }

    public static Builder builder(String toolName) {
        return new Builder(toolName);
    }

    public static final class Builder {
        private final String toolName;
        private int sequence;
        private String serverName = "";
        private String arguments = "";
        private String result = "";
        private ToolCallOutcome outcome = ToolCallOutcome.SUCCEEDED;
        private String failure = "";
        private Instant at = Instant.EPOCH;

        private Builder(String toolName) {
            this.toolName = toolName;
        }

        public Builder sequence(int value) {
            this.sequence = value;
            return this;
        }

        public Builder serverName(String value) {
            this.serverName = value;
            return this;
        }

        public Builder arguments(String value) {
            this.arguments = value;
            return this;
        }

        public Builder result(String value) {
            this.result = value;
            return this;
        }

        public Builder outcome(ToolCallOutcome value) {
            this.outcome = value;
            return this;
        }

        public Builder failure(String value) {
            this.failure = value;
            return this;
        }

        public Builder at(Instant value) {
            this.at = value;
            return this;
        }

        public ToolCallObservation build() {
            return new ToolCallObservation(sequence, serverName, toolName, arguments, result, outcome, failure, at);
        }
    }
}
