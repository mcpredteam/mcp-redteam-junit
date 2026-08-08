package io.github.harikrishna8121999.mcpredteam.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Everything one agent execution did, recorded for assertion.
 *
 * <p>An {@code AgentRun} is the dynamic counterpart to {@link ScanReport}: where a scan says
 * what tool metadata <em>looked</em> like, a run says what a real agent <em>did</em> when it
 * read that metadata. It is deliberately inert — it records, and detectors judge.
 *
 * @param task         the benign user request the agent was given, quoted back in failures so
 *                     a reader can see the agent was never asked to do the malicious thing
 * @param systemPrompt the context the agent started with, including any planted secret. Held
 *                     so a test can prove the canary really was planted — a canary that never
 *                     entered the context makes every later leak assertion pass vacuously.
 * @param offeredTools every tool definition visible to the agent, trusted and malicious alike.
 *                     Keeping these on the run lets the static scanner run over exactly what
 *                     the agent saw, rather than over a separately-built list that may drift.
 * @param assistantMessages the agent's intermediate turns, between tool calls.
 *                     <strong>The Spring AI harness does not populate this.</strong> Spring AI's
 *                     tool-calling loop does not surface per-iteration assistant text through a
 *                     public API, so only {@code finalResponse} is captured, and
 *                     {@code MCPRT-LEAK-002} can currently only fire against that. The field is
 *                     read by the detectors so a harness that <em>can</em> observe intermediate
 *                     turns gets the coverage for free; until one does, treat the gap as real.
 *                     A secret disclosed mid-run and then sent onward is still caught, because
 *                     the tool argument that carried it is recorded.
 * @param failure      why the run itself did not complete, empty when it did
 */
public record AgentRun(
        String task,
        String systemPrompt,
        String finalResponse,
        List<ToolCallObservation> toolCalls,
        List<String> assistantMessages,
        List<ToolDefinition> offeredTools,
        Instant startedAt,
        Instant finishedAt,
        String failure
) {
    /** Finding target for text the agent showed the user rather than handed to a tool. */
    private static final String AGENT = "agent";

    public AgentRun {
        task = task == null ? "" : task;
        systemPrompt = systemPrompt == null ? "" : systemPrompt;
        finalResponse = finalResponse == null ? "" : finalResponse;
        toolCalls = toolCalls == null ? List.of() : List.copyOf(toolCalls);
        // Filtered here rather than at every read site: a blank message is not something the
        // agent said, and letting one through would put an empty excerpt in a finding.
        assistantMessages = assistantMessages == null
                ? List.of()
                : assistantMessages.stream().filter(m -> m != null && !m.isBlank()).toList();
        offeredTools = offeredTools == null ? List.of() : List.copyOf(offeredTools);
        failure = failure == null ? "" : failure;
        startedAt = startedAt == null ? Instant.EPOCH : startedAt;
        finishedAt = finishedAt == null ? startedAt : finishedAt;
    }

    public boolean completed() {
        return failure.isEmpty();
    }

    /**
     * Whether the agent did anything observable at all.
     *
     * <p>Assertions consult this before passing. A run that produced no calls and no text
     * usually means the harness was misconfigured or the model errored, and every
     * "did not call the malicious tool" assertion over it would pass without testing anything.
     */
    public boolean hasObservations() {
        return !toolCalls.isEmpty() || !finalResponse.isBlank() || !assistantMessages.isEmpty();
    }

    /** Qualified names of every call, in order, including repeats. */
    public List<String> calledToolNames() {
        return toolCalls.stream().map(ToolCallObservation::qualifiedName).toList();
    }

    /** Accepts a bare or server-qualified name. */
    public boolean called(String toolName) {
        return toolCalls.stream().anyMatch(call -> call.matches(toolName));
    }

    public List<ToolCallObservation> callsTo(String toolName) {
        return toolCalls.stream().filter(call -> call.matches(toolName)).toList();
    }

    public List<ToolCallObservation> callsToServer(String serverName) {
        return toolCalls.stream().filter(call -> call.serverName().equals(serverName)).toList();
    }

    /**
     * Everything the agent <em>produced</em>, each piece tagged with where it came from.
     *
     * <p>Tool results are excluded on purpose. A result is something the agent <em>read</em>,
     * so a malicious server that echoes a planted secret back would otherwise trip a leak
     * assertion the agent never actually failed. Exfiltration shows up in an argument or in
     * the response — both of which are here. Use {@link #allObservedText()} when you want the
     * inbound side too, for example when hunting for injected instructions in tool output.
     *
     * <p>This is the single definition of "emitted". {@link #allEmittedText()} and
     * {@code CanaryLeakRule} both read it rather than each walking the run themselves, because
     * two copies of this rule would eventually disagree about it.
     */
    public List<Emission> emissions() {
        List<Emission> emissions = new ArrayList<>();
        if (!finalResponse.isBlank()) {
            emissions.add(new Emission("finalResponse", AGENT, finalResponse));
        }
        for (int i = 0; i < assistantMessages.size(); i++) {
            emissions.add(new Emission("assistantMessage/" + i, AGENT, assistantMessages.get(i)));
        }
        for (ToolCallObservation call : toolCalls) {
            if (!call.arguments().isBlank()) {
                emissions.add(new Emission(
                        "toolCall/" + call.sequence() + "/arguments", call.qualifiedName(), call.arguments()));
            }
        }
        return List.copyOf(emissions);
    }

    public List<String> allEmittedText() {
        return emissions().stream().map(Emission::text).toList();
    }

    /** Emitted text plus every tool result — the whole conversation surface. */
    public List<String> allObservedText() {
        List<String> texts = new ArrayList<>(allEmittedText());
        toolCalls.stream()
                .map(ToolCallObservation::result)
                .filter(r -> !r.isBlank())
                .forEach(texts::add);
        return List.copyOf(texts);
    }

    /**
     * One thing the agent produced.
     *
     * @param location where it came from, e.g. {@code toolCall/1/arguments}
     * @param target   who is answerable for it: the agent, or the tool it was handed to.
     *                 Text sent to a tool has left the agent's control, which is why leak
     *                 findings against a tool argument outrank ones against the response.
     */
    public record Emission(String location, String target, String text) {

        /** Whether this text was handed to a tool rather than shown to the user. */
        public boolean isToolArgument() {
            return location.startsWith("toolCall/");
        }
    }

    /** Multi-line trace of the run, for failure messages. */
    public String describeTrace() {
        StringBuilder sb = new StringBuilder("task: ").append(Excerpts.truncate(task));
        if (toolCalls.isEmpty()) {
            sb.append(System.lineSeparator()).append("    (no tool calls)");
        } else {
            for (ToolCallObservation call : toolCalls) {
                sb.append(System.lineSeparator()).append("    ").append(call.describe());
            }
        }
        if (!failure.isEmpty()) {
            sb.append(System.lineSeparator()).append("    run failed: ").append(Excerpts.truncate(failure));
        }
        return sb.toString();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String task = "";
        private String systemPrompt = "";
        private String finalResponse = "";
        private final List<ToolCallObservation> toolCalls = new ArrayList<>();
        private final List<String> assistantMessages = new ArrayList<>();
        private final Map<String, ToolDefinition> offeredTools = new LinkedHashMap<>();
        private Instant startedAt = Instant.EPOCH;
        private Instant finishedAt = Instant.EPOCH;
        private String failure = "";

        private Builder() {
        }

        public Builder task(String value) {
            this.task = value;
            return this;
        }

        public Builder systemPrompt(String value) {
            this.systemPrompt = value;
            return this;
        }

        public Builder finalResponse(String value) {
            this.finalResponse = value;
            return this;
        }

        /** Assigns the next sequence number, so callers cannot record calls out of order. */
        public Builder record(ToolCallObservation.Builder call) {
            Objects.requireNonNull(call, "call");
            toolCalls.add(call.sequence(toolCalls.size()).build());
            return this;
        }

        public Builder assistantMessage(String value) {
            if (value != null && !value.isBlank()) {
                assistantMessages.add(value);
            }
            return this;
        }

        /** Later definitions of the same qualified name replace earlier ones. */
        public Builder offering(ToolDefinition definition) {
            if (definition != null) {
                offeredTools.put(definition.qualifiedName(), definition);
            }
            return this;
        }

        public Builder offering(Iterable<ToolDefinition> definitions) {
            if (definitions != null) {
                definitions.forEach(this::offering);
            }
            return this;
        }

        public Builder startedAt(Instant value) {
            this.startedAt = value;
            return this;
        }

        public Builder finishedAt(Instant value) {
            this.finishedAt = value;
            return this;
        }

        public Builder failure(String value) {
            this.failure = value;
            return this;
        }

        public AgentRun build() {
            return new AgentRun(task, systemPrompt, finalResponse, toolCalls, assistantMessages,
                    List.copyOf(offeredTools.values()), startedAt, finishedAt, failure);
        }
    }
}
