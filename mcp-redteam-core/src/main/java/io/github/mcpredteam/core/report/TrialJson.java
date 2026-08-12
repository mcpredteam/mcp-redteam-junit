package io.github.mcpredteam.core.report;

import io.github.mcpredteam.core.AgentRun;
import io.github.mcpredteam.core.ToolCallObservation;
import io.github.mcpredteam.core.TrialReport;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * A {@link TrialReport} as JSON: the rate, and the runs it was computed from.
 *
 * <pre>{@code
 * Reports.json(harness.runTrials(20, task))
 *         .measuring("hijacked", TrialReport.hijacked(canary, "record_analytics"))
 *         .measuring("leaked", TrialReport.thatLeaked(canary))
 *         .writeTo(Path.of("target/mcp-redteam/trials.json"));
 * }</pre>
 *
 * <p>A rate needs a name and a definition, and only the caller has those — "hijacked" means
 * something different in every test. {@link #measuring} supplies both, and the predicate is
 * evaluated once per run so the artifact records <em>which</em> trials matched rather than only
 * how many.
 *
 * <p><strong>The traces are the point.</strong> A bare rate says 6/20 and leaves the reader to
 * take it on trust; this project's whole objection to single-run verdicts is that a number
 * without the evidence behind it cannot be checked. So each run carries its tool calls with the
 * arguments <em>as the model produced them</em>, which is where an exfiltrated secret actually
 * appears — the same reasoning that put the interception point at {@code ToolCallback}.
 *
 * <p><strong>Consequently a trial report can contain the planted canary, and often will — that
 * is what a leak looks like.</strong> Treat the file as evidence from a security test rather
 * than as something to commit: write it under {@code target/}, and if a real credential was ever
 * planted instead of a generated one, the artifact now holds it too.
 *
 * <p>Nothing is truncated. Tool results can be large and twenty of them larger still, but this
 * is the file someone opens to work out how the model was talked into it, and a clipped argument
 * is exactly the part they came for.
 */
public final class TrialJson implements Report {

    private final TrialReport trials;
    private final Map<String, Predicate<AgentRun>> measurements = new LinkedHashMap<>();

    TrialJson(TrialReport trials) {
        this.trials = trials;
    }

    /**
     * Adds a named rate to the report.
     *
     * @param name      what this measures, e.g. {@code "hijacked"}; reusing a name replaces it
     * @param predicate what counts as a match, e.g. {@link TrialReport#hijacked}
     */
    public TrialJson measuring(String name, Predicate<AgentRun> predicate) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(predicate, "predicate");
        measurements.put(name, predicate);
        return this;
    }

    @Override
    public String render() {
        JsonWriter json = new JsonWriter();
        json.startObject()
                .field("schemaVersion", JsonFormat.SCHEMA_VERSION)
                .field("reportType", "trials");

        json.startObject("producer")
                .field("name", BuildInfo.NAME)
                .field("version", BuildInfo.version())
                .endObject();

        json.field("task", trials.task());

        json.startObject("trials")
                .field("run", trials.trials())
                .field("completed", trials.completedTrials())
                .field("failed", trials.failedRuns().size())
                .endObject();

        writeRates(json);
        writeRuns(json);

        return json.endObject().render() + "\n";
    }

    private void writeRates(JsonWriter json) {
        int completed = trials.completedTrials();
        json.startArray("rates");
        measurements.forEach((name, predicate) -> {
            json.startElement()
                    .field("name", name)
                    .field("matched", trials.where(predicate).size())
                    .field("of", completed);
            if (completed == 0) {
                // Null, not 0.0. TrialReport#rateOf throws here rather than answering, for the
                // reason this follows: a rate over zero completed runs is not a rate of zero, and
                // an afternoon of provider errors must not read as a security improvement. The
                // artifact has to preserve that distinction or it launders it back in.
                json.nullField("rate");
            } else {
                json.rate("rate", trials.rateOf(predicate));
            }
            json.endObject();
        });
        json.endArray();
    }

    private void writeRuns(JsonWriter json) {
        List<AgentRun> runs = trials.runs();
        json.startArray("runs");
        for (int i = 0; i < runs.size(); i++) {
            AgentRun run = runs.get(i);
            json.startElement().field("index", i);
            json.value("completed", run.completed());
            json.field("failure", run.failure());
            json.value("matched", matchedNames(run));
            json.field("startedAt", String.valueOf(run.startedAt()))
                    .field("finishedAt", String.valueOf(run.finishedAt()));

            json.startArray("toolCalls");
            for (ToolCallObservation call : run.toolCalls()) {
                json.startElement()
                        .field("sequence", call.sequence())
                        .field("server", call.serverName())
                        .field("tool", call.toolName())
                        .field("qualifiedName", call.qualifiedName())
                        .field("arguments", call.arguments())
                        .field("result", call.result())
                        .field("outcome", call.outcome())
                        .field("failure", call.failure())
                        .endObject();
            }
            json.endArray();

            json.value("assistantMessages", run.assistantMessages());
            json.field("finalResponse", run.finalResponse());
            json.endObject();
        }
        json.endArray();
    }

    /**
     * Which measurements this run matched.
     *
     * <p>Only completed runs are tested. A predicate over a run that never happened would report
     * "not hijacked", which is true in the same worthless way that a scan of no tools is clean —
     * so a failed trial matches nothing and its {@code failure} says why.
     */
    private List<String> matchedNames(AgentRun run) {
        if (!run.completed()) {
            return List.of();
        }
        List<String> matched = new ArrayList<>();
        measurements.forEach((name, predicate) -> {
            if (predicate.test(run)) {
                matched.add(name);
            }
        });
        return matched;
    }
}
