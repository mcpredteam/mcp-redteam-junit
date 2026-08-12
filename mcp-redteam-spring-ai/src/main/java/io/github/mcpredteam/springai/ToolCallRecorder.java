package io.github.mcpredteam.springai;

import io.github.mcpredteam.core.ToolCallObservation;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Collects tool calls as they happen during one agent run.
 *
 * <p>Thread-safe because the tool-calling loop may execute calls in parallel: an agent that
 * requests three tools in one turn can have them dispatched concurrently, and a plain
 * {@code ArrayList} would drop or corrupt observations exactly when the agent is doing the
 * most interesting thing.
 */
public final class ToolCallRecorder {

    private final List<ToolCallObservation> observations = new CopyOnWriteArrayList<>();
    private final AtomicInteger nextSequence = new AtomicInteger();

    /** Reserves this call's position in the run before it executes. */
    int nextSequence() {
        return nextSequence.getAndIncrement();
    }

    void add(ToolCallObservation observation) {
        observations.add(observation);
    }

    /**
     * Observations in call order.
     *
     * <p>Sorted by the sequence reserved at dispatch rather than by completion, so a slow first
     * call cannot make the trace claim the agent acted in an order it did not.
     */
    public List<ToolCallObservation> observations() {
        return observations.stream()
                .sorted(Comparator.comparingInt(ToolCallObservation::sequence))
                .toList();
    }
}
