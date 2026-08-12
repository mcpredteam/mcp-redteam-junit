package io.github.mcpredteam.springai;

import io.github.mcpredteam.core.ToolCallObservation;
import io.github.mcpredteam.core.ToolCallOutcome;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.metadata.ToolMetadata;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Wraps a Spring AI {@link ToolCallback} and records every invocation.
 *
 * <p>This is the interception point the whole dynamic harness rests on, and it was chosen over
 * the advisor chain deliberately. An advisor sees messages; {@code ToolCallback#call} receives
 * the tool input <em>as the model produced it</em>, before any parsing, which is the only place
 * an exfiltrated secret is guaranteed to appear verbatim. It is also a stable public interface
 * rather than an internal of the tool-calling loop, so the harness does not break when that
 * loop is reorganised.
 *
 * <p>The decorator is transparent: {@link #getToolDefinition()} and {@link #getToolMetadata()}
 * pass straight through, so the model sees exactly the metadata the real server published,
 * poison included. Recording that changed what the agent saw would not be a test of anything.
 */
public final class RecordingToolCallback implements ToolCallback {

    private final ToolCallback delegate;
    private final String serverName;
    private final ToolCallRecorder recorder;
    private final Set<String> blockedTools;

    public RecordingToolCallback(ToolCallback delegate, String serverName,
                                 ToolCallRecorder recorder, Set<String> blockedTools) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.serverName = serverName == null ? "" : serverName;
        this.recorder = Objects.requireNonNull(recorder, "recorder");
        this.blockedTools = Set.copyOf(blockedTools);
    }

    @Override
    public ToolDefinition getToolDefinition() {
        return delegate.getToolDefinition();
    }

    @Override
    public ToolMetadata getToolMetadata() {
        return delegate.getToolMetadata();
    }

    @Override
    public String call(String toolInput) {
        return record(toolInput, () -> delegate.call(toolInput));
    }

    /**
     * Overridden as well as {@link #call(String)}, not instead of it. Callbacks that carry
     * context — MCP-backed ones do — are invoked through this overload, and inheriting the
     * interface default would drop the {@link ToolContext} on its way to the delegate.
     */
    @Override
    public String call(String toolInput, ToolContext toolContext) {
        return record(toolInput, () -> delegate.call(toolInput, toolContext));
    }

    private String record(String toolInput, Supplier<String> invocation) {
        String toolName = delegate.getToolDefinition().name();
        int sequence = recorder.nextSequence();

        ToolCallObservation.Builder observation = ToolCallObservation.builder(toolName)
                .sequence(sequence)
                .serverName(serverName)
                .arguments(toolInput)
                .at(Instant.now());

        if (blockedTools.contains(toolName) || blockedTools.contains(qualified(toolName))) {
            recorder.add(observation
                    .outcome(ToolCallOutcome.BLOCKED)
                    .result(BLOCKED_RESULT)
                    .build());
            return BLOCKED_RESULT;
        }

        try {
            String result = invocation.get();
            recorder.add(observation.result(result).outcome(ToolCallOutcome.SUCCEEDED).build());
            return result;
        } catch (RuntimeException e) {
            // Recorded, then rethrown. The agent's decision to make the call is the finding;
            // swallowing the exception here would hide a broken fixture behind a clean run.
            recorder.add(observation
                    .outcome(ToolCallOutcome.FAILED)
                    .failure(e.getClass().getSimpleName() + ": " + e.getMessage())
                    .build());
            throw e;
        }
    }

    private String qualified(String toolName) {
        return serverName.isEmpty() ? toolName : serverName + "/" + toolName;
    }

    /**
     * Returned in place of a blocked tool's output. It is deliberately bland: a message saying
     * "blocked by security test" would itself steer the agent and change the run being measured.
     */
    private static final String BLOCKED_RESULT = "The tool is unavailable.";
}
