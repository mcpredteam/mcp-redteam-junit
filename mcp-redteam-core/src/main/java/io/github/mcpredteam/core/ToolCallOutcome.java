package io.github.mcpredteam.core;

/** How a single observed tool call ended. */
public enum ToolCallOutcome {

    /** The tool ran and returned a result. */
    SUCCEEDED,

    /** The tool was invoked and threw. The call still happened, so it is still evidence. */
    FAILED,

    /**
     * The harness intercepted the call and refused to run it. The agent still <em>chose</em>
     * to call the tool, which is the fact a hijack assertion cares about — a blocked call is
     * not a passing test.
     */
    BLOCKED
}
