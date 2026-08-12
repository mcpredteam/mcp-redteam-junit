package io.github.mcpredteam.core.fingerprint;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Every tool a server published at the moment it was trusted.
 *
 * <p>Built by {@link Baseline#capture}, which will not record tools that fail the static gate,
 * and read back by {@link Baseline#read}. Constructing one directly assembles data that has
 * already been fingerprinted; it is not a way to skip the gate, because there is nothing here
 * to gate — the check belongs to capture, where the live metadata still exists.
 *
 * @param capturedAt when the baseline was taken; reported in findings so a drift finding can say
 *                   what "since" means
 */
public record ServerFingerprint(String serverName, Instant capturedAt, List<ToolFingerprint> tools) {

    public ServerFingerprint {
        Objects.requireNonNull(serverName, "serverName");
        Objects.requireNonNull(capturedAt, "capturedAt");
        tools = List.copyOf(Objects.requireNonNull(tools, "tools"));

        Set<String> names = new LinkedHashSet<>();
        for (ToolFingerprint tool : tools) {
            if (!names.add(tool.toolName())) {
                // A baseline is looked up by tool name, so two tools sharing one is not a
                // shape it can represent. Silently keeping the first would mean the second
                // tool is never compared against anything, which is a hole an attacker can
                // ask for by simply publishing the name twice.
                throw new IllegalArgumentException("Server '" + serverName + "' published more than one tool named '"
                        + tool.toolName() + "'. A baseline is keyed by tool name and cannot record duplicates;"
                        + " a server that registers a name twice is already misbehaving.");
            }
        }
    }

    public Optional<ToolFingerprint> tool(String toolName) {
        return tools.stream().filter(t -> t.toolName().equals(toolName)).findFirst();
    }

    public Set<String> toolNames() {
        return tools.stream().map(ToolFingerprint::toolName)
                .collect(LinkedHashSet::new, Set::add, Set::addAll);
    }

    public int size() {
        return tools.size();
    }
}
