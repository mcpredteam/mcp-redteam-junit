package io.github.harikrishna8121999.mcpredteam.core.behavior;

import io.github.harikrishna8121999.mcpredteam.core.AgentRun;
import io.github.harikrishna8121999.mcpredteam.core.Finding;

import java.util.List;

/**
 * A detection over what an agent actually did, as opposed to what its tools claimed.
 *
 * <p>The static counterpart is
 * {@link io.github.harikrishna8121999.mcpredteam.core.rule.MetadataRule}. The difference is
 * evidentiary rather than technical: a metadata rule reports that text <em>looked</em>
 * dangerous, while a behaviour rule reports that something <em>happened</em>. That makes these
 * findings materially stronger, and it is why they default to higher confidence.
 *
 * <p>Rules receive the whole run because the interesting signals are sequential — a call is
 * suspicious because of the tool result that preceded it.
 */
public interface BehaviorRule {

    /**
     * Stable family identifier, e.g. {@code MCPRT-HIJ}.
     *
     * <p>This is the family, not necessarily an emitted id: a rule may raise several numbered
     * findings beneath it, as {@code MCPRT-LEAK} does with {@code -001} and {@code -002}. The
     * static {@link io.github.harikrishna8121999.mcpredteam.core.rule.MetadataRule} side uses
     * the same convention, and suppression matches on the family boundary either way.
     */
    String id();

    /** Short human description of what this rule looks for. */
    String description();

    List<Finding> apply(AgentRun run);
}
