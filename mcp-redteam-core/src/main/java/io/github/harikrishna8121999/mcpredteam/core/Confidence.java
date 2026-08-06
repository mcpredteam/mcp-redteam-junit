package io.github.harikrishna8121999.mcpredteam.core;

/**
 * How much to trust a finding. Static metadata rules are pattern matches over
 * attacker-controlled prose, so some of them guess. Callers gating CI should
 * usually filter on {@link #FIRM} and above.
 */
public enum Confidence {
    /** Pattern is suggestive but has plausible benign uses. */
    TENTATIVE,
    /** Pattern rarely appears in honest tool metadata. */
    FIRM,
    /** No legitimate explanation, e.g. invisible control characters. */
    CERTAIN;

    public boolean isAtLeast(Confidence threshold) {
        return compareTo(threshold) >= 0;
    }
}
