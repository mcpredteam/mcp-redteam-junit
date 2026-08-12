package io.github.mcpredteam.core;

/**
 * Ordered from least to most severe. Ordinal order is relied upon by
 * {@link #isAtLeast(Severity)} and by report thresholds, so new values must be
 * inserted in rank order.
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public boolean isAtLeast(Severity threshold) {
        return compareTo(threshold) >= 0;
    }
}
