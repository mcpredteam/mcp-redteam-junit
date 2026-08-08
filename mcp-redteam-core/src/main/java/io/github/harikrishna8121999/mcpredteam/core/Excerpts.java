package io.github.harikrishna8121999.mcpredteam.core;

/**
 * Shared rendering of attacker-controlled text for failure messages.
 *
 * <p>Every excerpt shown to a developer goes through here. Whitespace is collapsed because a
 * hostile description can contain newlines that would otherwise reformat a report, and length
 * is capped because it can be arbitrarily long.
 */
final class Excerpts {

    private static final int MAX_LENGTH = 160;

    private Excerpts() {
    }

    static String truncate(String value) {
        if (value == null) {
            return "";
        }
        String collapsed = value.replaceAll("\\s+", " ").trim();
        return collapsed.length() <= MAX_LENGTH
                ? collapsed
                : collapsed.substring(0, MAX_LENGTH - 3) + "...";
    }
}
