package io.github.harikrishna8121999.mcpredteam.core.report;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * A rendered report, ready to print or write.
 *
 * <p>Obtained from {@link Reports}. Kept separate from the scan itself so that producing an
 * artifact is an explicit act: nothing in this library writes a file unless a test asked it to.
 * An extension that dropped reports into {@code target/} on its own would be convenient and
 * would also mean a build could be publishing scan output nobody knows is being generated.
 */
@FunctionalInterface
public interface Report {

    /** The whole report as text. Deterministic for a given scan — see {@link Reports}. */
    String render();

    /**
     * Writes the report as UTF-8, creating parent directories, overwriting what is there.
     *
     * <p>Overwrites rather than appends: a report describes one scan, and appending would build
     * a file that reads as a single larger scan with results from runs that never happened
     * together.
     */
    default void writeTo(Path file) {
        Objects.requireNonNull(file, "file");
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(file, render(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write the MCP RedTeam report to " + file, e);
        }
    }
}
