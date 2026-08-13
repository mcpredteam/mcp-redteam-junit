package com.example.notes;

import io.github.mcpredteam.core.fingerprint.Baseline;
import io.github.mcpredteam.mcp.McpServerConnection;

import java.nio.file.Path;

/**
 * Captures the baseline that {@link ServerDriftTest} reads. <strong>Run by hand, never from a
 * test.</strong>
 *
 * <pre>{@code
 * mvn test-compile exec:exec
 * }</pre>
 *
 * <p>Then read the diff and commit it, the same way you would review a dependency bump.
 *
 * <p>There is deliberately no test that regenerates this file, and the library deliberately ships
 * no capture-if-missing helper. A check that re-baselines itself whenever it has nothing to
 * compare against can never fail — it would create the baseline on the first CI run, from
 * whatever is being served that morning.
 *
 * <p>{@link Baseline#capture} also refuses a server that already fails the static scan, throwing
 * {@code UntrustedBaselineException}. Baselining is trust on first use, so a baseline taken from
 * a poisoned server records the poison as the approved state, after which drift detection fires
 * only if the attacker cleans up.
 */
public final class CaptureBaseline {

    private CaptureBaseline() {
    }

    static final Path FILE = Path.of("src/test/resources/notes-baseline.txt");

    public static void main(String[] args) {
        try (McpServerConnection notes = McpServerConnection.connect("notes", NotesServers.notes())) {

            Baseline.write(notes.captureBaseline(), FILE);

            System.out.println("wrote " + FILE.toAbsolutePath());
            System.out.println("Review the diff before committing it.");
        }
    }
}
