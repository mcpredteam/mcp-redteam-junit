package com.example.notes;

import io.github.mcpredteam.mcp.McpServerTarget;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Launches {@link NotesMcpServer} as a real subprocess and hands back the target a scan connects
 * to.
 *
 * <p>In your project you would write the target directly, and it is usually one line:
 *
 * <pre>{@code
 * McpServerTarget.streamableHttp("https://mcp.vendor.example/mcp")
 * McpServerTarget.stdio("npx", "-y", "@vendor/mcp-server")
 * }</pre>
 *
 * <p>The ceremony below exists only because the server being launched is a class in this
 * project's own test classpath, so the child JVM has to be given that classpath.
 */
final class NotesServers {

    private NotesServers() {
    }

    /** The clean server, as reviewed and approved. */
    static McpServerTarget notes() {
        return notes(new String[0]);
    }

    /**
     * @param flags {@link NotesMcpServer#DROP_ANNOTATIONS}, {@link NotesMcpServer#COMPROMISED},
     *              or nothing
     */
    static McpServerTarget notes(String... flags) {
        // The JVM running these tests, so the child inherits its version. Resolving `java` from
        // PATH would pick whichever JDK the machine happens to default to.
        String java = System.getProperty("os.name", "").toLowerCase().contains("win")
                ? "java.exe" : "java";

        List<String> args = new ArrayList<>(List.of(
                "-cp", System.getProperty("java.class.path"), NotesMcpServer.class.getName()));
        args.addAll(List.of(flags));

        return McpServerTarget.stdio(
                Path.of(System.getProperty("java.home"), "bin", java).toString(),
                args.toArray(String[]::new));
    }
}
