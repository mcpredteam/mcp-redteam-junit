package io.github.harikrishna8121999.mcpredteam.core.report;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Which release produced a report.
 *
 * <p>Recorded on every artifact so that a finding can be traced back to the ruleset that raised
 * it. Rules change: a report that says nothing about its own provenance cannot be told apart
 * from one produced by a version whose rules had a hole in them, and "we scanned it and it was
 * clean" is only worth something with a version attached.
 *
 * <p>The version is filtered into a resource at build time rather than written as a constant
 * here, because a constant is a second place to remember to bump at release and would sooner or
 * later disagree with the pom. If the resource is missing — running straight out of an IDE that
 * skipped {@code process-resources} — reports say {@code unknown} rather than guessing.
 */
final class BuildInfo {

    static final String NAME = "mcp-redteam";

    private static final String UNKNOWN = "unknown";
    private static final String RESOURCE = "mcp-redteam-build.properties";

    private static final String VERSION = load();

    private BuildInfo() {
    }

    static String version() {
        return VERSION;
    }

    private static String load() {
        try (InputStream in = BuildInfo.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return UNKNOWN;
            }
            Properties properties = new Properties();
            properties.load(in);
            String version = properties.getProperty("version", "");
            // An unfiltered resource still holds the literal '${project.version}', which would
            // otherwise be stamped onto reports as if it were a release.
            return version.isBlank() || version.startsWith("${") ? UNKNOWN : version;
        } catch (IOException e) {
            return UNKNOWN;
        }
    }
}
