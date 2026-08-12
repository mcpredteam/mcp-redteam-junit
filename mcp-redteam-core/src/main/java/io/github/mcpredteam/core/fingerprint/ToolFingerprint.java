package io.github.mcpredteam.core.fingerprint;

import io.github.mcpredteam.core.ToolDefinition;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * What one tool looked like, recorded so a later scan can tell whether it still does.
 *
 * <p>Digests, not text: a baseline is a file people commit and review, and it should not become
 * a second copy of a server's metadata that leaks into every diff. Digests are enough to answer
 * the question the rule asks — <em>did this change?</em> — and the answer to <em>what does it say
 * now?</em> is on the live server, which is where a scan reads it from anyway.
 *
 * <p>Per-location digests rather than one digest per tool, because "something changed" is not an
 * actionable finding. Knowing that {@code inputSchema/properties/apiKey/description} is the part
 * that moved is what lets {@link RugPullRule} re-run the static rules over the changed text alone
 * instead of re-reporting the whole tool.
 *
 * @param fieldDigests location to digest, ordered by location
 */
public record ToolFingerprint(String serverName, String toolName, Map<String, String> fieldDigests) {

    public ToolFingerprint {
        Objects.requireNonNull(toolName, "toolName");
        serverName = serverName == null ? "" : serverName;
        // A sorted view, not Map.copyOf: digest() hashes this map in iteration order, and
        // Map.copyOf's order is unspecified, which would make a tool's digest depend on the
        // hash codes of its property names.
        fieldDigests = Collections.unmodifiableMap(
                new TreeMap<>(Objects.requireNonNull(fieldDigests, "fieldDigests")));
    }

    public static ToolFingerprint of(ToolDefinition tool) {
        Map<String, String> digests = new TreeMap<>();
        CanonicalForm.of(tool).forEach((location, value) ->
                digests.put(location, Digests.sha256Hex(frame(location) + value)));
        return new ToolFingerprint(tool.serverName(), tool.name(), digests);
    }

    /**
     * One digest over the whole tool, derived from the per-location ones.
     *
     * <p>Derived rather than stored, so a baseline read back from a file cannot disagree with
     * itself. A recorded whole-tool digest would be a second, unverifiable claim about the same
     * metadata, and the case where the two would part company — a hand-edited baseline — is
     * precisely the one worth catching.
     */
    public String digest() {
        StringBuilder sb = new StringBuilder();
        fieldDigests.forEach((location, digest) -> sb.append(frame(location)).append(digest).append('\n'));
        return Digests.sha256Hex(sb.toString());
    }

    public String qualifiedName() {
        return serverName.isEmpty() ? toolName : serverName + "/" + toolName;
    }

    public boolean matches(ToolFingerprint other) {
        return other != null && fieldDigests.equals(other.fieldDigests());
    }

    /**
     * Locations where this and {@code other} disagree, including those present in only one of
     * them — an added parameter and a removed one are both drift.
     */
    public List<String> changedLocations(ToolFingerprint other) {
        Set<String> locations = new LinkedHashSet<>(fieldDigests.keySet());
        locations.addAll(other.fieldDigests().keySet());

        List<String> changed = new ArrayList<>();
        for (String location : locations) {
            if (!Objects.equals(fieldDigests.get(location), other.fieldDigests().get(location))) {
                changed.add(location);
            }
        }
        changed.sort(String::compareTo);
        return List.copyOf(changed);
    }

    /**
     * Length-prefixes a location so it cannot bleed into the value that follows.
     *
     * <p>Any separator character can appear in a location — property names are chosen by the
     * server — so a plain delimiter would let a tool with a property named {@code a b} hash
     * identically to a differently-shaped one. Prefixing the length removes the ambiguity
     * without needing some character to be unavailable.
     */
    private static String frame(String location) {
        return location.length() + ":" + location;
    }
}
