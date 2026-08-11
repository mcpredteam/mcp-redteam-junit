package io.github.harikrishna8121999.mcpredteam.core.fingerprint;

import io.github.harikrishna8121999.mcpredteam.core.Finding;
import io.github.harikrishna8121999.mcpredteam.core.ScanReport;
import io.github.harikrishna8121999.mcpredteam.core.Severity;

import java.util.List;

/**
 * Thrown when a baseline was asked for from a server that does not currently pass the static
 * gate — trust on first use, refused.
 *
 * <p>The failure this prevents is quiet and total. A fingerprint says "this is what the server
 * looked like when we trusted it"; take one from a server that is already poisoned and the
 * poison becomes the trusted state, so the rug-pull check reports drift only if the attacker
 * later removes the attack. The feature would then certify exactly what it was built to catch,
 * and would keep reporting clean while doing it.
 */
public class UntrustedBaselineException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient ScanReport report;
    private final Severity gate;

    UntrustedBaselineException(String serverName, Severity gate, ScanReport report) {
        super(message(serverName, gate, report));
        this.report = report;
        this.gate = gate;
    }

    /** The scan that refused the capture, so a caller can print or assert on it. */
    public ScanReport report() {
        return report;
    }

    public Severity gate() {
        return gate;
    }

    private static String message(String serverName, Severity gate, ScanReport report) {
        List<Finding> blocking = report.findingsAtOrAbove(gate);
        StringBuilder sb = new StringBuilder("Refusing to baseline '").append(serverName)
                .append("': it already fails the static scan at or above ").append(gate)
                .append(" (").append(blocking.size()).append(" finding(s)).")
                .append(" A baseline taken now would record the poisoned metadata as the trusted state,")
                .append(" and the rug-pull check would then fire only if the attack were removed.")
                .append(System.lineSeparator());
        for (Finding finding : blocking) {
            sb.append(System.lineSeparator()).append(finding.describe()).append(System.lineSeparator());
        }
        return sb.toString();
    }
}
