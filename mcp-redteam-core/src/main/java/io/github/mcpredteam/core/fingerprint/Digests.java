package io.github.mcpredteam.core.fingerprint;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256, hex-encoded. The one place this library hashes anything. */
final class Digests {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Digests() {
    }

    static String sha256Hex(String text) {
        byte[] digest = newDigest().digest(text.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(HEX[(b >> 4) & 0xF]).append(HEX[b & 0xF]);
        }
        return sb.toString();
    }

    static boolean isDigest(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Every conforming JRE ships SHA-256; there is no fallback worth having.
            throw new IllegalStateException("SHA-256 is not available in this JVM", e);
        }
    }
}
