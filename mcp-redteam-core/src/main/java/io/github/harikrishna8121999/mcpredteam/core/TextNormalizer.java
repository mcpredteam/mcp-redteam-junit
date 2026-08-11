package io.github.harikrishna8121999.mcpredteam.core;

import java.text.Normalizer;
import java.util.Map;

/**
 * Canonicalizes attacker-controlled text before pattern matching.
 *
 * <p>Without this, trivial evasions defeat the detection rules: a zero-width space spliced
 * into the middle of {@code "ignore previous instructions"} breaks a literal match, and
 * Cyrillic U+0430 renders identically to Latin {@code a} while comparing unequal. Rules match
 * against the normalized form so a payload has to survive canonicalization to stay hidden,
 * while {@link io.github.harikrishna8121999.mcpredteam.core.rule.HiddenUnicodeRule}
 * separately reports the evasion characters themselves.
 */
public final class TextNormalizer {

    /** Characters with no visible rendering that are used to break up payload text. */
    private static final String INVISIBLE_CHARS =
            "[\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF]";

    /** Unicode Tags block, rendered by nothing but read by tokenizers. */
    private static final String TAG_CHARS = "[\\x{E0000}-\\x{E007F}]";

    // Written as escapes rather than literal glyphs on purpose: the whole point of these
    // characters is that they are indistinguishable from ASCII on screen, so literals here
    // would be unreviewable in a diff.
    private static final Map<Character, Character> CONFUSABLES = Map.ofEntries(
            Map.entry('а', 'a'), // CYRILLIC SMALL LETTER A
            Map.entry('е', 'e'), // CYRILLIC SMALL LETTER IE
            Map.entry('о', 'o'), // CYRILLIC SMALL LETTER O
            Map.entry('р', 'p'), // CYRILLIC SMALL LETTER ER
            Map.entry('с', 'c'), // CYRILLIC SMALL LETTER ES
            Map.entry('х', 'x'), // CYRILLIC SMALL LETTER HA
            Map.entry('у', 'y'), // CYRILLIC SMALL LETTER U
            Map.entry('і', 'i'), // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
            Map.entry('ѕ', 's'), // CYRILLIC SMALL LETTER DZE
            Map.entry('ӏ', 'l'), // CYRILLIC SMALL LETTER PALOCHKA
            Map.entry('ԁ', 'd'), // CYRILLIC SMALL LETTER KOMI DE
            Map.entry('һ', 'h'), // CYRILLIC SMALL LETTER SHHA
            Map.entry('ο', 'o'), // GREEK SMALL LETTER OMICRON
            Map.entry('α', 'a'), // GREEK SMALL LETTER ALPHA
            Map.entry('ε', 'e'), // GREEK SMALL LETTER EPSILON
            Map.entry('ո', 'n'), // ARMENIAN SMALL LETTER VO
            Map.entry('ɡ', 'g')  // LATIN SMALL LETTER SCRIPT G
    );

    /** The two sets above, as one matcher, for {@link #isInvisible}. */
    private static final java.util.regex.Pattern INVISIBLE_OR_TAG =
            java.util.regex.Pattern.compile(INVISIBLE_CHARS + "|" + TAG_CHARS);

    private TextNormalizer() {
    }

    /**
     * Whether this code point is one of the invisible characters {@link #normalize} strips.
     *
     * <p>Exposed for the report writers, which escape these rather than removing them: a report
     * is evidence, so it must keep what was there while still making it legible to a reviewer.
     * Derived from the same patterns the stripping uses, deliberately, because a second list of
     * ranges maintained alongside the first would eventually disagree with it — and the failure
     * would be silent, in the direction of a payload rendering as nothing.
     */
    public static boolean isInvisible(int codePoint) {
        // Every character in both sets is non-ASCII, so ordinary text takes the cheap path and
        // never allocates. This runs per character over whole reports.
        return codePoint >= 0x80 && INVISIBLE_OR_TAG.matcher(Character.toString(codePoint)).matches();
    }

    /** Applies compatibility normalization, strips invisibles, folds confusables, collapses whitespace. */
    public static String normalize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        String text = Normalizer.normalize(input, Normalizer.Form.NFKC);
        text = text.replaceAll(TAG_CHARS, "");
        text = text.replaceAll(INVISIBLE_CHARS, "");
        text = foldConfusables(text);
        return text.replaceAll("\\s+", " ").trim();
    }

    private static String foldConfusables(String input) {
        StringBuilder sb = new StringBuilder(input.length());
        input.codePoints().forEach(cp -> {
            if (cp <= Character.MAX_VALUE) {
                Character folded = CONFUSABLES.get((char) cp);
                if (folded != null) {
                    sb.append(folded.charValue());
                    return;
                }
            }
            sb.appendCodePoint(cp);
        });
        return sb.toString();
    }

    /** True when normalization changed the text, i.e. the original carried evasion characters. */
    public static boolean isObfuscated(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return !input.replaceAll("\\s+", " ").trim().equals(normalize(input));
    }

    public static String invisibleCharPattern() {
        return INVISIBLE_CHARS;
    }

    public static String tagCharPattern() {
        return TAG_CHARS;
    }
}
