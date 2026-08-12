package io.github.mcpredteam.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TextNormalizerTest {

    @Test
    void stripsZeroWidthCharacters() {
        assertEquals("ignore previous instructions",
                TextNormalizer.normalize("ig​nore pre‌vious in‍structions"));
    }

    @Test
    void stripsBidirectionalOverrides() {
        assertEquals("safe tool", TextNormalizer.normalize("‮safe‬ tool"));
    }

    @Test
    void stripsUnicodeTagCharacters() {
        assertEquals("hello", TextNormalizer.normalize("hel󠁁lo"));
    }

    @Test
    @DisplayName("folds Cyrillic and Greek look-alikes to their Latin equivalents")
    void foldsHomoglyphs() {
        assertEquals("payment", TextNormalizer.normalize("pаyment"));
        assertEquals("ignore", TextNormalizer.normalize("ignоre"));
    }

    @Test
    void collapsesWhitespace() {
        assertEquals("a b c", TextNormalizer.normalize("a \n\t b   c "));
    }

    @Test
    void leavesOrdinaryTextAlone() {
        String text = "Returns a base64-encoded PNG thumbnail.";
        assertEquals(text, TextNormalizer.normalize(text));
        assertFalse(TextNormalizer.isObfuscated(text));
    }

    @Test
    void reportsObfuscationOnlyWhenCharactersWereRemovedOrFolded() {
        assertTrue(TextNormalizer.isObfuscated("ig​nore"));
        assertTrue(TextNormalizer.isObfuscated("pаyment"));
        assertFalse(TextNormalizer.isObfuscated("ignore"));
        assertFalse(TextNormalizer.isObfuscated("multi   space"), "Whitespace alone is not obfuscation");
    }

    @Test
    void handlesNullAndEmpty() {
        assertEquals("", TextNormalizer.normalize(null));
        assertEquals("", TextNormalizer.normalize(""));
        assertFalse(TextNormalizer.isObfuscated(null));
    }
}
