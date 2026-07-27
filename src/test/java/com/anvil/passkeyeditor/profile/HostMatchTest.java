package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Locale;

import org.junit.jupiter.api.Test;

/** HostMatch routing semantics: case-insensitivity, suffix boundaries, ANY/null, and cached REGEX. */
class HostMatchTest {

    @Test
    void exactIsCaseInsensitiveAndAnchored() {
        HostMatch m = HostMatch.exact("webauthn.io");
        assertTrue(m.matches("webauthn.io"));
        assertTrue(m.matches("WebAuthn.IO"));
        assertFalse(m.matches("evil-webauthn.io"));
        assertFalse(m.matches("webauthn.io.evil.com"));
    }

    @Test
    void suffixMatchesSubdomainsButNotImpostors() {
        HostMatch m = HostMatch.suffix(".hanko.io");
        assertTrue(m.matches("tenant-abc.hanko.io"));
        assertTrue(m.matches("TENANT.Hanko.IO"));
        assertFalse(m.matches("hanko.io.evil.com"), "suffix must be at the end");
        assertFalse(m.matches("evilhanko.io"), "boundary: the leading dot must match");
    }

    @Test
    void suffixIsLocaleIndependent() {
        // Turkish/Azeri lowercases ASCII 'I' to the dotless 'ı' (U+0131). A default-locale case fold would
        // break suffix matching for any host containing an uppercase 'I' (e.g. ".hanko.IO"); Locale.ROOT must not.
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("tr", "TR"));
            HostMatch m = HostMatch.suffix(".hanko.io");
            assertTrue(m.matches("TENANT.HANKO.IO"), "uppercase 'I' host must still match under the Turkish locale");
            assertTrue(m.matches("tenant.hanko.io"));
            assertFalse(m.matches("evil.com"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void anyMatchesEverythingIncludingNull() {
        HostMatch m = HostMatch.any();
        assertTrue(m.matches("anything.example.com"));
        assertTrue(m.matches(""));
        assertTrue(m.matches(null));
    }

    @Test
    void nonAnyNeverMatchesNull() {
        assertFalse(HostMatch.exact("webauthn.io").matches(null));
        assertFalse(HostMatch.suffix(".hanko.io").matches(null));
        assertFalse(HostMatch.regex("x").matches(null));
    }

    @Test
    void regexUsesFindAndSwallowsBadPatterns() {
        assertTrue(HostMatch.regex("\\.hanko\\.io$").matches("tenant.hanko.io"));
        assertTrue(HostMatch.regex("descope").matches("api.descope.com"), "find(), not full-match");
        assertFalse(HostMatch.regex("nope").matches("api.descope.com"));
        assertFalse(HostMatch.regex("[unclosed").matches("anything"), "malformed pattern → false, no throw");
    }
}
