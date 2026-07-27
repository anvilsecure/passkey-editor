package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/** Gate for {@link UrlMatch} - the per-phase verify-endpoint scope. */
class UrlMatchTest {

    @Test
    void anyMatchesEverythingAndIsInactive() {
        assertTrue(UrlMatch.any().matches("https://x/verify", "POST"));
        assertTrue(UrlMatch.any().matches(null, null));
        assertFalse(UrlMatch.any().isActive(), "ANY does not scope");
    }

    @Test
    void containsAndExactAndRegex() {
        assertTrue(UrlMatch.contains("/verify-authentication").matches("https://rp.io/api/verify-authentication", "POST"));
        assertFalse(UrlMatch.contains("/verify-registration").matches("https://rp.io/api/verify-authentication", "POST"));
        assertTrue(UrlMatch.exact("https://rp.io/v").matches("https://rp.io/v", "POST"));
        assertFalse(UrlMatch.exact("https://rp.io/v").matches("https://rp.io/v?x=1", "POST"));
        assertTrue(UrlMatch.regex("/verify-(reg|auth)").matches("https://rp.io/verify-auth", null));
    }

    @Test
    void methodGate() {
        UrlMatch m = new UrlMatch(UrlMatch.Kind.CONTAINS, "/verify", "POST");
        assertTrue(m.matches("https://rp.io/verify", "POST"));
        assertTrue(m.matches("https://rp.io/verify", "post"), "method is case-insensitive");
        assertFalse(m.matches("https://rp.io/verify", "GET"), "wrong method rejects");
        assertTrue(m.matches("https://rp.io/verify", null), "unknown request method is not rejected");
    }

    @Test
    void badRegexFailsClosed() {
        assertFalse(UrlMatch.regex("([unterminated").matches("https://rp.io/x", "POST"), "bad pattern → no match, no throw");
    }

    /**
     * AUDIT-3 M1 regression: a catastrophic-backtracking verify-URL regex must ABORT (via the shared
     * SafeRegex step budget) and return false fast - isEnabledFor runs this on the UI thread per request,
     * so an operator's pathological pattern must never hang the tab.
     */
    @Test
    void catastrophicUrlRegexAbortsQuicklyNoHang() {
        String url = "https://rp.io/" + "a".repeat(60); // no trailing 'b' → forces full backtracking
        UrlMatch m = UrlMatch.regex("(.*a){25}b");
        assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                assertFalse(m.matches(url, "POST"), "catastrophic URL regex trips the step budget → false, no hang"));
    }

    /** AUDIT M5: a method without a URL pattern is meaningless (matches() short-circuits) → normalised away. */
    @Test
    void methodWithoutPatternIsNormalisedAway() {
        assertNull(new UrlMatch(UrlMatch.Kind.ANY, "", "POST").method(), "ANY + method → method dropped");
        assertNull(new UrlMatch(UrlMatch.Kind.CONTAINS, "", "POST").method(), "blank pattern + method → dropped");
        assertEquals("POST", new UrlMatch(UrlMatch.Kind.CONTAINS, "/v", "POST").method(), "method WITH a pattern is kept");
    }
}
