package com.anvil.passkeyeditor.http;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The AUTO double-apply sentinel keys on the DELIMITED auto-note ({@code "[AUTO] <phase>"}), not a bare
 * {@code "[AUTO]"}. Regression guard: a profile literally NAMED {@code [AUTO]} makes the receive-stage
 * colour handler write {@code "<phase> - [AUTO]"}; a bare-token sentinel would then falsely trip and silently
 * block the first legitimate rewrite for that host. This pins the delimited check.
 */
class PasskeyAutoSentinelTest {

    @Test
    void tripsOnOurOwnAutoNote() {
        // annotate() writes it at the start of the note...
        assertTrue(PasskeyAutoHandler.noteHasSentinel("[AUTO] Authentication - webauthn.io"));
        assertTrue(PasskeyAutoHandler.noteHasSentinel("[AUTO] Registration - webauthn.io"));
        // ...or after an existing note with a TWO-space separator.
        assertTrue(PasskeyAutoHandler.noteHasSentinel("triage me  [AUTO] Authentication - rp"));
    }

    @Test
    void doesNotTripOnProfileNamesThatEmbedTheToken() {
        // The colour handler renders "<phase> - <name>", so any "[AUTO]" inside a NAME is preceded by "- " (a
        // single space): it neither starts the note nor is two-space-prefixed, so it must NOT trip the guard.
        assertFalse(PasskeyAutoHandler.noteHasSentinel("Authentication - [AUTO]"));
        assertFalse(PasskeyAutoHandler.noteHasSentinel("Registration - [AUTO]-test"));
        // Regression: a name embedding the full delimited sentinel used to falsely trip the guard.
        assertFalse(PasskeyAutoHandler.noteHasSentinel("Registration - [AUTO] Authentication srv"));
        // Ordinary tracked marks and non-notes.
        assertFalse(PasskeyAutoHandler.noteHasSentinel("Authentication - webauthn.io"));
        assertFalse(PasskeyAutoHandler.noteHasSentinel("Options - webauthn.io"));
        assertFalse(PasskeyAutoHandler.noteHasSentinel(""));
        assertFalse(PasskeyAutoHandler.noteHasSentinel(null));
    }
}
