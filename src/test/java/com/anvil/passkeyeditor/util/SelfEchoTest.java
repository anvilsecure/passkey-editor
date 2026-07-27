package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Regression for the live "cumulative edit summary collapses after a second action" bug.
 *
 * Burp re-invokes {@code setRequestResponse()} with the request the editor itself just emitted from
 * {@code getRequest()} (a self-echo refresh, on a sub-tab switch / send). Without recognising it, the
 * request editor reset its accumulated edit state and re-baselined the model to the already-forged
 * body - so a second action diffed against the forged baseline and the cumulative summary collapsed to
 * bare "re-signed". {@link SelfEcho#isSelfEcho} is the load-bearing decision that gates the editor's
 * state-preserving early return; it's unit-tested here in isolation (the full editor is Burp-coupled, so
 * the end-to-end state preservation is validated live, per the project's headless/live split).
 */
class SelfEchoTest {

    private static byte[] body(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void recognisesBurpReHandingOurOwnEmittedBody() {
        byte[] emitted = body("{\"response\":{\"signature\":\"FORGED\"}}");
        assertTrue(SelfEcho.isSelfEcho(emitted.clone(), emitted, true),
                "an armed editor re-bound with its own last emission is a self-echo (preserve state)");
    }

    @Test
    void aGenuinelyDifferentBodyIsNotASelfEcho() {
        byte[] emitted = body("{\"response\":{\"signature\":\"FORGED\"}}");
        byte[] fresh = body("{\"response\":{\"signature\":\"FRESH-MESSAGE\"}}");
        assertFalse(SelfEcho.isSelfEcho(fresh, emitted, true),
                "a different incoming body is a new message - must fully reset (no state leak)");
    }

    @Test
    void notModifiedIsNeverASelfEcho() {
        byte[] b = body("{\"a\":\"b\"}");
        assertFalse(SelfEcho.isSelfEcho(b.clone(), b, false),
                "with no edits armed (isModified()==false) a re-bind must reset, even on byte-equal input");
    }

    @Test
    void nullsAreNeverASelfEcho() {
        byte[] b = body("{\"a\":\"b\"}");
        assertFalse(SelfEcho.isSelfEcho(null, b, true), "null incoming is not a self-echo");
        assertFalse(SelfEcho.isSelfEcho(b, null, true), "no prior emission is not a self-echo");
    }
}
