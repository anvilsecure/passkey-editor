package com.anvil.passkeyeditor.util;

import java.util.Arrays;

/**
 * Self-echo re-bind detection for the request editor.
 *
 * Burp re-invokes an {@code ExtensionProvidedHttpRequestEditor}'s {@code setRequestResponse()} with the
 * request the editor itself just emitted from {@code getRequest()} - the documented
 * {@code getRequest → setRequestResponse} round-trip on a sub-tab switch / refresh / send (the editor
 * reports {@code isModified()==true}, so Burp pulls the edited bytes and hands them straight back). An
 * editor that blindly resets + re-baselines on every {@code setRequestResponse} would, on that self-echo,
 * wipe accumulated edit state and shift its diff baseline to the already-modified body. This predicate lets
 * the editor recognise the self-echo and preserve state instead.
 *
 * Burp-free + pure, so the decision is unit-testable without the Burp-coupled editor.
 */
public final class SelfEcho {

    private SelfEcho() {
    }

    /**
     * Whether {@code incomingBody} is the body this editor last emitted while holding edits - i.e. Burp is
     * re-handing the editor its own output rather than binding a new message.
     *
     * @param incomingBody    the body Burp is re-binding (null-safe)
     * @param lastEmittedBody the body the editor last returned from {@code getRequest()} (null if none)
     * @param modified        whether the editor currently holds edits ({@code isModified()})
     * @return {@code true} only when edits are held and the incoming body byte-equals the last emission
     */
    public static boolean isSelfEcho(byte[] incomingBody, byte[] lastEmittedBody, boolean modified) {
        return modified && incomingBody != null && lastEmittedBody != null
                && Arrays.equals(incomingBody, lastEmittedBody);
    }
}
