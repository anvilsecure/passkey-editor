package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.model.CeremonyType;

/**
 * The pure, Burp-free decision predicate for AUTO mode - "given the facts about an outgoing request, should
 * the handler PLANT, RE-SIGN, or PASS THROUGH untouched?". Extracted from {@link
 * com.anvil.passkeyeditor.http.PasskeyAutoHandler} so the entire safety story (the gating that decides whether
 * we ever rewrite live traffic) is unit-testable without a live Burp.
 *
 * Fail-closed. Every gate defaults to {@link Decision#PASS_THROUGH}; we act only when ALL conditions
 * for a specific action hold. The order is cheapest-first so the common (non-ceremony) request exits fast.
 */
public final class AutoDecision {

    /** What the handler should do with the request. */
    public enum Decision {
        /** Substitute our credential public key on a registration (REG_VERIFY). */
        PLANT,
        /** Re-sign the assertion with the held key (AUTH_VERIFY). */
        RESIGN,
        /** Leave the request byte-identical. */
        PASS_THROUGH
    }

    /**
     * The facts the handler resolves before deciding.
     *
     * @param inScope            whether the request is in Burp's target scope - informational only
     *                           (Option A: arming a profile IS the opt-in, so scope no longer gates; kept for
     *                           logging / a future per-tool scope policy)
     * @param fromExtensions     the request originates from our own tool (re-entrancy guard - never re-process)
     * @param alreadyMarked      a prior AUTO action already annotated this request (double-sign guard)
     * @param type               the detected ceremony type, or {@code null} if not a WebAuthn ceremony
     * @param autoProfileMatched a profile armed for this phase matched the host + URL scope
     *                           ({@code ProfileRegistry.matchAuto(...) != null}) - already encodes the
     *                           per-profile auto flag + host + URL gate
     * @param keyHeld            (AUTH only) a planted key is held for this credential (the capability boundary)
     */
    public record AutoContext(boolean inScope, boolean fromExtensions, boolean alreadyMarked,
                              CeremonyType type, boolean autoProfileMatched, boolean keyHeld) {
    }

    private AutoDecision() {
    }

    public static Decision decide(AutoContext c) {
        // Re-entrancy guards only - our own emission / an already-auto-signed resend. Scope is NOT a gate
        // (Option A): the per-profile arm + host + verify-URL match is the explicit opt-in.
        if (c.fromExtensions() || c.alreadyMarked()) {
            return Decision.PASS_THROUGH;
        }
        if (c.type() == null || !c.autoProfileMatched()) {
            return Decision.PASS_THROUGH; // not a ceremony, or no armed profile matched this host/phase/URL
        }
        if (c.type() == CeremonyType.CREATE) {
            return Decision.PLANT; // matchAuto(REG_VERIFY) already required autoPlant; plant creates its own key
        }
        // AUTH_VERIFY: capability boundary - auto re-sign only works on a key we already hold.
        return c.keyHeld() ? Decision.RESIGN : Decision.PASS_THROUGH;
    }
}
