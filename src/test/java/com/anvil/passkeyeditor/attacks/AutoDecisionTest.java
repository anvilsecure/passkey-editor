package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.anvil.passkeyeditor.attacks.AutoDecision.AutoContext;
import com.anvil.passkeyeditor.attacks.AutoDecision.Decision;
import com.anvil.passkeyeditor.model.CeremonyType;

import org.junit.jupiter.api.Test;

/**
 * The AUTO safety story, proven without Burp: {@link AutoDecision#decide} must fail closed to
 * {@link Decision#PASS_THROUGH} at every gate, and act only when ALL conditions for a specific action hold.
 */
class AutoDecisionTest {

    private static Decision decide(boolean inScope, boolean fromExt, boolean marked,
                                   CeremonyType type, boolean matched, boolean keyHeld) {
        return AutoDecision.decide(new AutoContext(inScope, fromExt, marked, type, matched, keyHeld));
    }

    @Test
    void outOfScopeStillActsWhenArmed() {
        // Option A: arming a profile (autoPlant/autoResign + host + verify-URL) IS the opt-in, so Burp Target
        // scope no longer gates - an armed, matched ceremony acts even out of scope (always logged + coloured).
        assertEquals(Decision.PLANT, decide(false, false, false, CeremonyType.CREATE, true, false),
                "out-of-scope no longer blocks an armed match - scope is informational now");
    }

    @Test
    void ourOwnReissuedTrafficPassesThrough() {
        assertEquals(Decision.PASS_THROUGH, decide(true, true, false, CeremonyType.GET, true, true),
                "requests from EXTENSIONS (our own re-issue) are never re-processed");
    }

    @Test
    void alreadyMarkedPassesThrough() {
        assertEquals(Decision.PASS_THROUGH, decide(true, false, true, CeremonyType.GET, true, true),
                "a request already carrying the AUTO sentinel is not re-signed again (double-sign guard)");
    }

    @Test
    void nonCeremonyPassesThrough() {
        assertEquals(Decision.PASS_THROUGH, decide(true, false, false, null, true, true),
                "a non-WebAuthn request is never touched");
    }

    @Test
    void noArmedProfileMatchedPassesThrough() {
        assertEquals(Decision.PASS_THROUGH, decide(true, false, false, CeremonyType.GET, false, true),
                "with no armed profile matched (e.g. the all-off Default), AUTO never acts - the freeze guard");
    }

    @Test
    void createWithArmedProfilePlants() {
        // PLANT creates its own key, so keyHeld is irrelevant (false here).
        assertEquals(Decision.PLANT, decide(true, false, false, CeremonyType.CREATE, true, false),
                "a registration matched by an auto-plant profile is planted");
    }

    @Test
    void getWithArmedProfileAndHeldKeyResigns() {
        assertEquals(Decision.RESIGN, decide(true, false, false, CeremonyType.GET, true, true),
                "an authentication matched by an auto-resign profile, with a held key, is re-signed");
    }

    @Test
    void getWithArmedProfileButNoHeldKeyPassesThrough() {
        assertEquals(Decision.PASS_THROUGH, decide(true, false, false, CeremonyType.GET, true, false),
                "the capability boundary: auto re-sign only acts on a key we already hold");
    }
}
