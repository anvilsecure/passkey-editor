package com.anvil.passkeyeditor.profile;

/**
 * The ceremony phase a {@link PhaseSpec} describes. The {@code Detector} decides the phase structurally
 * (attestationObject ⇒ registration, signature ⇒ authentication); the profile then says where that
 * phase's fields live for the matched RP.
 *
 * Options-response phases ({@code REG_OPTIONS}/{@code AUTH_OPTIONS}, for the UV-downgrade response
 * editor) arrive with - kept out of the enum until wired.
 */
public enum Phase {
    /** A registration verify request (carries clientDataJSON + attestationObject). */
    REG_VERIFY("Registration"),
    /** An authentication verify request (carries clientDataJSON + authenticatorData + signature). */
    AUTH_VERIFY("Authentication");

    private final String displayName;

    Phase(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Human-facing label for the UI (titled borders, etc.). NOT the persisted token - JSON uses
     * {@link #name()} (see {@code ProfileJson}), so this label can change freely without touching
     * stored profiles or seed data.
     */
    public String displayName() {
        return displayName;
    }
}
