package com.anvil.passkeyeditor.profile;

/**
 * The attestation format a registration key-plant emits - the selectable alternative that lets the
 * plant target an RP that requires attestation, not only one that accepts {@code fmt="none"}.
 *
 *   - {@link #NONE} - {@code fmt="none"} with an empty {@code attStmt}: no attestation signature at all.
 *       The historical default; accepted by the overwhelming majority of consumer RPs and the freeze-safe
 *       default path (byte-identical when unedited).
 *   - {@link #PACKED_SELF} - WebAuthn packed self-attestation (§8.2): an {@code attStmt} of exactly
 *       {@code { "alg", "sig" }} with no x5c chain, whose signature is made by the credential's own
 *       (planted) private key over {@code authenticatorData ‖ SHA-256(clientDataJSON)}. An RP that requires
 *       attestation but does not pin a trusted root chain accepts it.
 *
 * Orthogonal to the signing algorithm. Either mode works with whatever {@link SignerSpec}
 * algorithm is in play - the signer's COSE alg is carried into the packed {@code attStmt} verbatim, so the
 * mode is neither tied to a relying party nor to a specific algorithm.
 *
 * Pure data. Kept in the {@code profile} package (like {@link SignerSpec}) so it (de)serialises
 * trivially and carries no dependency on the {@code attacks}/{@code crypto} layers - avoiding a package
 * cycle. The attack code consumes it; it never depends on the attack code.
 */
public enum PlantAttestation {

    /** {@code fmt="none"}, empty {@code attStmt} - no attestation signature (the default, freeze-safe). */
    NONE("None"),

    /** WebAuthn packed self-attestation: {@code { alg, sig }}, no x5c, signed by the planted key. */
    PACKED_SELF("Packed self-attestation");

    private final String label;

    PlantAttestation(String label) {
        this.label = label;
    }

    /** A short, human-readable label for the UI selectors. */
    public String label() {
        return label;
    }

    /**
     * The mode named {@code name}, or {@link #NONE} when {@code name} is null / unknown - the tolerant parse
     * for persistence, so an absent or garbage persisted value degrades to the freeze-safe default rather
     * than breaking the profile load.
     */
    public static PlantAttestation fromName(String name) {
        if (name != null) {
            for (PlantAttestation mode : values()) {
                if (mode.name().equals(name)) {
                    return mode;
                }
            }
        }
        return NONE;
    }
}
