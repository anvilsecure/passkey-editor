package com.anvil.passkeyeditor.profile;

/**
 * A profile's default signing algorithm, as a COSE algorithm id (e.g. {@code -7} ES256, {@code -8}
 * EdDSA). The per-target default that the manual algorithm chooser pre-selects when this profile matches,
 * and the algorithm the (deferred) AUTO mode plants / re-signs under - see the profile's signer config.
 *
 * Pure data. Kept as a bare COSE id so it (de)serialises trivially and carries no dependency on
 * the {@code crypto} layer (no cycle: {@code crypto} already knows nothing of {@code profile}). The id is
 * validated against the signer catalog ({@code SignerAlgorithm.forCoseId}) at the UI / edit boundary, not
 * here - an unknown id round-trips as data and is simply rejected (or falls back to ES256) when a signer is
 * actually constructed.
 */
public record SignerSpec(int coseAlg) {

    /** ES256 ({@code -7}) - the default for every profile absent an explicit choice (freeze-safe default path). */
    public static final SignerSpec ES256 = new SignerSpec(-7);

    /** EdDSA ({@code -8}, Ed25519) - the algorithm several captured RPs (webauthn.io / debugger / lubu) offer. */
    public static final SignerSpec EDDSA = new SignerSpec(-8);
}
