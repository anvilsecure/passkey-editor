package com.anvil.passkeyeditor.util;

import com.anvil.passkeyeditor.model.AuthenticatorData;

/**
 * Surgical, byte-level edits of an assertion's authenticator data - the {@code authData} counterpart of
 * {@link JsonValueEditor} (which edits JSON string values like {@code clientDataJSON}/{@code signature}).
 *
 * An assertion authData is a flat fixed-layout structure
 * {@code rpIdHash(32) | flags(1) | signCount(4 BE)} (37 bytes, AT=0), not CBOR - so the
 * attack knobs the editable view exposes (flag checkboxes, signCount, RP-ID) are exact in-place byte
 * replacements, never a re-encode. Each method returns a fresh array and leaves every byte outside the
 * edited field untouched, so the result can be fed straight to {@link com.anvil.passkeyeditor.attacks.AssertionForger}
 * to re-sign over the edited bytes.
 *
 * Pure functions, no Burp types - fully unit-testable.
 */
public final class AuthDataEditor {

    private static final int FLAGS_OFFSET = AuthenticatorData.FLAGS_OFFSET;
    private static final int SIGN_COUNT_OFFSET = AuthenticatorData.SIGN_COUNT_OFFSET;

    private AuthDataEditor() {
    }

    /**
     * Replace the single flags byte (offset 32). Use the {@code AuthenticatorData.FLAG_*} masks to
     * compose the value (e.g. {@code FLAG_UP | FLAG_UV} = 0x05, or clear UV for a UV=0 forgery).
     *
     * @param authData the inner authData bytes (≥ 37)
     * @param flags    the new flags byte (low 8 bits used)
     * @return a copy with byte[32] replaced
     */
    public static byte[] withFlags(byte[] authData, int flags) {
        byte[] out = require(authData);
        out[FLAGS_OFFSET] = (byte) (flags & 0xFF);
        return out;
    }

    /**
     * Replace the 4-byte big-endian signCount (offsets 33-36) - e.g. to defeat a clone-detection counter
     * or to push a forged assertion's counter forward.
     *
     * @param authData  the inner authData bytes (≥ 37)
     * @param signCount the new unsigned 32-bit counter
     * @return a copy with the signCount field replaced
     */
    public static byte[] withSignCount(byte[] authData, long signCount) {
        byte[] out = require(authData);
        out[SIGN_COUNT_OFFSET] = (byte) ((signCount >>> 24) & 0xFF);
        out[SIGN_COUNT_OFFSET + 1] = (byte) ((signCount >>> 16) & 0xFF);
        out[SIGN_COUNT_OFFSET + 2] = (byte) ((signCount >>> 8) & 0xFF);
        out[SIGN_COUNT_OFFSET + 3] = (byte) (signCount & 0xFF);
        return out;
    }

    /**
     * Replace the 32-byte rpIdHash (offsets 0-31) - the RP-ID mutation attack ({@code SHA-256(new_rpId)}).
     *
     * @param authData     the inner authData bytes (≥ 37)
     * @param rpIdHash the new 32-byte rpIdHash
     * @return a copy with the rpIdHash field replaced
     */
    public static byte[] withRpIdHash(byte[] authData, byte[] rpIdHash) {
        if (rpIdHash == null || rpIdHash.length != AuthenticatorData.RP_ID_HASH_LENGTH) {
            throw new IllegalArgumentException("rpIdHash must be 32 bytes");
        }
        byte[] out = require(authData);
        System.arraycopy(rpIdHash, 0, out, 0, AuthenticatorData.RP_ID_HASH_LENGTH);
        return out;
    }

    /** Defensive copy + length guard: the fixed 37-byte header must be present to edit any field. */
    private static byte[] require(byte[] authData) {
        if (authData == null || authData.length < AuthenticatorData.ASSERTION_LENGTH) {
            throw new IllegalArgumentException(
                    "authData too short to edit (need ≥ " + AuthenticatorData.ASSERTION_LENGTH + " bytes)");
        }
        return authData.clone();
    }
}
