package com.anvil.passkeyeditor.model;

/**
 * Decoded authenticator data (WebAuthn-2 §6.1), tool-internal and independent of webauthn4j.
 *
 * Wire layout (verified):
 *   rpIdHash(32) | flags(1) | signCount(4 BE) | [ aaguid(16) | credIdLen(2 BE) | credId | COSE pubkey ]
 * The attested-credential-data block (aaguid … COSE pubkey) is present only when the AT flag is set
 * (registration). An assertion's authData is exactly 37 bytes (AT=0, no extensions); when re-signing
 * an assertion the COSE key must not be appended.
 *
 * Flag bits: UP=0x01, UV=0x04, BE=0x08, BS=0x10, AT=0x40, ED=0x80 (bit1/bit5 RFU).
 *
 * {@link #raw()} retains the verbatim decoded bytes so an unedited structure (including a foreign
 * producer's COSE map order / int width) round-trips byte-identically; the parsed fields drive the
 * editable display and are re-encoded only for fields that were actually changed.
 */
public final class AuthenticatorData {

    public static final int RP_ID_HASH_LENGTH = 32;
    public static final int AAGUID_LENGTH = 16;
    /** Length of an assertion authData with AT=0 and no extensions. */
    public static final int ASSERTION_LENGTH = 37;

    /** Byte offset of the 1-byte flags field (immediately after the 32-byte rpIdHash). */
    public static final int FLAGS_OFFSET = RP_ID_HASH_LENGTH;
    /** Byte offset of the 4-byte big-endian signCount field. */
    public static final int SIGN_COUNT_OFFSET = RP_ID_HASH_LENGTH + 1;

    // Flag bit masks.
    public static final int FLAG_UP = 0x01; // User Present
    public static final int FLAG_UV = 0x04; // User Verified
    public static final int FLAG_BE = 0x08; // Backup Eligible
    public static final int FLAG_BS = 0x10; // Backup State
    public static final int FLAG_AT = 0x40; // Attested credential data included
    public static final int FLAG_ED = 0x80; // Extension data included

    /** Verbatim authData bytes as decoded from the wire; lossless shadow for round-tripping. */
    private byte[] raw;

    private byte[] rpIdHash;   // 32 bytes
    private int flags;         // single byte, 0..255
    private long signCount;    // unsigned 32-bit, big-endian on the wire

    // Attested credential data - present only when FLAG_AT is set.
    private byte[] aaguid;             // 16 bytes
    private byte[] credentialId;       // credIdLen bytes
    private CoseKey credentialPublicKey;

    /**
     * True when the structural CBOR parse failed and only the fixed 37-byte header was recovered by length
     * (see {@code Webauthn4jCborCodec.decodeAuthDataHeaderBestEffort}). The decode-for-display tab still
     * renders such a value (degrade-don't-vanish), but a consumer that needs to know the bytes are a REAL
     * authData - the profile {@code Check} validator - must treat a header-recovered value as suspect: ANY
     * blob ≥ 37 bytes yields a non-null {@link #rpIdHash()} this way, so rpIdHash-presence alone is not proof.
     */
    private boolean headerRecovered;

    public AuthenticatorData() {
    }

    public byte[] raw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    public byte[] rpIdHash() {
        return rpIdHash;
    }

    public void setRpIdHash(byte[] rpIdHash) {
        this.rpIdHash = rpIdHash;
    }

    public int flags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public boolean hasFlag(int mask) {
        return (flags & mask) != 0;
    }

    public long signCount() {
        return signCount;
    }

    public void setSignCount(long signCount) {
        this.signCount = signCount;
    }

    public byte[] aaguid() {
        return aaguid;
    }

    public void setAaguid(byte[] aaguid) {
        this.aaguid = aaguid;
    }

    public byte[] credentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public CoseKey credentialPublicKey() {
        return credentialPublicKey;
    }

    public void setCredentialPublicKey(CoseKey credentialPublicKey) {
        this.credentialPublicKey = credentialPublicKey;
    }

    /** True if only the 37-byte header was length-recovered (the structural CBOR parse failed). */
    public boolean headerRecovered() {
        return headerRecovered;
    }

    public void setHeaderRecovered(boolean headerRecovered) {
        this.headerRecovered = headerRecovered;
    }
}
