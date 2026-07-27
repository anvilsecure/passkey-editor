package com.anvil.passkeyeditor.model;

/**
 * Decoded attestation object (registration / {@code webauthn.create}), tool-internal and independent
 * of webauthn4j.
 *
 * Wire shape: a CBOR map {@code { "fmt": tstr, "authData": bstr, "attStmt": map }}. The
 * {@link #authData()} carries the attested credential data (AT flag set, COSE public key inside).
 *
 * For key-substitution attacks the tool emits {@code fmt="none"} with an empty {@code attStmt};
 * the raw {@code attStmt} bytes are retained as {@link #attStmtRaw()} so a non-{@code none}
 * attestation round-trips verbatim when unedited. {@link #raw()} retains the whole verbatim
 * attestation-object bytes as the lossless shadow.
 */
public final class AttestationObject {

    /** Verbatim attestation-object CBOR bytes as decoded; lossless shadow for round-tripping. */
    private byte[] raw;

    private String fmt;                      // attestation statement format, e.g. "none", "packed"
    private AuthenticatorData authData;      // decoded authData (AT set)
    private byte[] attStmtRaw;               // verbatim CBOR bytes of the attStmt map

    public AttestationObject() {
    }

    public byte[] raw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    public String fmt() {
        return fmt;
    }

    public void setFmt(String fmt) {
        this.fmt = fmt;
    }

    public AuthenticatorData authData() {
        return authData;
    }

    public void setAuthData(AuthenticatorData authData) {
        this.authData = authData;
    }

    public byte[] attStmtRaw() {
        return attStmtRaw;
    }

    public void setAttStmtRaw(byte[] attStmtRaw) {
        this.attStmtRaw = attStmtRaw;
    }
}
