package com.anvil.passkeyeditor.model;

/**
 * The {@code clientDataJSON} of a ceremony.
 *
 * Byte-opaque by contract. The relying party signs the exact wire bytes of
 * {@code clientDataJSON} (the signed input is {@code authData ‖ SHA-256(clientDataJSON wire bytes)}),
 * so {@link #raw()} is the single source of truth. The parsed accessors ({@link #type()},
 * {@link #challenge()}, {@link #origin()}, {@link #crossOrigin()}, {@link #topOrigin()}) are a
 * display-only convenience produced by lenient JSON parsing; edits must be performed as surgical
 * byte substitution on {@code raw} and never via re-serialization of a parsed view.
 */
public final class ClientData {

    private byte[] raw;

    // Display-only parsed view. Populated best-effort; any field may be null if parsing failed.
    private String type;
    private String challenge;
    private String origin;
    private Boolean crossOrigin;
    private String topOrigin;

    public ClientData() {
    }

    public ClientData(byte[] raw) {
        this.raw = raw;
    }

    /** The exact wire bytes of clientDataJSON. The signed, authoritative representation. */
    public byte[] raw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    /** Display-only: the {@code type} member ("webauthn.create" / "webauthn.get"). */
    public String type() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    /** Display-only: the base64url {@code challenge} member, as a string. */
    public String challenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    /** Display-only: the {@code origin} member. */
    public String origin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    /** Display-only: the {@code crossOrigin} member; may be null when absent. */
    public Boolean crossOrigin() {
        return crossOrigin;
    }

    public void setCrossOrigin(Boolean crossOrigin) {
        this.crossOrigin = crossOrigin;
    }

    /** Display-only: the {@code topOrigin} member (top-level document origin in a cross-origin ceremony);
     * may be null when absent. */
    public String topOrigin() {
        return topOrigin;
    }

    public void setTopOrigin(String topOrigin) {
        this.topOrigin = topOrigin;
    }
}
