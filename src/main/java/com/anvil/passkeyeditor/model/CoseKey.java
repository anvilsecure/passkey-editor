package com.anvil.passkeyeditor.model;

/**
 * A decoded COSE_Key (RFC 9052 / 8812), tool-internal and independent of webauthn4j's key types.
 *
 * Carries the fields needed to display and to re-encode an ES256 (EC2 / P-256) key: {@code kty=2},
 * {@code alg=-7}, {@code crv=1}, {@code x(-2)} = 32 bytes, {@code y(-3)} = 32 bytes. An OKP (Ed25519) key
 * also decodes for display: {@code kty=1}, {@code alg=-8}, {@code crv=6}, {@code x(-2)} = the 32-byte public
 * key (no {@code y}). An RSA key decodes {@code kty=3}, {@code alg}, and its {@code n(-1)} / {@code e(-2)}
 * for display, leaving the EC2 coordinate fields null. {@code raw} is always retained so an unedited key
 * round-trips verbatim.
 *
 * {@code n}/{@code e} are display-only. Nothing re-encodes them: {@code encodeCoseKey} returns the
 * verbatim {@code raw} whenever it is present (always, for a decoded or planted RSA key), and its
 * from-fields fallback accepts EC2 only. So surfacing them cannot change a byte on the wire.
 *
 * Shadow is verbatim wire bytes, not canonical. Both decode paths populate {@code raw} with
 * the exact COSE bytes as they appeared on the wire: a standalone {@code decodeCoseKey} uses its input
 * directly, and an embedded credential key (inside a registration's authData) is sliced verbatim
 * off the authData tail rather than re-serialised. A foreign producer's COSE map order / integer width
 * therefore survives a round-trip byte-identically - so a key-splice attack that re-encodes an unedited
 * {@code raw()} does not silently reorder the map and invalidate the RP's attestation/assertion signature.
 *
 * COSE EC2 coordinates are fixed 32 bytes - see {@code toFixed32} in the crypto layer (that
 * normalisation is for COSE coords only, never for DER signature r/s).
 */
public final class CoseKey {

    /** Verbatim COSE_Key bytes as decoded from the wire; the lossless shadow for round-tripping. */
    private byte[] raw;

    private int kty;   // COSE key type label (1): 2 = EC2, 3 = RSA, 1 = OKP
    private int alg;   // COSE algorithm label (3): -7 = ES256
    private int crv;   // EC2/OKP curve label (-1): 1 = P-256

    private byte[] x;  // EC2 x-coordinate (-2), fixed 32 bytes for P-256
    private byte[] y;  // EC2 y-coordinate (-3), fixed 32 bytes for P-256

    private byte[] n;  // RSA modulus (-1), display-only
    private byte[] e;  // RSA public exponent (-2), display-only

    public CoseKey() {
    }

    public byte[] raw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    public int kty() {
        return kty;
    }

    public void setKty(int kty) {
        this.kty = kty;
    }

    public int alg() {
        return alg;
    }

    public void setAlg(int alg) {
        this.alg = alg;
    }

    public int crv() {
        return crv;
    }

    public void setCrv(int crv) {
        this.crv = crv;
    }

    public byte[] x() {
        return x;
    }

    public void setX(byte[] x) {
        this.x = x;
    }

    public byte[] y() {
        return y;
    }

    public void setY(byte[] y) {
        this.y = y;
    }

    public byte[] n() {
        return n;
    }

    public void setN(byte[] n) {
        this.n = n;
    }

    public byte[] e() {
        return e;
    }

    public void setE(byte[] e) {
        this.e = e;
    }
}
