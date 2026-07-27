package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;

/**
 * EdDSA / Ed25519 (COSE alg {@code -8}, OKP key type) {@link CoseSigner}.
 *
 * Crypto is JDK only ({@code KeyPairGenerator("Ed25519")}, {@code Signature("Ed25519")}) - no
 * BouncyCastle, matching {@link Es256Signer}'s SunEC-only discipline. Ed25519 is a pure signature
 * scheme (PureEdDSA, RFC 8032): the signer hashes the message internally, so {@link #sign} is fed the
 * WebAuthn assertion signed-input {@code authenticatorData ‖ SHA-256(clientDataJSON)} verbatim and emits
 * the fixed 64-byte {@code R ‖ S} signature, which is the COSE EdDSA wire format - returned
 * unchanged (no DER framing, unlike ES256).
 *
 * {@link #publicCoseKey()} hand-rolls this keypair's public half as a COSE OKP key (RFC 8812 §2): the
 * 32-byte public key is sliced out of the JDK X.509/SPKI encoding (RFC 8410, fixed 44-byte layout for
 * Ed25519) and wrapped in the canonical 42-byte COSE_Key CBOR. Hand-rolled rather than routed through
 * webauthn4j so this layer stays dependency-free; the encoding is gated by verifying the round-tripped
 * key under webauthn4j's own decoder.
 *
 * This is the marquee algorithm for real-RP coverage: webauthn.io, passkeys-debugger and webauthn.lubu
 * all default to Ed25519 (the Chrome virtual authenticator picks {@code -8} when an RP lists it first), so
 * forging/planting a credential there requires this signer rather than {@link Es256Signer}.
 */
public final class EdDsaSigner implements CoseSigner {

    /** COSE algorithm identifier for EdDSA. */
    public static final int COSE_ALG_EDDSA = -8;

    /** JCA standard algorithm name for Ed25519 (key generation, signing, verification). */
    public static final String ALGORITHM = "Ed25519";

    /** COSE key-type label value for OKP (RFC 9053 / 8812). */
    private static final int COSE_KTY_OKP = 1;

    /** COSE OKP curve label value for Ed25519 (RFC 8812 §3.1). */
    private static final int COSE_CRV_ED25519 = 6;

    /** Length of an Ed25519 public key / COSE OKP {@code x} coordinate, in bytes. */
    private static final int KEY_LEN = 32;

    /**
     * The fixed 12-byte X.509 {@code SubjectPublicKeyInfo} prefix the JDK emits for an Ed25519 public key
     * (RFC 8410 §4 / §10.3): {@code SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING(33){ 0x00 || key }}}.
     * The remaining 32 bytes are the raw public key. Validated so a provider framing change fails loud
     * rather than slicing the wrong bytes.
     */
    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    private final KeyPair keyPair;

    public EdDsaSigner(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /** Generate a fresh Ed25519 keypair (JDK) and wrap it. */
    public static EdDsaSigner generate() {
        try {
            return new EdDsaSigner(KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair());
        } catch (GeneralSecurityException e) {
            // Ed25519 is present in the JDK from 15 onward; failure on the supported JDK 21 is non-recoverable.
            throw new IllegalStateException("Ed25519 key generation unavailable", e);
        }
    }

    /** The wrapped keypair (test/seam access; the private key never leaves the tool). */
    public KeyPair keyPair() {
        return keyPair;
    }

    @Override
    public int coseAlg() {
        return COSE_ALG_EDDSA;
    }

    @Override
    public CoseKey publicCoseKey() {
        byte[] x = rawPublicKey((EdECPublicKey) keyPair.getPublic());

        CoseKey key = new CoseKey();
        key.setKty(COSE_KTY_OKP);
        key.setAlg(COSE_ALG_EDDSA);
        key.setCrv(COSE_CRV_ED25519);
        key.setX(x);
        // Lossless shadow: the canonical 42-byte COSE OKP encoding {1:1, 3:-8, -1:6, -2:x} - the bytes
        // the from-fields re-encode (RegistrationSubstituter) puts on the wire verbatim.
        key.setRaw(CoseKeyWriter.okp(COSE_ALG_EDDSA, COSE_CRV_ED25519, x));
        return key;
    }

    @Override
    public byte[] sign(byte[] signedData) {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initSign(keyPair.getPrivate());
            sig.update(signedData);
            // Ed25519 emits the fixed 64-byte R||S signature, which IS the COSE EdDSA wire format. Do NOT
            // wrap it in DER (that is the ES256 convention) - return it unchanged.
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("EdDSA signing failed", e);
        }
    }

    /**
     * Slice the raw 32-byte Ed25519 public key out of the JDK's X.509/SPKI encoding. Validates the fixed
     * Ed25519 SPKI prefix + length (RFC 8410) so a provider framing change fails loud rather than yielding
     * the wrong key.
     */
    private static byte[] rawPublicKey(EdECPublicKey pub) {
        byte[] spki = pub.getEncoded();
        int expected = ED25519_SPKI_PREFIX.length + KEY_LEN;
        if (spki.length != expected
                || !Arrays.equals(spki, 0, ED25519_SPKI_PREFIX.length, ED25519_SPKI_PREFIX, 0, ED25519_SPKI_PREFIX.length)) {
            throw new IllegalStateException(
                    "unexpected Ed25519 SubjectPublicKeyInfo encoding (len=" + spki.length + ")");
        }
        return Arrays.copyOfRange(spki, ED25519_SPKI_PREFIX.length, expected);
    }
}
