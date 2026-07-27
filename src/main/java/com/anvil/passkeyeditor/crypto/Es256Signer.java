package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * ES256 (COSE alg {@code -7}, ECDSA over P-256 / secp256r1) {@link CoseSigner}.
 *
 * Crypto is JDK SunEC only ({@code KeyPairGenerator("EC")} secp256r1, {@code Signature("SHA256withECDSA")},
 * {@code MessageDigest("SHA-256")}) - no BouncyCastle. {@code SHA256withECDSA} emits a DER
 * {@code Ecdsa-Sig-Value} which is exactly the WebAuthn wire format, so {@link #sign} returns it
 * unchanged.
 *
 * {@link #publicCoseKey()} encodes this keypair's public point as a COSE EC2 key. COSE EC2
 * coordinates are fixed 32 bytes: {@code toFixed32} normalises them ({@code len==32} as-is;
 * {@code len==33 && b[0]==0} strip the sign byte; {@code len<32} left-pad to fill 32; else throw) -
 * for COSE coordinates only, never for the DER signature's r/s.
 */
public final class Es256Signer implements CoseSigner {

    /** COSE algorithm identifier for ES256. */
    public static final int COSE_ALG_ES256 = -7;

    /** JCA standard curve name for the NIST P-256 / secp256r1 curve. */
    public static final String CURVE_NAME = "secp256r1";

    /** COSE key-type label value for EC2 (RFC 9053). */
    private static final int COSE_KTY_EC2 = 2;

    /** COSE EC2 curve label value for P-256 (RFC 9053). */
    private static final int COSE_CRV_P256 = 1;

    /** Fixed length of a P-256 field element / COSE EC2 coordinate, in bytes. */
    private static final int COORD_LEN = 32;

    private final KeyPair keyPair;

    public Es256Signer(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /** Generate a fresh secp256r1 keypair (JDK SunEC) and wrap it. */
    public static Es256Signer generate() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(CURVE_NAME));
            return new Es256Signer(kpg.generateKeyPair());
        } catch (GeneralSecurityException e) {
            // secp256r1 is guaranteed present in SunEC on every supported JDK; failure is non-recoverable.
            throw new IllegalStateException("EC P-256 key generation unavailable", e);
        }
    }

    /** The wrapped keypair (test/seam access; the private key never leaves the tool). */
    public KeyPair keyPair() {
        return keyPair;
    }

    @Override
    public int coseAlg() {
        return COSE_ALG_ES256;
    }

    @Override
    public CoseKey publicCoseKey() {
        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        ECPoint w = pub.getW();
        byte[] x = toFixed32(w.getAffineX().toByteArray());
        byte[] y = toFixed32(w.getAffineY().toByteArray());

        CoseKey key = new CoseKey();
        key.setKty(COSE_KTY_EC2);
        key.setAlg(COSE_ALG_ES256);
        key.setCrv(COSE_CRV_P256);
        key.setX(x);
        key.setY(y);
        // Lossless shadow: the canonical 77-byte COSE_Key encoding for this point.
        key.setRaw(coseKeyBytes(x, y));
        return key;
    }

    @Override
    public byte[] sign(byte[] signedData) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(signedData);
            // SHA256withECDSA emits a DER Ecdsa-Sig-Value, which IS the WebAuthn wire format. Do NOT
            // convert to raw r||s - return the DER bytes unchanged.
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ES256 signing failed", e);
        }
    }

    /**
     * Build the canonical 77-byte COSE_Key encoding for a P-256 public point from its fixed 32-byte
     * coordinates. Layout (CBOR, definite-length 5-entry map; RFC 9052/9053 EC2):
     *   A5                      map(5)
     *   01 02                   1 (kty)  : 2   (EC2)
     *   03 26                   3 (alg)  : -7  (ES256; 0x26 = neg int 6)
     *   20 01                   -1 (crv) : 1   (P-256; 0x20 = neg int 0)
     *   21 58 20 <X>            -2 (x)   : bstr(32)
     *   22 58 20 <Y>            -3 (y)   : bstr(32)
     * Keys are in canonical (RFC 8949 §4.2.1) order: positive labels ascending, then negative labels.
     *
     * @param x the 32-byte big-endian x-coordinate
     * @param y the 32-byte big-endian y-coordinate
     * @return the 77-byte COSE_Key CBOR
     */
    public static byte[] coseKeyBytes(byte[] x, byte[] y) {
        if (x.length != COORD_LEN || y.length != COORD_LEN) {
            throw new IllegalArgumentException(
                    "COSE EC2 coordinates must be " + COORD_LEN + " bytes (x=" + x.length + ", y=" + y.length + ")");
        }
        byte[] out = new byte[77];
        int p = 0;
        out[p++] = (byte) 0xA5;             // map(5)
        out[p++] = (byte) 0x01;             // label 1 (kty)
        out[p++] = (byte) 0x02;             //   = 2 (EC2)
        out[p++] = (byte) 0x03;             // label 3 (alg)
        out[p++] = (byte) 0x26;             //   = -7 (ES256)
        out[p++] = (byte) 0x20;             // label -1 (crv)
        out[p++] = (byte) 0x01;             //   = 1 (P-256)
        out[p++] = (byte) 0x21;             // label -2 (x)
        out[p++] = (byte) 0x58;             //   bstr, 1-byte length follows
        out[p++] = (byte) 0x20;             //   length 32
        System.arraycopy(x, 0, out, p, COORD_LEN);
        p += COORD_LEN;
        out[p++] = (byte) 0x22;             // label -3 (y)
        out[p++] = (byte) 0x58;             //   bstr, 1-byte length follows
        out[p++] = (byte) 0x20;             //   length 32
        System.arraycopy(y, 0, out, p, COORD_LEN);
        return out;
    }

    /**
     * Left-pad / normalise a big-endian unsigned integer to exactly 32 bytes for a COSE EC2 coordinate.
     * COSE EC2 coordinates only - never DER signature r/s.
     *
     * Handles the three cases produced by {@link BigInteger#toByteArray()} for a non-negative
     * field element: an exact 32-byte value (returned as-is), a 33-byte value whose leading byte is a
     * {@code 0x00} two's-complement sign byte (stripped), and a short value (left-padded with zeros to
     * fill 32). Anything else - including a genuine 33-byte magnitude with a non-zero leading byte, or a
     * value wider than 33 bytes - cannot be a P-256 coordinate and is rejected.
     *
     * @param coordinate the raw big-endian bytes (e.g. {@code BigInteger.toByteArray()})
     * @return a 32-byte big-endian representation
     * @throws IllegalArgumentException if {@code coordinate} cannot fit 32 bytes
     */
    public static byte[] toFixed32(byte[] coordinate) {
        // Delegates to the shared EC2 coordinate normaliser so the P-256 path cannot diverge from the larger
        // curves' EcdsaSigner. Kept as a public entry point for the re-sign/publicCoseKey callers and its tests.
        return CoseKeyWriter.toFixed(coordinate, COORD_LEN);
    }
}
