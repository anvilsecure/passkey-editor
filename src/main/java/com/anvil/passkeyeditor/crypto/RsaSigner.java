package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

/**
 * RSASSA-PKCS1-v1_5 {@link CoseSigner} covering the full RSA range: RS256 ({@code -257}),
 * RS384 ({@code -258}), RS512 ({@code -259}), and RS1 ({@code -65535}, SHA-1).
 *
 * Crypto is JDK SunRsaSign only ({@code KeyPairGenerator("RSA")} 2048-bit, {@code Signature("SHAxxxwithRSA")})
 * - no BouncyCastle. The PKCS#1 v1.5 signature ({@code modulus-length} bytes - 256 for a 2048-bit key) is
 * the COSE wire format, so {@link #sign} returns it unchanged. The four variants differ only in the hash
 * (hence the JCA signature name) and the COSE algorithm label: the RSA public key {@code (n, e)} itself is
 * identical, since the hash is named by the algorithm id, not the key.
 *
 * {@link #publicCoseKey()} encodes {@code n}/{@code e} (minimal unsigned big-endian, RFC 8230) as a COSE
 * RSA key via {@link CoseKeyWriter}. RS256 is the classic algorithm-confusion surface (Chen test #9); RS1
 * is deprecated (SHA-1) and is most useful as a downgrade target - an RP that accepts an RS1 key is itself
 * a finding.
 */
public final class RsaSigner implements CoseSigner {

    /** COSE algorithm identifiers for the RSASSA-PKCS1-v1_5 family. */
    public static final int COSE_ALG_RS256 = -257;
    public static final int COSE_ALG_RS384 = -258;
    public static final int COSE_ALG_RS512 = -259;
    public static final int COSE_ALG_RS1 = -65535;

    /** Modulus size for a freshly generated keypair (bits). */
    public static final int KEY_SIZE_BITS = 2048;

    /** COSE key-type label value for RSA (RFC 8812 §2). */
    private static final int COSE_KTY_RSA = 3;

    private final KeyPair keyPair;
    private final int coseAlg;
    private final String jcaSignatureAlgorithm;

    private RsaSigner(KeyPair keyPair, int coseAlg, String jcaSignatureAlgorithm) {
        this.keyPair = keyPair;
        this.coseAlg = coseAlg;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
    }

    /** Generate a fresh RS256 signer. */
    public static RsaSigner rs256() {
        return rs256(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as an RS256 signer - used to reconstruct a stored key. */
    public static RsaSigner rs256(KeyPair keyPair) {
        return new RsaSigner(keyPair, COSE_ALG_RS256, "SHA256withRSA");
    }

    /** Generate a fresh RS384 signer. */
    public static RsaSigner rs384() {
        return rs384(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as an RS384 signer. */
    public static RsaSigner rs384(KeyPair keyPair) {
        return new RsaSigner(keyPair, COSE_ALG_RS384, "SHA384withRSA");
    }

    /** Generate a fresh RS512 signer. */
    public static RsaSigner rs512() {
        return rs512(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as an RS512 signer. */
    public static RsaSigner rs512(KeyPair keyPair) {
        return new RsaSigner(keyPair, COSE_ALG_RS512, "SHA512withRSA");
    }

    /** Generate a fresh RS1 (deprecated, SHA-1) signer. */
    public static RsaSigner rs1() {
        return rs1(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as an RS1 (deprecated, SHA-1) signer. */
    public static RsaSigner rs1(KeyPair keyPair) {
        return new RsaSigner(keyPair, COSE_ALG_RS1, "SHA1withRSA");
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEY_SIZE_BITS);
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
            // RSA is present in SunRsaSign on every supported JDK; failure is non-recoverable.
            throw new IllegalStateException("RSA key generation unavailable", e);
        }
    }

    /** The wrapped keypair (test/seam access; the private key never leaves the tool). */
    public KeyPair keyPair() {
        return keyPair;
    }

    @Override
    public int coseAlg() {
        return coseAlg;
    }

    @Override
    public CoseKey publicCoseKey() {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        byte[] n = CoseKeyWriter.minimalUnsigned(pub.getModulus());
        byte[] e = CoseKeyWriter.minimalUnsigned(pub.getPublicExponent());

        CoseKey key = new CoseKey();
        key.setKty(COSE_KTY_RSA);
        key.setAlg(coseAlg);
        // The CoseKey model carries no RSA n/e fields (EC2-oriented); the verbatim COSE shadow is the
        // authoritative encoding the from-fields re-encode (RegistrationSubstituter) puts on the wire.
        key.setRaw(CoseKeyWriter.rsa(coseAlg, n, e));
        return key;
    }

    @Override
    public byte[] sign(byte[] signedData) {
        try {
            Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
            sig.initSign(keyPair.getPrivate());
            sig.update(signedData);
            // SHAxxxwithRSA emits the PKCS#1 v1.5 signature octet string, which IS the COSE wire format.
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA (" + jcaSignatureAlgorithm + ") signing failed", e);
        }
    }
}
