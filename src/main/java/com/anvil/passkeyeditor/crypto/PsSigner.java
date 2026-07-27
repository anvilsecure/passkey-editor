package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * RSASSA-PSS {@link CoseSigner}: PS256 ({@code -37}), PS384 ({@code -38}), PS512
 * ({@code -39}). The PSS family, which comparable tooling commonly omits.
 *
 * Crypto is JDK SunRsaSign only ({@code KeyPairGenerator("RSA")} 2048-bit, {@code Signature("RSASSA-PSS")}
 * with the COSE-mandated PSS parameters: MGF1 over the same hash, salt length = hash length, trailer 1) -
 * no BouncyCastle. The signature is the raw modulus-length octet string (the COSE wire format), returned
 * unchanged. The COSE public key is identical in shape to an RSASSA-PKCS1-v1_5 key (kty=3, {@code n}/{@code
 * e}); only the algorithm label distinguishes it - so {@link CoseKeyWriter#rsa} serves both.
 *
 * Interop note (gated): webauthn4j 0.28.3 still decodes the RSA key and recovers its public
 * key, but reports the algorithm as {@code Unknown COSEAlgorithmIdentifier(-37)} - it cannot map a PS label
 * to a verifier, so a webauthn4j-backed relying party cannot verify a PS assertion (itself a finding).
 * The gates therefore recover the public key through webauthn4j (proving the COSE key is well-formed) but
 * verify the signature under JDK's own RSASSA-PSS.
 */
public final class PsSigner implements CoseSigner {

    /** COSE algorithm identifiers for the RSASSA-PSS family. */
    public static final int COSE_ALG_PS256 = -37;
    public static final int COSE_ALG_PS384 = -38;
    public static final int COSE_ALG_PS512 = -39;

    /** Modulus size for a freshly generated keypair (bits). */
    public static final int KEY_SIZE_BITS = 2048;

    /** COSE key-type label value for RSA (RFC 8812 §2). */
    private static final int COSE_KTY_RSA = 3;

    /** JCA signature algorithm name for RSASSA-PSS (parameters supplied per-instance). */
    private static final String SIGN_ALGORITHM = "RSASSA-PSS";

    private final KeyPair keyPair;
    private final int coseAlg;
    private final PSSParameterSpec pssParameters;

    private PsSigner(KeyPair keyPair, int coseAlg, PSSParameterSpec pssParameters) {
        this.keyPair = keyPair;
        this.coseAlg = coseAlg;
        this.pssParameters = pssParameters;
    }

    /** Generate a fresh PS256 signer. */
    public static PsSigner ps256() {
        return ps256(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as a PS256 signer - used to reconstruct a stored key. */
    public static PsSigner ps256(KeyPair keyPair) {
        return new PsSigner(keyPair, COSE_ALG_PS256, pssParameters("SHA-256", MGF1ParameterSpec.SHA256, 32));
    }

    /** Generate a fresh PS384 signer. */
    public static PsSigner ps384() {
        return ps384(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as a PS384 signer. */
    public static PsSigner ps384(KeyPair keyPair) {
        return new PsSigner(keyPair, COSE_ALG_PS384, pssParameters("SHA-384", MGF1ParameterSpec.SHA384, 48));
    }

    /** Generate a fresh PS512 signer. */
    public static PsSigner ps512() {
        return ps512(generateKeyPair());
    }

    /** Wrap an existing RSA keypair as a PS512 signer. */
    public static PsSigner ps512(KeyPair keyPair) {
        return new PsSigner(keyPair, COSE_ALG_PS512, pssParameters("SHA-512", MGF1ParameterSpec.SHA512, 64));
    }

    /** COSE PSxxx fixes MGF1 over the same hash, salt length = hash output length, trailer field 1. */
    private static PSSParameterSpec pssParameters(String hash, MGF1ParameterSpec mgf1, int saltLength) {
        return new PSSParameterSpec(hash, "MGF1", mgf1, saltLength, 1);
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEY_SIZE_BITS);
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
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
        key.setRaw(CoseKeyWriter.rsa(coseAlg, n, e));
        return key;
    }

    @Override
    public byte[] sign(byte[] signedData) {
        try {
            Signature sig = Signature.getInstance(SIGN_ALGORITHM);
            sig.setParameter(pssParameters);
            sig.initSign(keyPair.getPrivate());
            sig.update(signedData);
            // RSASSA-PSS emits the raw modulus-length octet string, which IS the COSE wire format.
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSASSA-PSS signing failed", e);
        }
    }

    /** The PSS parameters this signer uses - a verifier must mirror them (test/seam access). */
    public PSSParameterSpec pssParameters() {
        return pssParameters;
    }
}
