package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * ECDSA {@link CoseSigner} for the larger NIST curves - ES384 (COSE {@code -35}, P-384) and
 * ES512 (COSE {@code -36}, P-521). The P-256 / ES256 case keeps its dedicated {@link Es256Signer}
 * (the established ES256 signer); this class is the parametric sibling for the bigger curves so the
 * tool covers the full COSE ECDSA range.
 *
 * Crypto is JDK SunEC only ({@code KeyPairGenerator("EC")}, {@code Signature("SHAxxxwithECDSA")}) - no
 * BouncyCastle. Like ES256, every ECDSA signature is an ASN.1 DER {@code Ecdsa-Sig-Value} (variable
 * length), which is the WebAuthn wire format, so {@link #sign} returns it unchanged. {@link #publicCoseKey()}
 * encodes the public point as a COSE EC2 key via {@link CoseKeyWriter}; coordinates are normalised to the
 * curve's fixed field width ({@code toFixed}: 48 bytes for P-384, 66 for P-521).
 */
public final class EcdsaSigner implements CoseSigner {

    /** COSE algorithm identifier for ES384. */
    public static final int COSE_ALG_ES384 = -35;
    /** COSE algorithm identifier for ES512. */
    public static final int COSE_ALG_ES512 = -36;

    /** COSE key-type label value for EC2 (RFC 9053). */
    private static final int COSE_KTY_EC2 = 2;
    /** COSE EC2 curve label values (RFC 9053): P-384 = 2, P-521 = 3. */
    private static final int COSE_CRV_P384 = 2;
    private static final int COSE_CRV_P521 = 3;

    private final KeyPair keyPair;
    private final int coseAlg;
    private final int coseCrv;
    private final String jcaSignatureAlgorithm;
    private final int coordLen;

    private EcdsaSigner(KeyPair keyPair, int coseAlg, int coseCrv, String jcaSignatureAlgorithm, int coordLen) {
        this.keyPair = keyPair;
        this.coseAlg = coseAlg;
        this.coseCrv = coseCrv;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        this.coordLen = coordLen;
    }

    /** Generate a fresh ES384 (P-384) signer. */
    public static EcdsaSigner es384() {
        return es384(generateKeyPair("secp384r1"));
    }

    /** Wrap an existing P-384 keypair as an ES384 signer - used to reconstruct a stored key. */
    public static EcdsaSigner es384(KeyPair keyPair) {
        return new EcdsaSigner(keyPair, COSE_ALG_ES384, COSE_CRV_P384, "SHA384withECDSA", 48);
    }

    /** Generate a fresh ES512 (P-521) signer. */
    public static EcdsaSigner es512() {
        return es512(generateKeyPair("secp521r1"));
    }

    /** Wrap an existing P-521 keypair as an ES512 signer - used to reconstruct a stored key. */
    public static EcdsaSigner es512(KeyPair keyPair) {
        return new EcdsaSigner(keyPair, COSE_ALG_ES512, COSE_CRV_P521, "SHA512withECDSA", 66);
    }

    private static KeyPair generateKeyPair(String curve) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(curve));
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
            // The NIST P-curves are present in SunEC on every supported JDK; failure is non-recoverable.
            throw new IllegalStateException(curve + " key generation unavailable", e);
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
        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        ECPoint w = pub.getW();
        byte[] x = CoseKeyWriter.toFixed(w.getAffineX().toByteArray(), coordLen);
        byte[] y = CoseKeyWriter.toFixed(w.getAffineY().toByteArray(), coordLen);

        CoseKey key = new CoseKey();
        key.setKty(COSE_KTY_EC2);
        key.setAlg(coseAlg);
        key.setCrv(coseCrv);
        key.setX(x);
        key.setY(y);
        key.setRaw(CoseKeyWriter.ec2(coseAlg, coseCrv, x, y));
        return key;
    }

    @Override
    public byte[] sign(byte[] signedData) {
        try {
            Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
            sig.initSign(keyPair.getPrivate());
            sig.update(signedData);
            // SHAxxxwithECDSA emits a DER Ecdsa-Sig-Value, which IS the WebAuthn wire format. Return it
            // unchanged - never convert to raw r||s, and never assume a fixed length.
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ECDSA (" + jcaSignatureAlgorithm + ") signing failed", e);
        }
    }

}
