package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.model.CoseKey;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;

import org.junit.jupiter.api.Test;

/**
 * re-sign oracle for {@link PsSigner} (RSASSA-PSS: PS256 / PS384 / PS512). Each signs the WebAuthn
 * assertion signed-input and is verified under JDK's RSASSA-PSS using the public key webauthn4j recovers
 * from our COSE RSA key - even though webauthn4j reports the PS algorithm as {@code Unknown(-N)} (it decodes
 * the key and recovers the public key, but cannot pick a PSS verifier itself; we supply it).
 */
class PsSignerTest {

    private final CborCodec codec = new Webauthn4jCborCodec();

    private static byte[] sampleSignedInput() throws Exception {
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] cdHash = MessageDigest.getInstance("SHA-256").digest(clientData);
        ByteArrayOutputStream out = new ByteArrayOutputStream(authData.length + cdHash.length);
        out.write(authData);
        out.write(cdHash);
        return out.toByteArray();
    }

    private static Signature pssVerifier(PSSParameterSpec params) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(params);
        return s;
    }

    private void assertSignsAndVerifies(PsSigner signer, int expectedAlgValue) throws Exception {
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        // RSASSA-PSS is the raw modulus-length octet string (256 bytes for a 2048-bit key).
        assertEquals(256, sig.length, "a 2048-bit PSS signature is 256 bytes (never DER-framed)");

        // (1) standard JDK PSS verifier, signer's own public key.
        Signature jca = pssVerifier(signer.pssParameters());
        jca.initVerify(signer.keyPair().getPublic());
        jca.update(signedInput);
        assertTrue(jca.verify(sig), "PSS signature must verify under JDK RSASSA-PSS with matching params");

        // (2) the oracle: webauthn4j decodes our COSE RSA key and recovers the public key (alg reported as
        // Unknown(-N), but the key + public key are valid), and our PSS signature verifies under it.
        CoseKey ourKey = signer.publicCoseKey();
        COSEKey w4jKey = Fixtures.decodeCoseKey(codec.encodeCoseKey(ourKey));
        RSACOSEKey rsa = assertInstanceOf(RSACOSEKey.class, w4jKey, "decoded key must be RSA");
        assertEquals(expectedAlgValue, rsa.getAlgorithm().getValue(),
                "decoded alg value is the PS label even though webauthn4j classes it Unknown");
        assertEquals(256, rsa.getN().length, "decoded modulus is 256 bytes for a 2048-bit key");

        PublicKey recovered = w4jKey.getPublicKey();
        Signature viaW4j = pssVerifier(signer.pssParameters());
        viaW4j.initVerify(recovered);
        viaW4j.update(signedInput);
        assertTrue(viaW4j.verify(sig), "signature must verify under the webauthn4j-recovered public key");

        // negative control.
        byte[] tampered = signedInput.clone();
        tampered[0] ^= 0x01;
        Signature neg = pssVerifier(signer.pssParameters());
        neg.initVerify(signer.keyPair().getPublic());
        neg.update(tampered);
        assertFalse(neg.verify(sig), "a tampered input must not verify (negative control)");
    }

    @Test
    void ps256SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(PsSigner.ps256(), PsSigner.COSE_ALG_PS256);
    }

    @Test
    void ps384SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(PsSigner.ps384(), PsSigner.COSE_ALG_PS384);
    }

    @Test
    void ps512SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(PsSigner.ps512(), PsSigner.COSE_ALG_PS512);
    }
}
