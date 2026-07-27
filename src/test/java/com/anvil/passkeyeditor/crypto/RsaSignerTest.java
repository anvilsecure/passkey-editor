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
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.jupiter.api.Test;

/**
 * re-sign oracle for {@link RsaSigner} across the full RSASSA-PKCS1-v1_5 family (RS256 / RS384 /
 * RS512 / RS1) - the {@link ReSignOracleTest} discipline per algorithm. Each signs the WebAuthn assertion
 * signed-input and is verified under standard JCA and under the public key webauthn4j recovers from our
 * COSE RSA key; the signature is the raw modulus-length octet string (never DER-framed).
 */
class RsaSignerTest {

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

    private void assertSignsAndVerifies(RsaSigner signer, String jcaName, COSEAlgorithmIdentifier expectedAlg)
            throws Exception {
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        // RSASSA-PKCS1-v1_5 is the raw modulus-length octet string (256 bytes for a 2048-bit key).
        assertEquals(256, sig.length, "a 2048-bit PKCS#1 v1.5 signature is 256 bytes (never DER-framed)");

        Signature jca = Signature.getInstance(jcaName);
        jca.initVerify(signer.keyPair().getPublic());
        jca.update(signedInput);
        assertTrue(jca.verify(sig), jcaName + " signature must verify under standard JCA");

        CoseKey ourKey = signer.publicCoseKey();
        COSEKey w4jKey = Fixtures.decodeCoseKey(codec.encodeCoseKey(ourKey));
        RSACOSEKey rsa = assertInstanceOf(RSACOSEKey.class, w4jKey, "decoded key must be RSA");
        assertEquals(expectedAlg, rsa.getAlgorithm(), "decoded alg");
        assertEquals(256, rsa.getN().length, "decoded modulus is 256 bytes for a 2048-bit key");

        PublicKey recovered = w4jKey.getPublicKey();
        Signature viaW4j = Signature.getInstance(jcaName);
        viaW4j.initVerify(recovered);
        viaW4j.update(signedInput);
        assertTrue(viaW4j.verify(sig), "signature must verify under the webauthn4j-recovered public key");

        byte[] tampered = signedInput.clone();
        tampered[0] ^= 0x01;
        Signature neg = Signature.getInstance(jcaName);
        neg.initVerify(signer.keyPair().getPublic());
        neg.update(tampered);
        assertFalse(neg.verify(sig), "a tampered input must not verify (negative control)");
    }

    @Test
    void rs256SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(RsaSigner.rs256(), "SHA256withRSA", COSEAlgorithmIdentifier.RS256);
    }

    @Test
    void rs384SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(RsaSigner.rs384(), "SHA384withRSA", COSEAlgorithmIdentifier.RS384);
    }

    @Test
    void rs512SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(RsaSigner.rs512(), "SHA512withRSA", COSEAlgorithmIdentifier.RS512);
    }

    @Test
    void rs1SignsAndVerifies() throws Exception {
        // RS1 is deprecated (SHA-1) - supported precisely as an algorithm-downgrade target.
        assertSignsAndVerifies(RsaSigner.rs1(), "SHA1withRSA", COSEAlgorithmIdentifier.RS1);
    }
}
