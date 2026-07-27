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
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.jupiter.api.Test;

/**
 * re-sign oracle for {@link EcdsaSigner} (ES384 / P-384 and ES512 / P-521) - the
 * {@link ReSignOracleTest} discipline for the larger NIST curves. Each signs the WebAuthn assertion
 * signed-input and is verified under standard JCA and under the public key webauthn4j recovers from our
 * COSE EC2 key, with the curve/alg/coordinate-width and DER framing pinned.
 */
class EcdsaSignerTest {

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

    private void assertSignsAndVerifies(EcdsaSigner signer, String jcaName, Curve expectedCurve,
                                        COSEAlgorithmIdentifier expectedAlg, int coordLen) throws Exception {
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        // (1) standard JCA verifier, signer's own public key.
        Signature jca = Signature.getInstance(jcaName);
        jca.initVerify(signer.keyPair().getPublic());
        jca.update(signedInput);
        assertTrue(jca.verify(sig), jcaName + " signature must verify under standard JCA");

        // ECDSA is DER on the wire for every curve (not raw r||s, not fixed length).
        assertEquals((byte) 0x30, sig[0], "ECDSA signature must be a DER SEQUENCE (0x30)");
        assertTrue(sig.length > 64, "DER Ecdsa-Sig-Value is > 64 bytes; len=" + sig.length);

        // (2) the oracle: webauthn4j decodes our COSE EC2 key and the recovered key verifies our signature.
        CoseKey ourKey = signer.publicCoseKey();
        COSEKey w4jKey = Fixtures.decodeCoseKey(codec.encodeCoseKey(ourKey));
        EC2COSEKey ec2 = assertInstanceOf(EC2COSEKey.class, w4jKey, "decoded key must be EC2");
        assertEquals(expectedAlg, ec2.getAlgorithm(), "decoded alg");
        assertEquals(expectedCurve, ec2.getCurve(), "decoded curve");
        assertEquals(coordLen, ec2.getX().length, "decoded x coordinate width");
        assertEquals(coordLen, ec2.getY().length, "decoded y coordinate width");

        PublicKey recovered = w4jKey.getPublicKey();
        Signature viaW4j = Signature.getInstance(jcaName);
        viaW4j.initVerify(recovered);
        viaW4j.update(signedInput);
        assertTrue(viaW4j.verify(sig), "signature must verify under the webauthn4j-recovered public key");

        // negative control.
        byte[] tampered = signedInput.clone();
        tampered[0] ^= 0x01;
        Signature neg = Signature.getInstance(jcaName);
        neg.initVerify(signer.keyPair().getPublic());
        neg.update(tampered);
        assertFalse(neg.verify(sig), "a tampered input must not verify (negative control)");
    }

    @Test
    void es384SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(EcdsaSigner.es384(), "SHA384withECDSA",
                Curve.SECP384R1, COSEAlgorithmIdentifier.ES384, 48);
    }

    @Test
    void es512SignsAndVerifies() throws Exception {
        assertSignsAndVerifies(EcdsaSigner.es512(), "SHA512withECDSA",
                Curve.SECP521R1, COSEAlgorithmIdentifier.ES512, 66);
    }
}
