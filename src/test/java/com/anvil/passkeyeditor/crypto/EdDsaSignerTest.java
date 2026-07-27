package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.model.CoseKey;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.authenticator.EdDSACOSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.jupiter.api.Test;

/**
 * re-sign oracle for {@link EdDsaSigner} (EdDSA / Ed25519, COSE alg {@code -8}) - the
 * {@link ReSignOracleTest} discipline extended to a new algorithm.
 *
 * {@link EdDsaSigner} signs the WebAuthn assertion signed-input
 * {@code authenticatorData ‖ SHA-256(clientDataJSON)} and emits the fixed 64-byte Ed25519 signature.
 * Correctness is localised to our code by verifying that output under independent verifiers:
 * standard JCA {@code Signature("Ed25519")}, and the public key webauthn4j recovers by decoding our
 * hand-rolled COSE OKP key - so the COSE-key encode path is in the loop and a secure RP backed by
 * webauthn4j would accept the signature.
 */
class EdDsaSignerTest {

    private final CborCodec codec = new Webauthn4jCborCodec();

    /** Build the canonical assertion signed input: {@code authData ‖ SHA-256(clientDataJSON)}. */
    private static byte[] signedInput(byte[] authData, byte[] clientDataJson) throws Exception {
        byte[] cdHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
        ByteArrayOutputStream out = new ByteArrayOutputStream(authData.length + cdHash.length);
        out.write(authData);
        out.write(cdHash);
        return out.toByteArray();
    }

    private static byte[] sampleSignedInput() throws Exception {
        return signedInput(Fixtures.assertionAuthData(), Fixtures.clientDataJson("webauthn.get"));
    }

    @Test
    void signatureVerifiesUnderStandardJcaVerifier() throws Exception {
        EdDsaSigner signer = EdDsaSigner.generate();
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        Signature verifier = Signature.getInstance(EdDsaSigner.ALGORITHM);
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(signedInput);
        assertTrue(verifier.verify(sig), "Ed25519 signature must verify under standard JCA Ed25519");
    }

    /**
     * The oracle: verify under the public key webauthn4j recovers from our COSE key - our public OKP key
     * → CBOR (codec encode, which returns our verbatim shadow) → webauthn4j COSE decode → {@code
     * getPublicKey()}. Proves the substitute key we put on the wire matches the private key we sign with,
     * and that webauthn4j can decode the COSE bytes we emit.
     */
    @Test
    void signatureVerifiesUnderWebauthn4jRecoveredKey() throws Exception {
        EdDsaSigner signer = EdDsaSigner.generate();
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        CoseKey ourKey = signer.publicCoseKey();
        byte[] coseCbor = codec.encodeCoseKey(ourKey);
        COSEKey w4jKey = Fixtures.decodeCoseKey(coseCbor);
        PublicKey recovered = w4jKey.getPublicKey();

        // webauthn4j exposes no createEdDSA() factory; it recovers the PublicKey and verifies via JCA, which
        // is exactly what we exercise here - the recovered key is webauthn4j's, the verify is JCA Ed25519.
        Signature verifier = Signature.getInstance(EdDsaSigner.ALGORITHM);
        verifier.initVerify(recovered);
        verifier.update(signedInput);
        assertTrue(verifier.verify(sig),
                "signature must verify under the key webauthn4j recovered from our round-tripped COSE OKP key");
    }

    @Test
    void coseKeyDecodesToOkpEd25519UnderWebauthn4j() {
        EdDsaSigner signer = EdDsaSigner.generate();
        CoseKey ourKey = signer.publicCoseKey();

        // Our model view.
        assertEquals(1, ourKey.kty(), "kty must be OKP (1)");
        assertEquals(EdDsaSigner.COSE_ALG_EDDSA, ourKey.alg(), "alg must be EdDSA (-8)");
        assertEquals(42, ourKey.raw().length, "the OKP COSE_Key is a fixed 42 bytes");

        // webauthn4j's independent decode of the same bytes.
        COSEKey w4jKey = Fixtures.decodeCoseKey(codec.encodeCoseKey(ourKey));
        EdDSACOSEKey eddsa = assertInstanceOf(EdDSACOSEKey.class, w4jKey,
                "webauthn4j must decode our COSE bytes as an OKP/EdDSA key");
        assertEquals(COSEAlgorithmIdentifier.EdDSA, eddsa.getAlgorithm(), "decoded alg must be EdDSA");
        assertEquals(Curve.ED25519, eddsa.getCurve(), "decoded curve must be Ed25519");
        assertEquals(32, eddsa.getX().length, "decoded x is the 32-byte Ed25519 public key");
    }

    @Test
    void decodeCoseKeyMapsOkpCurveAndX() {
        // Regression (the tab showed "curve":"crv0" with no "x"): decoding an OKP
        // (Ed25519) COSE key through our codec must populate crv + x in the tool's model - mapCoseKey used to
        // handle only EC2 fully and drop OKP coordinates into the catch-all branch.
        EdDsaSigner signer = EdDsaSigner.generate();
        CoseKey source = signer.publicCoseKey();          // the 42-byte OKP COSE_Key as it goes on the wire

        CoseKey decoded = codec.decodeCoseKey(source.raw());

        assertEquals(1, decoded.kty(), "decoded kty must be OKP (1)");
        assertEquals(6, decoded.crv(), "decoded crv must be Ed25519 (6), not 0");
        assertEquals(EdDsaSigner.COSE_ALG_EDDSA, decoded.alg(), "decoded alg must be EdDSA (-8)");
        assertNotNull(decoded.x(), "decoded OKP key must carry x (the public key), not null");
        assertArrayEquals(source.x(), decoded.x(), "decoded x must equal the original 32-byte public key");
    }

    @Test
    void encodeCoseKeyReturnsOurVerbatimShadow() {
        EdDsaSigner signer = EdDsaSigner.generate();
        CoseKey ourKey = signer.publicCoseKey();
        // The composition that makes alg-confusion work without touching the codec: the from-fields
        // encode short-circuits on the non-null raw shadow, so RegistrationSubstituter embeds OUR exact
        // OKP bytes (encodeCoseKey from EC2-only fields is never reached for an OKP key).
        assertArrayEquals(ourKey.raw(), codec.encodeCoseKey(ourKey),
                "encodeCoseKey must return our verbatim COSE shadow, not re-synthesise it");
    }

    @Test
    void signatureIsFixed64Bytes() throws Exception {
        EdDsaSigner signer = EdDsaSigner.generate();
        byte[] sig = signer.sign(sampleSignedInput());
        assertEquals(64, sig.length, "an Ed25519 signature is a fixed 64-byte R||S (never DER)");
    }

    @Test
    void verifierRejectsTamperedInput() throws Exception {
        EdDsaSigner signer = EdDsaSigner.generate();
        byte[] signedInput = sampleSignedInput();
        byte[] sig = signer.sign(signedInput);

        byte[] tampered = signedInput.clone();
        tampered[0] ^= 0x01; // flip a bit in the rpIdHash

        Signature verifier = Signature.getInstance(EdDsaSigner.ALGORITHM);
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(tampered);
        assertFalse(verifier.verify(sig), "a tampered input must not verify (negative control)");
    }
}
