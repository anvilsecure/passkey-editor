package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.model.CoseKey;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.SignatureUtil;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * re-sign oracle.
 *
 * {@link Es256Signer} signs the WebAuthn assertion signed-input
 * {@code authenticatorData ‖ SHA-256(clientDataJSON wire bytes)} and emits an ASN.1 DER
 * {@code Ecdsa-Sig-Value}. Correctness is localised to our code (vs an RP) by verifying that
 * output under independent verifiers:
 *
 *   - standard JCA {@code Signature("SHA256withECDSA")} with the signer's public key - a fully
 *       independent code path;
 *   - webauthn4j's own {@code SignatureUtil.createES256()} verifier, fed the public key
 *       recovered by round-tripping our {@code publicCoseKey()} through the CBOR codec and webauthn4j's
 *       COSE decoder (so the COSE-key encode path is in the loop too) - the oracle named in the gate.
 *
 * The signature is asserted DER-parseable with {@code len > 64} and never {@code == 72}
 * (DER ECDSA signatures are variable-length; a fixed-72 assumption is the classic re-sign bug).
 */
class ReSignOracleTest {

    /** Build the canonical assertion signed input: {@code authData ‖ SHA-256(clientDataJSON)}. */
    private static byte[] signedInput(byte[] authData, byte[] clientDataJson) throws Exception {
        byte[] cdHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
        ByteArrayOutputStream out = new ByteArrayOutputStream(authData.length + cdHash.length);
        out.write(authData);
        out.write(cdHash);
        return out.toByteArray();
    }

    @Test
    void signatureVerifiesUnderStandardJcaVerifier() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] signedInput = signedInput(authData, clientData);

        byte[] sig = signer.sign(signedInput);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(signedInput);
        assertTrue(verifier.verify(sig), "DER signature must verify under standard JCA SHA256withECDSA");
    }

    /**
     * The named oracle: verify under webauthn4j's own ES256 Signature, with the public key
     * recovered through our COSE-key encode path → webauthn4j's COSE decode → {@code getPublicKey()}.
     * This exercises {@code Es256Signer.publicCoseKey()} + {@code Webauthn4jCborCodec.encodeCoseKey} and
     * proves the substitute key we would put on the wire matches the private key we sign with.
     */
    @Test
    void signatureVerifiesUnderWebauthn4jVerifierViaRoundTrippedCoseKey() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] signedInput = signedInput(authData, clientData);
        byte[] sig = signer.sign(signedInput);

        // our public COSE key -> CBOR (codec encode) -> webauthn4j COSE decode -> JCA PublicKey
        CoseKey ourKey = signer.publicCoseKey();
        CborCodec codec = new Webauthn4jCborCodec();
        byte[] coseCbor = codec.encodeCoseKey(ourKey);
        COSEKey w4jKey = Fixtures.decodeCoseKey(coseCbor);
        PublicKey recovered = w4jKey.getPublicKey();

        Signature w4jVerifier = SignatureUtil.createES256(); // webauthn4j's own Signature instance
        w4jVerifier.initVerify(recovered);
        w4jVerifier.update(signedInput);
        assertTrue(w4jVerifier.verify(sig),
                "signature must verify under webauthn4j's ES256 verifier using the round-tripped COSE key");
    }

    /** A tampered signed-input must NOT verify - confirms the oracle actually discriminates. */
    @Test
    void verifierRejectsTamperedInput() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] signedInput = signedInput(authData, clientData);
        byte[] sig = signer.sign(signedInput);

        byte[] tampered = signedInput.clone();
        tampered[0] ^= 0x01; // flip a bit in the rpIdHash

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(tampered);
        assertTrue(!verifier.verify(sig), "a tampered input must not verify (negative control)");
    }

    /** The DER signature is parseable and variable-length (>64), and we never assert ==72. */
    @Test
    void signatureIsDerParseableAndVariableLength() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] sig = signer.sign(signedInput(authData, clientData));

        assertTrue(sig.length > 64, "ES256 DER Ecdsa-Sig-Value is > 64 bytes (never assert ==72): len=" + sig.length);
        assertTrue(isDerEcdsaSigValue(sig), "signature must be a parseable DER SEQUENCE of two INTEGERs");
    }

    /**
     * Repeated signings produce DER of (potentially) different total length but each verifies - guards
     * against any latent fixed-length assumption and exercises leading-zero r/s DER encodings over many
     * trials.
     */
    @Test
    void manySignaturesAllVerifyAndAreDerEvenWhenShort() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");
        byte[] signedInput = signedInput(authData, clientData);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        for (int i = 0; i < 64; i++) {
            byte[] sig = signer.sign(signedInput);
            assertTrue(isDerEcdsaSigValue(sig), "iteration " + i + ": not DER");
            assertTrue(sig.length > 64, "iteration " + i + ": DER len must be > 64, was " + sig.length);
            verifier.initVerify(signer.keyPair().getPublic());
            verifier.update(signedInput);
            assertTrue(verifier.verify(sig), "iteration " + i + ": signature failed to verify");
        }
    }

    // ---- minimal DER ECDSA-Sig-Value structural check ------------------------------------------

    /**
     * Structurally validate an ASN.1 DER {@code Ecdsa-Sig-Value} (RFC 3279):
     * {@code SEQUENCE { INTEGER r, INTEGER s }} with the declared SEQUENCE length consuming exactly the
     * whole buffer and two well-formed INTEGER TLVs inside. Deliberately independent of JCA so it is a
     * true second opinion on the wire bytes.
     */
    private static boolean isDerEcdsaSigValue(byte[] der) {
        try {
            int i = 0;
            if (der[i++] != 0x30) {
                return false; // SEQUENCE
            }
            int seqLen = der[i] & 0xFF;
            if (seqLen < 0x80) {
                i += 1;
            } else if (seqLen == 0x81) {
                seqLen = der[i + 1] & 0xFF;
                i += 2;
            } else {
                return false; // ECDSA P-256 sig length never needs a 2-byte length
            }
            if (i + seqLen != der.length) {
                return false; // SEQUENCE must span exactly the buffer
            }
            int[] next = readInteger(der, i);
            if (next == null) {
                return false; // r
            }
            next = readInteger(der, next[0]);
            if (next == null) {
                return false; // s
            }
            return next[0] == der.length; // exactly two INTEGERs, nothing trailing
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Read a DER INTEGER TLV at {@code off}; return {@code {endOffset}} or null if malformed. */
    private static int[] readInteger(byte[] der, int off) {
        if (off >= der.length || der[off] != 0x02) {
            return null; // INTEGER tag
        }
        int len = der[off + 1] & 0xFF;
        if (len == 0 || len >= 0x80) {
            return null; // r/s for P-256 fit a single-byte length and are non-empty
        }
        int contentStart = off + 2;
        int end = contentStart + len;
        if (end > der.length) {
            return null;
        }
        // Reject a redundant leading 0x00 (DER minimal encoding) unless needed for the sign bit.
        if (len > 1 && der[contentStart] == 0x00 && (der[contentStart + 1] & 0x80) == 0) {
            return null;
        }
        return new int[]{end};
    }
}
