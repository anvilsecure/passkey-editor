package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.util.AuthDataEditor;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * the assertion forge engine. The signed input must be exactly
 * {@code authData ‖ SHA-256(clientDataJSON)}, and a signature produced over (possibly edited) bytes must
 * verify under an independent JCA verifier with the signer's public key - i.e. an RP that stored our key
 * would accept it. The edited-bytes cases prove the lossless property: we sign precisely what we put on
 * the wire, so a flipped UV flag or a swapped origin is honoured with no re-encode.
 */
class AssertionForgerTest {

    private final AssertionForger forger = new AssertionForger();

    private static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private static boolean verifies(byte[] signedInput, byte[] sig, Es256Signer signer) throws Exception {
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(signer.keyPair().getPublic());
        v.update(signedInput);
        return v.verify(sig);
    }

    @Test
    void signedInputIsAuthDataConcatClientDataHash() throws Exception {
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");

        byte[] input = AssertionForger.signedInput(authData, clientData);

        assertEquals(authData.length + 32, input.length, "authData ‖ 32-byte SHA-256");
        assertArrayEquals(authData, Arrays.copyOfRange(input, 0, authData.length), "authData prefix verbatim");
        assertArrayEquals(sha256(clientData), Arrays.copyOfRange(input, authData.length, input.length),
                "clientDataJSON hash suffix");
    }

    @Test
    void forgedSignatureVerifiesUnderTheSignersPublicKey() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");

        byte[] sig = forger.sign(authData, clientData, signer);

        assertTrue(sig.length > 64, "ES256 DER Ecdsa-Sig-Value is > 64 bytes (never assume ==72)");
        assertTrue(verifies(AssertionForger.signedInput(authData, clientData), sig, signer),
                "forged signature verifies under the signer's own public key");
    }

    @Test
    void signsOverAFlagEditedAuthData() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData("localhost", (byte) 0x05, 7L); // UP|UV
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");

        // Clear the UV bit (0x05 -> 0x01) and re-sign over the edited authData.
        byte[] edited = AuthDataEditor.withFlags(authData, AuthenticatorData.FLAG_UP);
        assertEquals((byte) 0x01, edited[32], "UV cleared in the edited authData");

        byte[] sig = forger.sign(edited, clientData, signer);
        assertTrue(verifies(AssertionForger.signedInput(edited, clientData), sig, signer),
                "signature covers the edited (UV=0) authData");
    }

    @Test
    void signsOverAnOriginEditedClientData() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData();
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");

        // Swap the origin byte-surgically (the #3 origin-mutation attack), then re-sign.
        int[] span = JsonValueEditor.findStringValueSpan(clientData, "origin");
        byte[] edited = JsonValueEditor.splice(clientData, span, "https://evil.example".getBytes());

        byte[] sig = forger.sign(authData, edited, signer);
        assertTrue(verifies(AssertionForger.signedInput(authData, edited), sig, signer),
                "signature covers the edited-origin clientDataJSON");
        // And the same signature does NOT verify over the ORIGINAL clientData (the edit really took).
        assertTrue(!verifies(AssertionForger.signedInput(authData, clientData), sig, signer),
                "the forged signature is bound to the edited origin, not the original");
    }

    @Test
    void signsOverASignCountEditedAuthData() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] authData = Fixtures.assertionAuthData("localhost", (byte) 0x05, 7L);
        byte[] clientData = Fixtures.clientDataJson("webauthn.get");

        // signCount is a first-class inline edit inside the signed bytes - prove the sig is bound to it.
        byte[] edited = AuthDataEditor.withSignCount(authData, 0x7FFFFFFFL);
        byte[] sig = forger.sign(edited, clientData, signer);

        assertTrue(verifies(AssertionForger.signedInput(edited, clientData), sig, signer),
                "signature covers the signCount-edited authData");
        assertTrue(!verifies(AssertionForger.signedInput(authData, clientData), sig, signer),
                "the forged signature is bound to the edited signCount, not the original");
    }

    @Test
    void nullInputsAreRejected() {
        Es256Signer signer = Es256Signer.generate();
        assertThrows(IllegalArgumentException.class,
                () -> forger.sign(null, Fixtures.clientDataJson("webauthn.get"), signer));
        assertThrows(IllegalArgumentException.class,
                () -> forger.sign(Fixtures.assertionAuthData(), null, signer));
    }
}
