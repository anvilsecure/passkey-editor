package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.model.AttestationObject;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The packed self-attestation oracle. Proves that the registration key-plant, when it emits a packed
 * self-attestation, produces an attestation a relying party accepts - and that this holds for MULTIPLE
 * algorithms (not just ES256), i.e. the feature is algorithm-agnostic and relying-party-agnostic.
 *
 * Two independent oracles, mirroring {@code ForgeryOracleTest}'s discipline:
 *   - T1 - spec oracle (multi-alg): feed the produced registration to webauthn4j's real
 *       {@link PackedAttestationStatementVerifier} wired with only the trust anchors nulled
 *       ({@link NullCertPathTrustworthinessVerifier} + {@link NullSelfAttestationTrustworthinessVerifier}) -
 *       i.e. self-attestation ALLOWED with NO trust anchor. This actually checks the signature (the
 *       {@code createNonStrict...} manager uses a NULL packed verifier that would not), for ES256, RS256, and
 *       EdDSA.
 *   - T2 - generic SHA-256/DER parity: for ES256, independently verify the {@code attStmt} DER
 *       signature over {@code authData ‖ SHA-256(clientDataJSON)} with the embedded P-256 key using a plain
 *       JCA {@code SHA256withECDSA} verifier - how a PHP/openssl RP (the lubu.ch class of target) checks a
 *       self-attestation.
 * Plus T3 (AAGUID zeroed) and T4 (attStmt shape = {@code {alg,sig}}, no x5c, alg == credential-key alg).
 */
class SelfAttestationOracleTest {

    private static final String RP_ID = "example.org";
    private static final String ORIGIN = "https://example.org";

    private final CborCodec cbor = new Webauthn4jCborCodec();

    /** A fixed 32-byte challenge (arbitrary bytes; WebAuthn challenges are opaque). */
    private static byte[] challenge() {
        return sha256("self-attestation-oracle-challenge".getBytes(StandardCharsets.UTF_8));
    }

    /** A create-phase clientDataJSON binding {@link #challenge()} + {@link #ORIGIN}. */
    private static byte[] createClientData() {
        String json = "{\"type\":\"webauthn.create\",\"challenge\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(challenge())
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Plant {@code signer}'s key as a packed self-attestation into a base registration whose rpIdHash is
     * SHA-256({@link #RP_ID}) - so the produced object is self-consistent for the webauthn4j oracle. Exercises
     * the code under test ({@link RegistrationSubstituter#substituteSelfAttestedAndEncode}).
     */
    private byte[] packedSelfAttestation(CoseSigner signer, byte[] clientDataJson) {
        AttestationObject base = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256())); // rpIdHash = SHA-256("example.org")
        return new RegistrationSubstituter(cbor).substituteSelfAttestedAndEncode(base, signer, clientDataJson);
    }

    /** webauthn4j with the REAL packed verifier but NO trust anchor - self-attestation accepted, sig checked. */
    private static WebAuthnManager selfAttestationOracle() {
        return new WebAuthnManager(
                List.of(new PackedAttestationStatementVerifier()),
                new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier(),
                new ObjectConverter());
    }

    // ---- T1: spec oracle, multi-algorithm ------------------------------------------------------

    @Test
    void webauthn4jAcceptsPackedSelfAttestationForMultipleAlgorithms() {
        WebAuthnManager oracle = selfAttestationOracle();
        // Deliberately spans EC (DER sig), RSA (raw PKCS#1 sig), and OKP (raw Ed25519 sig) - three distinct
        // wire forms - proving the mode is not tied to ES256 or any single algorithm family.
        for (SignerAlgorithm alg : List.of(SignerAlgorithm.ES256, SignerAlgorithm.RS256, SignerAlgorithm.EDDSA)) {
            CoseSigner signer = alg.generate();
            byte[] clientDataJson = createClientData();
            byte[] attestationObject = packedSelfAttestation(signer, clientDataJson);

            RegistrationRequest request = new RegistrationRequest(attestationObject, clientDataJson);
            ServerProperty serverProperty = new ServerProperty(
                    Origin.create(ORIGIN), RP_ID, new DefaultChallenge(challenge()), null);
            // userVerificationRequired / userPresenceRequired both false: this oracle checks the ATTESTATION,
            // not RP policy (the base fixture sets UP|UV anyway).
            RegistrationParameters params = new RegistrationParameters(serverProperty, null, false, false);

            assertDoesNotThrow(() -> oracle.verify(request, params),
                    alg.label() + " packed self-attestation must be accepted (self-attestation, no trust anchor)");
        }
    }

    @Test
    void webauthn4jRejectsTamperedSelfAttestationForMultipleAlgorithms() {
        // Negative control across ALL tested algorithms: the attStmt sig must ACTUALLY be checked by this
        // oracle for each alg (so the multi-alg ACCEPTANCE in T1 is not vacuous). For each alg, build a valid
        // self-attestation then swap the embedded credential key for a DIFFERENT key OF THE SAME ALG - alg
        // still matches (so it's not an alg-mismatch rejection), only the signature no longer matches the
        // embedded key. A discriminating verifier must reject all three.
        WebAuthnManager oracle = selfAttestationOracle();
        for (SignerAlgorithm alg : List.of(SignerAlgorithm.ES256, SignerAlgorithm.RS256, SignerAlgorithm.EDDSA)) {
            CoseSigner signer = alg.generate();
            CoseSigner other = alg.generate(); // same algorithm, different key
            byte[] clientDataJson = createClientData();

            AttestationObject base = cbor.decodeAttestationObject(
                    Fixtures.registrationAttestationObject(Fixtures.generateP256()));
            new RegistrationSubstituter(cbor).substituteSelfAttested(base, signer, clientDataJson);
            // Tamper: replace the embedded credential key with another same-alg key (breaks the sig), then
            // re-encode. The authData raw shadow is dropped so the new key is emitted.
            base.authData().setCredentialPublicKey(other.publicCoseKey());
            base.authData().setRaw(null);
            byte[] tampered = cbor.encodeAttestationObject(base);

            RegistrationRequest request = new RegistrationRequest(tampered, clientDataJson);
            ServerProperty serverProperty = new ServerProperty(
                    Origin.create(ORIGIN), RP_ID, new DefaultChallenge(challenge()), null);
            RegistrationParameters params = new RegistrationParameters(serverProperty, null, false, false);
            assertTrue(runThrows(() -> oracle.verify(request, params)),
                    alg.label() + ": a self-attestation whose sig does not match the embedded key must be rejected");
        }
    }

    // ---- T2: generic SHA-256 / DER parity (openssl-style RP) ------------------------------------

    @Test
    void es256SelfAttestationDerSigVerifiesWithEmbeddedKey() throws Exception {
        CoseSigner signer = SignerAlgorithm.ES256.generate();
        byte[] clientDataJson = createClientData();
        byte[] attestationObject = packedSelfAttestation(signer, clientDataJson);

        // Independently parse what was EMITTED (webauthn4j converters as the neutral parser).
        AttestationObjectConverter aoc = new AttestationObjectConverter(new ObjectConverter());
        com.webauthn4j.data.attestation.AttestationObject parsed = aoc.convert(attestationObject);
        PackedAttestationStatement stmt = (PackedAttestationStatement) parsed.getAttestationStatement();
        assertNull(stmt.getX5c(), "self-attestation carries no x5c chain");

        byte[] derSig = stmt.getSig();
        // ECDSA wire-form discipline: an ASN.1 DER Ecdsa-Sig-Value, NOT a raw 64-byte r||s.
        assertNotEquals(64, derSig.length, "ES256 attestation sig must be DER, not raw 64B r||s");
        assertEquals(0x30, derSig[0] & 0xFF, "DER SEQUENCE tag");

        byte[] authData = aoc.extractAuthenticatorData(attestationObject);
        PublicKey embedded = parsed.getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getPublicKey();

        // Exactly how a PHP/openssl RP checks self-attestation: SHA256withECDSA over authData ‖ SHA-256(cdj).
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(embedded);
        verifier.update(concat(authData, sha256(clientDataJson)));
        assertTrue(verifier.verify(derSig),
                "the packed self-attestation DER sig verifies over authData ‖ SHA-256(clientDataJSON)");
    }

    // ---- T3: AAGUID zeroed ---------------------------------------------------------------------

    @Test
    void aaguidIsZeroed() {
        byte[] attestationObject = packedSelfAttestation(SignerAlgorithm.ES256.generate(), createClientData());
        byte[] aaguid = cbor.decodeAttestationObject(attestationObject).authData().aaguid();
        assertArrayEquals(new byte[16], aaguid, "packed self-attestation must zero the 16-byte AAGUID");
    }

    // ---- T4: attStmt shape = {alg,sig}, no x5c, alg == credential-key alg -----------------------

    @Test
    void attStmtIsAlgSigNoX5cAndAlgMatchesEmbeddedKey() throws Exception {
        for (SignerAlgorithm alg : List.of(SignerAlgorithm.ES256, SignerAlgorithm.RS256, SignerAlgorithm.EDDSA)) {
            CoseSigner signer = alg.generate();
            byte[] attestationObject = packedSelfAttestation(signer, createClientData());

            // The attStmt EMITTED on the wire (inside the ACTUAL attestationObject produced by the code under
            // test) must be a DEFINITE-length map of exactly two entries (0xA2 ...) - strict-parser-safe for a
            // PHP/openssl RP. Parse the raw attestationObject CBOR directly with an INDEPENDENT scan (NOT
            // decodeAttestationObject().attStmtRaw(): webauthn4j's extractAttestationStatement RE-SERIALISES it
            // to an INDEFINITE-length map 0xBF on read-back, which would hide a regression to indefinite here).
            assertEquals(0xA2, onWireAttStmtFirstByte(attestationObject) & 0xFF,
                    alg.label() + ": on-wire attStmt is a 2-entry DEFINITE-length CBOR map (no x5c key)");

            // Parsed: alg present, sig present, no x5c; alg == signer alg == embedded credential-key alg.
            AttestationObjectConverter aoc = new AttestationObjectConverter(new ObjectConverter());
            com.webauthn4j.data.attestation.AttestationObject parsed = aoc.convert(attestationObject);
            PackedAttestationStatement stmt = (PackedAttestationStatement) parsed.getAttestationStatement();
            assertNull(stmt.getX5c(), alg.label() + ": no x5c");
            assertEquals(signer.coseAlg(), (int) stmt.getAlg().getValue(), alg.label() + ": attStmt alg == signer alg");
            COSEKey credentialKey = parsed.getAuthenticatorData().getAttestedCredentialData().getCOSEKey();
            assertEquals(signer.coseAlg(), (int) credentialKey.getAlgorithm().getValue(),
                    alg.label() + ": attStmt alg == embedded credential-key alg (WebAuthn §8.2)");
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    /**
     * The first byte of the attStmt VALUE as it sits in the raw attestationObject CBOR - found by an
     * independent scan for the CBOR text-string key "attStmt" (0x67 + ASCII), so it reflects the actual wire
     * framing rather than any re-serialisation. 0xA2 = a definite-length 2-entry map; 0xBF = indefinite.
     */
    private static int onWireAttStmtFirstByte(byte[] attestationObject) {
        byte[] key = {0x67, 'a', 't', 't', 'S', 't', 'm', 't'}; // CBOR tstr(7) "attStmt"
        outer:
        for (int i = 0; i + key.length < attestationObject.length; i++) {
            for (int j = 0; j < key.length; j++) {
                if (attestationObject[i + j] != key[j]) {
                    continue outer;
                }
            }
            return attestationObject[i + key.length] & 0xFF;
        }
        throw new IllegalStateException("attStmt key not found in attestationObject CBOR");
    }

    private static boolean runThrows(Runnable r) {
        try {
            r.run();
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(a.length + b.length);
        bo.writeBytes(a);
        bo.writeBytes(b);
        return bo.toByteArray();
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
