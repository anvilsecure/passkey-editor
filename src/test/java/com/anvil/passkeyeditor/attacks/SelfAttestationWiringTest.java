package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.Encodings;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.PlantAttestation;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Proves the {@link PlantAttestation} selection is honoured through BOTH shared plant paths - the AUTO
 * handler's {@link ReSignEngine#plantRegistration} and the manual editor's {@link RegistrationEditor#edit} -
 * and that the default stays {@code fmt="none"} (freeze-safe). Also pins that a packed self-attestation signs
 * over the FINAL authData when {@code credentialId}/flags are edited in the same pass.
 *
 * Signature correctness is checked with a plain JCA {@code SHA256withECDSA} verifier over the EMITTED
 * bytes (the openssl-style RP check), keyed on the exact signer passed in - the strongest oracle without Burp.
 */
class SelfAttestationWiringTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();
    private final PhaseSpec regSpec = BuiltinProfiles.defaultProfile().phase(Phase.REG_VERIFY);

    // ---- AUTO path: ReSignEngine.plantRegistration --------------------------------------------

    @Test
    void enginePlantPackedSelfEmitsPackedAndSigVerifies() throws Exception {
        byte[] body = loadFixture("reg-clean.json");
        Es256Signer signer = Es256Signer.generate();

        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, signer, PlantAttestation.PACKED_SELF);
        assertTrue(r.changed(), "packed self-attestation plant changes the body");

        byte[] emittedAttObj = wrapper.unwrap(wrappedValue(r.body(), "attestationObject")).inner();
        assertEquals("packed", cbor.decodeAttestationObject(emittedAttObj).fmt(), "engine honoured PACKED_SELF");

        // The signature must verify over the EMITTED authData ‖ SHA-256(the registration's clientDataJSON).
        byte[] clientDataJson = Encodings.decode(wrapper,
                slice(body, regSpec.locate(Field.CLIENT_DATA_JSON, body)),
                regSpec.locator(Field.CLIENT_DATA_JSON).encoding()).inner();
        assertSelfAttestationSigVerifies(emittedAttObj, clientDataJson, signer);
    }

    @Test
    void enginePlantMultiAlgAllEmitPackedAndSigVerifies() throws Exception {
        // Algorithm-agnostic THROUGH THE SHARED ENGINE PATH: EC / RSA / OKP all emit fmt=packed AND the
        // emitted self-attestation signature verifies with the signer's own key (not merely fmt=packed), so
        // an alg-specific corruption in the engine's post-substituter rewrap/splice would be caught.
        byte[] body = loadFixture("reg-clean.json");
        byte[] clientDataJson = Encodings.decode(wrapper,
                slice(body, regSpec.locate(Field.CLIENT_DATA_JSON, body)),
                regSpec.locator(Field.CLIENT_DATA_JSON).encoding()).inner();
        for (SignerAlgorithm alg : List.of(SignerAlgorithm.ES256, SignerAlgorithm.RS256, SignerAlgorithm.EDDSA)) {
            CoseSigner signer = alg.generate();
            ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, signer,
                    PlantAttestation.PACKED_SELF);
            assertTrue(r.changed(), alg.label() + ": plant changed the body");
            byte[] emitted = wrapper.unwrap(wrappedValue(r.body(), "attestationObject")).inner();
            assertEquals("packed", cbor.decodeAttestationObject(emitted).fmt(),
                    alg.label() + ": engine emits packed self-attestation");
            assertSelfAttestationSigVerifies(emitted, clientDataJson, signer);
        }
    }

    @Test
    void enginePlantPackedSelfIsNoOpWhenClientDataNotLocatable() {
        // A registration body with a locatable attestationObject but NO clientDataJSON: packed self-attestation
        // has nothing to sign over, so the shared engine path is a safe no-op (never signs over empty bytes).
        byte[] body = ("{\"attestationObject\":\""
                + Fixtures.b64url(Fixtures.registrationAttestationObject(Fixtures.generateP256()))
                + "\"}").getBytes(StandardCharsets.UTF_8);
        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, Es256Signer.generate(),
                PlantAttestation.PACKED_SELF);
        assertFalse(r.changed(), "no locatable clientDataJSON ⇒ packed self-attestation is a no-op");
        assertArrayEquals(body, r.body(), "a no-op returns the byte-identical original body");
        assertTrue(r.detail() != null && r.detail().contains("clientDataJSON"),
                "the skip reason names the missing clientDataJSON");
    }

    @Test
    void enginePlantNoneEmitsNone() {
        byte[] body = loadFixture("reg-clean.json");
        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, Es256Signer.generate(),
                PlantAttestation.NONE);
        assertTrue(r.changed());
        byte[] emitted = wrapper.unwrap(wrappedValue(r.body(), "attestationObject")).inner();
        assertEquals("none", cbor.decodeAttestationObject(emitted).fmt(), "NONE mode still forces fmt=none");
    }

    @Test
    void enginePlantThreeArgDefaultsToNone() {
        // Back-compat: the pre-existing 3-arg entry point must behave exactly as before (fmt=none).
        byte[] body = loadFixture("reg-clean.json");
        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, Es256Signer.generate());
        assertTrue(r.changed());
        byte[] emitted = wrapper.unwrap(wrappedValue(r.body(), "attestationObject")).inner();
        assertEquals("none", cbor.decodeAttestationObject(emitted).fmt(), "3-arg plant defaults to fmt=none");
    }

    // ---- manual path: RegistrationEditor.edit -------------------------------------------------

    @Test
    void editorPackedSelfEmitsPackedZeroesAaguidAndSigVerifies() throws Exception {
        Es256Signer signer = Es256Signer.generate();
        byte[] clientDataJson = Fixtures.clientDataJson("webauthn.create");
        AttestationObject attObj = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));

        byte[] wire = new RegistrationEditor(cbor)
                .edit(attObj, signer, null, null, PlantAttestation.PACKED_SELF, clientDataJson);

        AttestationObject decoded = cbor.decodeAttestationObject(wire);
        assertEquals("packed", decoded.fmt(), "manual editor honoured PACKED_SELF");
        assertArrayEquals(new byte[16], decoded.authData().aaguid(), "manual packed self-attestation zeroes AAGUID");
        assertSelfAttestationSigVerifies(wire, clientDataJson, signer);
    }

    @Test
    void editorPackedSelfSignsOverEditedCredIdAndFlags() throws Exception {
        // A packed self-attestation must sign the FINAL authData, so a same-pass credentialId + flags edit is
        // covered by the signature (else a strict RP would reject it).
        Es256Signer signer = Es256Signer.generate();
        byte[] clientDataJson = Fixtures.clientDataJson("webauthn.create");
        AttestationObject attObj = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));

        byte[] newCredId = new byte[]{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
        int newFlags = AuthenticatorData.FLAG_UP | AuthenticatorData.FLAG_UV | AuthenticatorData.FLAG_BE
                | AuthenticatorData.FLAG_AT; // 0x4D - AT preserved, BE added
        byte[] wire = new RegistrationEditor(cbor)
                .edit(attObj, signer, newCredId, newFlags, PlantAttestation.PACKED_SELF, clientDataJson);

        AttestationObject decoded = cbor.decodeAttestationObject(wire);
        assertEquals("packed", decoded.fmt());
        assertArrayEquals(newCredId, decoded.authData().credentialId(), "edited credentialId is emitted");
        assertEquals(newFlags, decoded.authData().flags(), "edited flags are emitted");
        // The signature covers the edited authData (contains newCredId + newFlags).
        assertSelfAttestationSigVerifies(wire, clientDataJson, signer);
    }

    @Test
    void editorNoneAndFourArgDefaultEmitNone() {
        Es256Signer signer = Es256Signer.generate();
        byte[] cdj = Fixtures.clientDataJson("webauthn.create");
        AttestationObject a1 = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));
        AttestationObject a2 = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));

        byte[] noneWire = new RegistrationEditor(cbor).edit(a1, signer, null, null, PlantAttestation.NONE, cdj);
        assertEquals("none", cbor.decodeAttestationObject(noneWire).fmt(), "NONE mode forces fmt=none");

        byte[] fourArgWire = new RegistrationEditor(cbor).edit(a2, signer, null, null); // back-compat 4-arg
        assertEquals("none", cbor.decodeAttestationObject(fourArgWire).fmt(), "4-arg edit defaults to fmt=none");
    }

    @Test
    void editorPackedSelfWithoutClientDataIsRefused() {
        // The manual editor must refuse a packed self-attestation plant with no clientDataJSON to sign over
        // (there is nothing to sign) rather than emit a bogus attestation.
        AttestationObject attObj = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));
        assertThrows(IllegalStateException.class,
                () -> new RegistrationEditor(cbor)
                        .edit(attObj, Es256Signer.generate(), null, null, PlantAttestation.PACKED_SELF, null),
                "packed self-attestation without clientDataJSON must be refused");
    }

    // ---- helpers -------------------------------------------------------------------------------

    /**
     * Verify the emitted packed self-attestation's signature over authData ‖ SHA-256(clientDataJSON) with the
     * signer's OWN public key, using the JCA verifier for the signer's algorithm - so it works for ES256
     * (DER), RS256 (PKCS#1) and EdDSA (Ed25519), not just ES256.
     */
    private void assertSelfAttestationSigVerifies(byte[] attestationObject, byte[] clientDataJson,
                                                  CoseSigner signer) throws Exception {
        AttestationObjectConverter aoc = new AttestationObjectConverter(new ObjectConverter());
        com.webauthn4j.data.attestation.AttestationObject parsed = aoc.convert(attestationObject);
        PackedAttestationStatement stmt = (PackedAttestationStatement) parsed.getAttestationStatement();
        assertNull(stmt.getX5c(), "self-attestation carries no x5c");
        byte[] sig = stmt.getSig();
        byte[] authData = aoc.extractAuthenticatorData(attestationObject);

        Signature v = Signature.getInstance(jcaVerifyAlgorithm(signer.coseAlg()));
        v.initVerify(signer.keyPair().getPublic());
        v.update(concat(authData, sha256(clientDataJson)));
        assertTrue(v.verify(sig), "emitted self-attestation sig verifies over authData ‖ SHA-256(clientDataJSON)");
    }

    /** The JCA Signature algorithm that verifies a signature of the given COSE alg (the algs tested here). */
    private static String jcaVerifyAlgorithm(int coseAlg) {
        return switch (coseAlg) {
            case -7 -> "SHA256withECDSA"; // ES256
            case -257 -> "SHA256withRSA"; // RS256
            case -8 -> "Ed25519";         // EdDSA
            default -> throw new IllegalArgumentException("test verifier does not handle COSE alg " + coseAlg);
        };
    }

    private static byte[] loadFixture(String name) {
        try (InputStream in = SelfAttestationWiringTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] wrappedValue(byte[] body, String field) {
        Matcher m = Pattern.compile("\"" + field + "\":\"([^\"]+)\"")
                .matcher(new String(body, StandardCharsets.UTF_8));
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + field);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] slice(byte[] body, int[] span) {
        return Arrays.copyOfRange(body, span[0], span[1]);
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
