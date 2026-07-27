package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.Encodings;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import com.webauthn4j.util.SignatureUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Gates the Burp-free {@link ReSignEngine} that the AUTO handler drives. The headline gate is byte-equivalence
 * to the editor's canonical locate→unwrap→forge→re-wrap→splice recipe: it uses a deterministic
 * algorithm (EdDSA - RFC 8032 has no random nonce, unlike ECDSA/PSS) so a frozen inline copy of the recipe and
 * the engine produce the identical body; the test fails the instant the engine drifts from the recipe.
 * Plus an ES256 verify (correctness of the variable-length DER path), a no-op guard, and the plant path.
 */
class ReSignEngineWireTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final PhaseSpec authSpec = BuiltinProfiles.defaultProfile().phase(Phase.AUTH_VERIFY);
    private final PhaseSpec regSpec = BuiltinProfiles.defaultProfile().phase(Phase.REG_VERIFY);

    private static byte[] loadFixture(String name) {
        try (InputStream in = ReSignEngineWireTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] wrappedValue(byte[] body, String field) {
        Matcher m = Pattern.compile("\"" + field + "\":\"([^\"]+)\"").matcher(new String(body, StandardCharsets.UTF_8));
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + field);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] slice(byte[] body, int[] span) {
        return Arrays.copyOfRange(body, span[0], span[1]);
    }

    /** The canonical re-sign recipe, inlined + frozen - what the engine must reproduce byte-for-byte. */
    private byte[] canonicalReSign(byte[] body, PhaseSpec spec, CoseSigner signer) {
        int[] sigSpan = spec.locate(Field.SIGNATURE, body);
        int[] adSpan = spec.locate(Field.AUTHENTICATOR_DATA, body);
        int[] cdSpan = spec.locate(Field.CLIENT_DATA_JSON, body);
        WrapperCodec.Unwrapped ad = Encodings.decode(wrapper, slice(body, adSpan), spec.locator(Field.AUTHENTICATOR_DATA).encoding());
        WrapperCodec.Unwrapped cd = Encodings.decode(wrapper, slice(body, cdSpan), spec.locator(Field.CLIENT_DATA_JSON).encoding());
        WrapperCodec.Unwrapped sig = Encodings.decode(wrapper, slice(body, sigSpan), spec.locator(Field.SIGNATURE).encoding());
        byte[] forged = new AssertionForger().sign(ad.inner(), cd.inner(), signer);
        byte[] sigWire = wrapper.rewrap(forged, sig.spec());
        return JsonValueEditor.spliceAll(body, List.of(sigSpan), List.of(sigWire));
    }

    @Test
    void reSignIsByteEquivalentToTheCanonicalRecipe() {
        byte[] body = loadFixture("auth-clean.json");
        // EdDSA is deterministic, so the SAME signer instance signing the same input in both paths yields the
        // SAME bytes - any divergence is a real recipe drift, not nonce randomness.
        CoseSigner signer = SignerAlgorithm.EDDSA.generate();
        byte[] expected = canonicalReSign(body, authSpec, signer);
        ReSignEngine.Result actual = ReSignEngine.reSignAssertion(body, authSpec, signer);
        assertTrue(actual.changed());
        assertArrayEquals(expected, actual.body(), "engine re-sign must equal the canonical recipe byte-for-byte");
        assertEquals(-8, actual.coseAlg());
    }

    @Test
    void reSignEmittedSignatureVerifiesUnderEs256() throws Exception {
        byte[] body = loadFixture("auth-clean.json");
        Es256Signer signer = Es256Signer.generate();
        ReSignEngine.Result r = ReSignEngine.reSignAssertion(body, authSpec, signer);
        assertTrue(r.changed());
        // Recover the inner authData/clientData (unchanged) + the emitted signature, and verify.
        byte[] ad = Encodings.decode(wrapper, slice(body, authSpec.locate(Field.AUTHENTICATOR_DATA, body)),
                authSpec.locator(Field.AUTHENTICATOR_DATA).encoding()).inner();
        byte[] cd = Encodings.decode(wrapper, slice(body, authSpec.locate(Field.CLIENT_DATA_JSON, body)),
                authSpec.locator(Field.CLIENT_DATA_JSON).encoding()).inner();
        byte[] emittedSig = wrapper.unwrap(wrappedValue(r.body(), "signature")).inner();
        Signature v = SignatureUtil.createES256();
        v.initVerify(signer.keyPair().getPublic());
        v.update(AssertionForger.signedInput(ad, cd));
        assertTrue(v.verify(emittedSig), "the engine's emitted signature must verify under the forging key");
    }

    @Test
    void reSignIsANoOpWhenNoSignatureField() {
        byte[] body = "{\"foo\":\"bar\"}".getBytes(StandardCharsets.UTF_8);
        ReSignEngine.Result r = ReSignEngine.reSignAssertion(body, authSpec, Es256Signer.generate());
        assertFalse(r.changed(), "no signature field ⇒ no-op");
        assertArrayEquals(body, r.body(), "a no-op returns the byte-identical original body");
    }

    @Test
    void plantEmbedsOurKeyAndForcesNoneFmt() {
        byte[] body = loadFixture("reg-clean.json");
        CoseSigner signer = SignerAlgorithm.EDDSA.generate();
        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, regSpec, signer);
        assertTrue(r.changed());
        assertNotNull(r.credIdHex(), "the registered credId is reported so the caller stores the planted key");
        CborCodec cbor = new Webauthn4jCborCodec();
        AttestationObject ao = cbor.decodeAttestationObject(wrapper.unwrap(wrappedValue(r.body(), "attestationObject")).inner());
        assertEquals("none", ao.fmt(), "plant forces fmt=\"none\" (undetectable self-attestation)");
        assertNotNull(ao.authData().credentialPublicKey(), "the substituted credential public key is present");
    }

    @Test
    void originHostMirrorsTheClientDataOrigin() throws Exception {
        // The handler keys the store on this (not the HTTP host) so a manual plant + AUTO re-sign match (F7).
        byte[] body = loadFixture("auth-clean.json");
        byte[] cd = Encodings.decode(wrapper, slice(body, authSpec.locate(Field.CLIENT_DATA_JSON, body)),
                authSpec.locator(Field.CLIENT_DATA_JSON).encoding()).inner();
        String origin = com.google.gson.JsonParser.parseString(new String(cd, StandardCharsets.UTF_8))
                .getAsJsonObject().get("origin").getAsString();
        String expected = new java.net.URI(origin).getHost();
        String actual = ReSignEngine.originHost(body, authSpec);
        assertEquals(expected, actual, "originHost must mirror URI(clientData.origin).getHost() (== editor rpIdHost)");
        assertFalse(actual.isEmpty(), "a real assertion has a locatable origin host");
    }

    @Test
    void plantIsByteEquivalentToTheCanonicalRecipe() {
        byte[] body = loadFixture("reg-clean.json");
        CoseSigner signer = SignerAlgorithm.EDDSA.generate(); // deterministic key shape for a fixed key
        // Canonical inline plant recipe.
        int[] attSpan = regSpec.locate(Field.ATTESTATION_OBJECT, body);
        WrapperCodec.Unwrapped att = Encodings.decode(wrapper, slice(body, attSpan), regSpec.locator(Field.ATTESTATION_OBJECT).encoding());
        CborCodec cbor = new Webauthn4jCborCodec();
        AttestationObject ao = cbor.decodeAttestationObject(att.inner());
        byte[] newInner = new RegistrationSubstituter(cbor).substituteAndEncode(ao, signer);
        byte[] expected = JsonValueEditor.spliceAll(body, List.of(attSpan), List.of(wrapper.rewrap(newInner, att.spec())));
        ReSignEngine.Result actual = ReSignEngine.plantRegistration(body, regSpec, signer);
        assertArrayEquals(expected, actual.body(), "engine plant must equal the canonical recipe byte-for-byte");
    }
}
