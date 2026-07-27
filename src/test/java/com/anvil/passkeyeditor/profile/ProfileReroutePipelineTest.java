package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.attacks.AssertionForger;
import com.anvil.passkeyeditor.attacks.RegistrationSubstituter;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.util.JsonValueEditor;
import java.io.IOException;
import java.io.InputStream;
import java.security.Signature;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Proves the rerouted editor's write path on a deeply-nested RP - webauthn.io, the capture that
 * originally broke (fields at {@code response.response.X}). Mirrors what {@code CeremonyRequestEditor}
 * does for a re-sign: profile-locate each field's span, unwrap, forge a fresh ES256 assertion over
 * (authData, clientDataJSON) with a key we hold, re-wrap, splice back at the profile span - then
 * re-parses the emitted body via the SAME profile and checks the forged signature (a) re-locates, (b)
 * verifies under our key, and (c) left every other nested field byte-identical.
 *
 * A fresh DER signature is variable-length, so the spliced body differs in length from the capture -
 * the structural locator must still find it (variable-length-DER concern, now across nesting).
 */
class ProfileReroutePipelineTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();
    private final ProfileRegistry registry = RpFixtureProfiles.seededRegistry();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = ProfileReroutePipelineTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    private static byte[] slice(byte[] b, int[] span) {
        return Arrays.copyOfRange(b, span[0], span[1]);
    }

    @Test
    void reSignRoundTripOnNestedWebauthnIo() throws Exception {
        byte[] body = load("webauthn-io-auth");
        PhaseSpec spec = registry.resolve("webauthn.io", Phase.AUTH_VERIFY);

        int[] adSpan = spec.locate(Field.AUTHENTICATOR_DATA, body);
        int[] cdSpan = spec.locate(Field.CLIENT_DATA_JSON, body);
        int[] sigSpan = spec.locate(Field.SIGNATURE, body);
        assertNotNull(adSpan, "authenticatorData located at response.response.authenticatorData");
        assertNotNull(cdSpan, "clientDataJSON located at response.response.clientDataJSON");
        assertNotNull(sigSpan, "signature located at response.response.signature");

        byte[] ad = CODEC.unwrap(slice(body, adSpan)).inner();
        byte[] cd = CODEC.unwrap(slice(body, cdSpan)).inner();
        WrapperCodec.Unwrapped sigUw = CODEC.unwrap(slice(body, sigSpan));

        // Forge: re-sign (authData, clientDataJSON) with a fresh key we hold (the post-substitution attack).
        Es256Signer signer = Es256Signer.generate();
        byte[] forgedSig = new AssertionForger().sign(ad, cd, signer);
        assertEquals((byte) 0x30, forgedSig[0], "ES256 forgery is a DER signature");

        // Re-wrap as the original signature field was wrapped, splice back at its nested span.
        byte[] wireSig = CODEC.rewrap(forgedSig, sigUw.spec());
        byte[] newBody = JsonValueEditor.splice(body, sigSpan, wireSig);

        // Re-locate via the SAME profile on the EMITTED (different-length) body - it must round-trip.
        int[] newSigSpan = spec.locate(Field.SIGNATURE, newBody);
        assertNotNull(newSigSpan, "forged signature re-locates on the spliced nested body");
        byte[] relocated = CODEC.unwrap(slice(newBody, newSigSpan)).inner();
        assertArrayEquals(forgedSig, relocated, "forged signature survives nested re-wrap + splice round-trip");

        // The forgery actually verifies under our key over authData || SHA-256(clientDataJSON).
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(AssertionForger.signedInput(ad, cd));
        assertTrue(verifier.verify(relocated), "re-signed nested assertion verifies under our key");

        // Surgical: the other nested fields are untouched, and the head/tail outside the splice are verbatim.
        assertArrayEquals(ad, CODEC.unwrap(slice(newBody, spec.locate(Field.AUTHENTICATOR_DATA, newBody))).inner(),
                "authenticatorData unchanged");
        assertArrayEquals(cd, CODEC.unwrap(slice(newBody, spec.locate(Field.CLIENT_DATA_JSON, newBody))).inner(),
                "clientDataJSON unchanged");
        assertArrayEquals(Arrays.copyOfRange(body, 0, sigSpan[0]), Arrays.copyOfRange(newBody, 0, sigSpan[0]),
                "body before the signature is byte-identical");
        assertArrayEquals(Arrays.copyOfRange(body, sigSpan[1], body.length),
                Arrays.copyOfRange(newBody, sigSpan[0] + wireSig.length, newBody.length),
                "body after the signature (userHandle, closing braces) is byte-identical");
    }

    /**
     * The CREATE-side symmetry of the above: key SUBSTITUTION on webauthn.io's nested registration. Mirrors
     * Attacks ▾ → "Register with our key" - profile-locate the nested attestationObject, decode, substitute
     * our ES256 key + force fmt="none", re-encode (a DIFFERENT-length CBOR - the OKP→EC2 swap shrinks it),
     * re-wrap, splice back, then re-locate + decode on the emitted body and confirm our key is embedded with
     * the victim's credentialId preserved and the rest of the nested body byte-identical.
     */
    @Test
    void keySubstitutionRoundTripOnNestedWebauthnIo() throws Exception {
        byte[] body = load("webauthn-io-reg");
        PhaseSpec spec = registry.resolve("webauthn.io", Phase.REG_VERIFY);
        int[] attSpan = spec.locate(Field.ATTESTATION_OBJECT, body);
        assertNotNull(attSpan, "attestationObject located at response.response.attestationObject");

        CborCodec cbor = new Webauthn4jCborCodec();
        WrapperCodec.Unwrapped attUw = CODEC.unwrap(slice(body, attSpan));
        AttestationObject att = cbor.decodeAttestationObject(attUw.inner());
        byte[] originalCredId = att.authData().credentialId().clone();

        // Substitute our ES256 key (the post-substitution attack plants the key we hold).
        Es256Signer attacker = Es256Signer.generate();
        byte[] substituted = new RegistrationSubstituter(cbor).substituteAndEncode(att, attacker);

        byte[] wireAtt = CODEC.rewrap(substituted, attUw.spec());
        byte[] newBody = JsonValueEditor.splice(body, attSpan, wireAtt);

        int[] newAttSpan = spec.locate(Field.ATTESTATION_OBJECT, newBody);
        assertNotNull(newAttSpan, "substituted attestationObject re-locates on the spliced nested body");
        AttestationObject reDecoded = cbor.decodeAttestationObject(CODEC.unwrap(slice(newBody, newAttSpan)).inner());
        assertEquals("none", reDecoded.fmt(), "attestation forced to fmt=none");
        assertEquals(2, reDecoded.authData().credentialPublicKey().kty(), "our EC2 key (kty=2)");
        assertEquals(-7, reDecoded.authData().credentialPublicKey().alg(), "our ES256 key (alg=-7)");
        assertArrayEquals(attacker.publicCoseKey().raw(), reDecoded.authData().credentialPublicKey().raw(),
                "the embedded credential public key is ours");
        assertArrayEquals(originalCredId, reDecoded.authData().credentialId(), "victim credentialId preserved");

        // Surgical: clientDataJSON (later in the body) unchanged; head + tail outside the splice verbatim.
        byte[] cd = CODEC.unwrap(slice(body, spec.locate(Field.CLIENT_DATA_JSON, body))).inner();
        assertArrayEquals(cd, CODEC.unwrap(slice(newBody, spec.locate(Field.CLIENT_DATA_JSON, newBody))).inner(),
                "clientDataJSON unchanged");
        assertArrayEquals(Arrays.copyOfRange(body, 0, attSpan[0]), Arrays.copyOfRange(newBody, 0, attSpan[0]),
                "body before attestationObject is byte-identical");
        assertArrayEquals(Arrays.copyOfRange(body, attSpan[1], body.length),
                Arrays.copyOfRange(newBody, attSpan[0] + wireAtt.length, newBody.length),
                "body after attestationObject is byte-identical");
    }
}
