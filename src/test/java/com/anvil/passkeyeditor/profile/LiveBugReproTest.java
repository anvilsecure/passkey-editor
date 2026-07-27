package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.attacks.RegistrationSubstituter;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.ClientData;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * Headless root-cause of two bugs seen against live relying parties: passkeys-debugger.io
 * authentication behaving erratically, and passkeys.io/Hanko showing an error banner.
 *
 * This test does NOT assert a desired end state - it reproduces the pipeline the editor runs
 * (host → registry → {@code PhaseSpec.locate} → {@code WrapperCodec.unwrap} → decode → forge/substitute)
 * on the real captures and pins down exactly where each ceremony does / does not behave, so the fix and
 * the redesign rest on proven mechanism rather than on guesswork.
 * Each block is annotated with the hypothesis it confirms or refutes.
 *
 * Findings (see assertions): (1) debugger decode + credId resolution are CORRECT on this capture - the
 * credId-substring-scan mis-key hypothesis does NOT reproduce here (every id-ish member holds the same
 * value); the captured assertion is a raw Ed25519 signature, so a plain ES256 re-sign needs a prior
 * "Register with our key" (expectation gap, not a code bug). (2) "Register with our key" rewrites ONLY
 * {@code attestationObject} and leaves the echoed client key material ({@code publicKey} SPKI,
 * {@code publicKeyAlgorithm}, a standalone {@code authenticatorData}) advertising the victim's key - a
 * latent incompleteness. But this is a Chrome {@code toJSON()} artifact present in the WORKING captures
 * too ({@code webauthn-io-reg}, {@code reg-clean}), whose RPs read {@code attestationObject} and
 * ignore the echo - so it is NOT the debugger's discriminator, just a real and noteworthy RP-divergence
 * risk for an RP that trusts client {@code getPublicKey()}. (3) the Hanko captures decode CLEANLY under
 * the matched profile and locate NOTHING under the Default - an unlocated field is silent (no banner), so
 * the "degrade banner from an unlocated field" hypothesis is mechanically refuted; the banner is
 * host-match / live-body specific (needs the real request host + phase to reproduce).
 */
class LiveBugReproTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();
    private static final CborCodec CBOR = new Webauthn4jCborCodec();
    private final ProfileRegistry registry = RpFixtureProfiles.seededRegistry();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = LiveBugReproTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    private static byte[] slice(byte[] b, int[] span) {
        return Arrays.copyOfRange(b, span[0], span[1]);
    }

    private static void diag(String line) {
        System.out.println("REPRO>> " + line);
    }

    /** Replicates {@code CeremonyRequestEditor.credIdHexFromAssertion}: first rawId/id, base64(url|std) → hex. */
    private static String credIdHexFromAssertion(byte[] body) {
        int[] span = JsonValueEditor.findStringValueSpan(body, "rawId");
        if (span == null) {
            span = JsonValueEditor.findStringValueSpan(body, "id");
        }
        if (span == null) {
            return null;
        }
        String token = new String(body, span[0], span[1] - span[0], StandardCharsets.US_ASCII);
        for (Base64.Decoder dec : new Base64.Decoder[]{Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                return HexFormat.of().formatHex(dec.decode(token));
            } catch (RuntimeException ignored) {
                // try next flavor
            }
        }
        return null;
    }

    // =====================================================================================
    // BUG 1 - passkeys-debugger.io authentication "a little buggy"
    // =====================================================================================

    /**
     * Hypotheses (a) Ed25519-default re-sign and (b) credId-substring mis-key, on the AUTH capture.
     * Result: decode is correct; the assertion signature is a RAW 64-byte Ed25519 sig (not DER) - so a
     * plain ES256 re-sign cannot match the RP-stored Ed25519 key without a prior key-substitution
     * (confirms a); and the credId scan resolves the CORRECT credential (refutes b for this capture).
     */
    @Test
    void debuggerAuthDecodesAndResolvesCredIdCorrectly() throws Exception {
        byte[] body = load("passkeys-debugger-auth");
        PhaseSpec spec = registry.resolve("www.passkeys-debugger.io", Phase.AUTH_VERIFY);

        int[] cdSpan = spec.locate(Field.CLIENT_DATA_JSON, body);
        int[] adSpan = spec.locate(Field.AUTHENTICATOR_DATA, body);
        int[] sigSpan = spec.locate(Field.SIGNATURE, body);
        assertNotNull(cdSpan, "clientDataJSON locates at [2].response.response.clientDataJSON");
        assertNotNull(adSpan, "authenticatorData locates at [2].response.response.authenticatorData");
        assertNotNull(sigSpan, "signature locates at [2].response.response.signature");

        ClientData cd = new ClientData(CODEC.unwrap(slice(body, cdSpan)).inner());
        AuthenticatorData ad = CBOR.decodeAuthData(CODEC.unwrap(slice(body, adSpan)).inner());
        byte[] sig = CODEC.unwrap(slice(body, sigSpan)).inner();

        // (decode is correct - these all parse)
        assertNotNull(ad.rpIdHash(), "authData decodes (rpIdHash present) - decode is NOT the bug");
        String origin = clientDataString(cd, "origin");
        assertEquals("https://www.passkeys-debugger.io", origin, "clientDataJSON origin decodes correctly");
        diag("debugger AUTH: clientDataJSON origin = " + origin + ", authData flags=0x"
                + String.format("%02x", ad.flags() & 0xFF) + ", signature length=" + sig.length);

        // (a) The captured signature is a RAW 64-byte Ed25519 signature, NOT a DER Ecdsa-Sig-Value.
        // A DER sig begins with 0x30 (SEQUENCE) and is ~70-72 bytes; Ed25519 is a fixed 64 bytes.
        assertEquals(64, sig.length, "captured assertion sig is a 64-byte raw Ed25519 signature");
        assertTrue((sig[0] & 0xFF) != 0x30, "Ed25519 sig is NOT DER (no 0x30 SEQUENCE prefix)");
        diag("(a) CONFIRMED: assertion is Ed25519 (alg -8). A plain ES256 re-sign won't verify against the "
                + "RP's stored Ed25519 key - it requires a prior 'Register with our key' substitution.");

        // (b) The credId-substring scan: in THIS body every id-ish member holds the same credential value,
        // so the scan resolves the correct credId - the mis-key hypothesis does NOT reproduce here.
        String scanned = credIdHexFromAssertion(body);
        assertNotNull(scanned, "credId scan resolves a value");
        String rawIdValue = stringMember(body, "rawId");
        String expected = HexFormat.of().formatHex(Base64.getUrlDecoder().decode(rawIdValue));
        assertEquals(expected, scanned, "scanned credId == base64url(rawId) - correct credential");
        diag("(b) REFUTED here: credId scan resolved " + scanned.substring(0, 16) + "… == rawId. "
                + "All id-ish members ([2].response.id / .rawId / [2].credentialId) share one value, so no "
                + "mis-key on this capture. The substring scan is still fragile (migrate to the profile).");
    }

    /**
     * Latent incompleteness (NOT the debugger's discriminator): the debugger REGISTRATION ships
     * {@code publicKey} (SPKI), {@code publicKeyAlgorithm}, and a standalone {@code authenticatorData} as
     * SIBLINGS of {@code attestationObject}. "Register with our key" rewrites only {@code attestationObject};
     * the sibling key material is left advertising the victim's Ed25519 key. An RP that trusts the
     * client-asserted {@code getPublicKey()} convenience fields would store the WRONG key and reject our
     * forgeries. However these fields are a Chrome {@code PublicKeyCredential.toJSON()} artifact and
     * are present in the WORKING captures too - {@code webauthn-io-reg} and {@code reg-clean}, whose
     * RPs (py_webauthn, SimpleWebAuthn) accept our forgery (the key-substitution flow is live-proven). So the working
     * RPs read {@code attestationObject} and ignore the echo: the staleness is a genuine correctness gap +
     * noteworthy RP-divergence risk, but it does NOT explain why the debugger differs from webauthn.io.
     */
    @Test
    void debuggerRegistrationSubstitutionLeavesStaleSiblingKeyMaterial() throws Exception {
        byte[] body = load("passkeys-debugger-reg");
        PhaseSpec spec = registry.resolve("www.passkeys-debugger.io", Phase.REG_VERIFY);
        int[] attSpan = spec.locate(Field.ATTESTATION_OBJECT, body);
        assertNotNull(attSpan, "attestationObject locates at [2].response.response.attestationObject");

        WrapperCodec.Unwrapped attUw = CODEC.unwrap(slice(body, attSpan));
        AttestationObject att = CBOR.decodeAttestationObject(attUw.inner());
        assertNotNull(att.authData(), "registration attestationObject decodes");
        assertNotNull(att.authData().credentialPublicKey(), "embedded credential key decodes");
        int origKty = att.authData().credentialPublicKey().kty();
        int origAlg = att.authData().credentialPublicKey().alg();
        diag("debugger REG: attestationObject fmt=" + att.fmt() + ", embedded key kty=" + origKty
                + " alg=" + origAlg + " (kty=1/alg=-8 == OKP/Ed25519)");
        assertEquals(1, origKty, "embedded credential key is OKP (Ed25519)");

        // The redundant sibling key material the body ALSO carries (Chrome getPublicKey()/algorithm +
        // a standalone authenticatorData), all advertising the SAME Ed25519 key.
        String siblingSpki = stringMember(body, "publicKey");
        assertNotNull(siblingSpki, "registration carries a sibling publicKey (SPKI) field");
        assertTrue(new String(body, StandardCharsets.UTF_8).contains("\"publicKeyAlgorithm\":-8"),
                "registration carries publicKeyAlgorithm:-8 (EdDSA)");
        boolean hasStandaloneAuthData = new String(body, StandardCharsets.UTF_8)
                .contains("\"authenticatorData\":\"PpZrl");
        diag("debugger REG siblings present - publicKey(SPKI)=" + siblingSpki.substring(0, 16) + "…, "
                + "publicKeyAlgorithm:-8, standalone authenticatorData=" + hasStandaloneAuthData);

        // Run "Register with our key": substitute our ES256 key into attestationObject only, splice back.
        Es256Signer ours = Es256Signer.generate();
        AttestationObject fresh = CBOR.decodeAttestationObject(attUw.inner());
        byte[] subWire = new RegistrationSubstituter(CBOR).substituteAndEncode(fresh, ours);
        byte[] newBody = JsonValueEditor.splice(body, attSpan, CODEC.rewrap(subWire, attUw.spec()));

        // attestationObject now carries OUR ES256 key …
        int[] newAttSpan = spec.locate(Field.ATTESTATION_OBJECT, newBody);
        AttestationObject reDecoded = CBOR.decodeAttestationObject(CODEC.unwrap(slice(newBody, newAttSpan)).inner());
        assertEquals("none", reDecoded.fmt(), "attestation forced to fmt=none");
        assertEquals(2, reDecoded.authData().credentialPublicKey().kty(), "attestationObject key is now ours (EC2)");

        // … BUT the sibling key material is UNCHANGED - still the victim's Ed25519 key. THIS is the bug:
        // an RP that reads getPublicKey()/publicKeyAlgorithm (not the attestationObject) stores the wrong key.
        assertEquals(siblingSpki, stringMember(newBody, "publicKey"),
                "BUG: sibling publicKey (SPKI) still advertises the victim's Ed25519 key after substitution");
        assertTrue(new String(newBody, StandardCharsets.UTF_8).contains("\"publicKeyAlgorithm\":-8"),
                "BUG: sibling publicKeyAlgorithm still -8 (EdDSA) after substitution");
        assertTrue(new String(newBody, StandardCharsets.UTF_8).contains("\"authenticatorData\":\"PpZrl"),
                "standalone authenticatorData (embedding the Ed25519 key) unchanged after substitution");

        // CROSS-FIXTURE PROOF that this is NOT the debugger's discriminator: the WORKING captures carry the
        // same Chrome toJSON() echo fields, yet their RPs accept our forgery (webauthn.io "fully works"; the
        // reg-clean key-substitution flow is live-proven). So the echo staleness is a latent gap, not the cause.
        for (String working : new String[]{"webauthn-io-reg", "reg-clean"}) {
            String b = new String(load(working), StandardCharsets.UTF_8);
            assertTrue(b.contains("\"publicKey\"") && b.contains("\"publicKeyAlgorithm\""),
                    working + " ALSO carries publicKey/publicKeyAlgorithm echo fields, yet works");
        }
        diag("LATENT GAP, not the discriminator: substitution rewrote attestationObject (EC2/ES256/ours) but "
                + "left the publicKey/publicKeyAlgorithm/standalone-authenticatorData echo stale. The WORKING "
                + "captures (webauthn-io-reg, reg-clean) carry the SAME Chrome toJSON() echo and their RPs "
                + "accept our forgery → they read attestationObject. Hardening (substitute the echo too) is a "
                + "noteworthy defence for RPs that trust getPublicKey(), but does NOT explain debugger≠webauthn.io.");
    }

    // =====================================================================================
    // BUG 2 - passkeys.io (Hanko) "an error banner showed up"
    // =====================================================================================

    /**
     * The Hanko AUTH + REG captures decode CLEANLY under the matched (.hanko.io) profile - every declared
     * field locates and decodes, so the editor adds nothing to its {@code degraded} list and shows no
     * banner. The "degrade banner from an unlocated profile field" hypothesis is mechanically refuted: in
     * {@code decodeBestEffort} an unlocated field returns null and is SKIPPED (no degrade); only a
     * located-but-undecodable field banners. So the live banner is host-match / live-body specific.
     */
    @Test
    void hankoCapturesDecodeCleanlyUnderMatchedProfile() throws Exception {
        // AUTH
        byte[] auth = load("passkeys-io-auth");
        PhaseSpec authSpec = registry.resolve("passkeys.hanko.io", Phase.AUTH_VERIFY);
        for (Field f : new Field[]{Field.CLIENT_DATA_JSON, Field.AUTHENTICATOR_DATA, Field.SIGNATURE}) {
            assertNotNull(authSpec.locate(f, auth), "Hanko AUTH " + f + " locates under .hanko.io profile");
        }
        AuthenticatorData ad = CBOR.decodeAuthData(
                CODEC.unwrap(slice(auth, authSpec.locate(Field.AUTHENTICATOR_DATA, auth))).inner());
        assertNotNull(ad.rpIdHash(), "Hanko AUTH authData decodes (no degrade)");
        byte[] sig = CODEC.unwrap(slice(auth, authSpec.locate(Field.SIGNATURE, auth))).inner();
        assertEquals((byte) 0x30, sig[0], "Hanko AUTH signature is DER (ES256) - decodes, no degrade");
        diag("Hanko AUTH under .hanko.io: all fields decode; sig is DER/ES256 len=" + sig.length
                + " → NO degrade, NO banner.");

        // REG
        byte[] reg = load("passkeys-io-reg");
        PhaseSpec regSpec = registry.resolve("passkeys.hanko.io", Phase.REG_VERIFY);
        int[] attSpan = regSpec.locate(Field.ATTESTATION_OBJECT, reg);
        assertNotNull(attSpan, "Hanko REG attestationObject locates under .hanko.io profile");
        AttestationObject att = CBOR.decodeAttestationObject(CODEC.unwrap(slice(reg, attSpan)).inner());
        assertNotNull(att.authData(), "Hanko REG attestationObject decodes (no degrade)");
        diag("Hanko REG under .hanko.io: attestationObject fmt=" + att.fmt() + " decodes → NO banner.");
    }

    /**
     * If the live request host is NOT {@code *.hanko.io} (e.g. the page host {@code www.passkeys.io}), the
     * registry falls to the Default profile, whose candidate paths ({@code response.<field>} / flat
     * {@code <field>}) do not exist in Hanko's {@code input_data.<wrapper>.response.<field>} body - so every
     * field locates to NOTHING. That is the dead-but-silent state (no banner), which pins the open question:
     * the banner needs the actual request host + phase to reproduce. (Drives the URL/host fix.)
     */
    @Test
    void hankoUnderDefaultProfileLocatesNothing() throws Exception {
        byte[] auth = load("passkeys-io-auth");
        PhaseSpec defaultSpec = registry.resolve("www.passkeys.io", Phase.AUTH_VERIFY);
        assertTrue(registry.match("www.passkeys.io") == registry.defaultProfile(),
                "www.passkeys.io does not match .hanko.io → Default profile");
        assertNull(defaultSpec.locate(Field.CLIENT_DATA_JSON, auth), "Default cannot locate Hanko clientDataJSON");
        assertNull(defaultSpec.locate(Field.AUTHENTICATOR_DATA, auth), "Default cannot locate Hanko authenticatorData");
        assertNull(defaultSpec.locate(Field.SIGNATURE, auth), "Default cannot locate Hanko signature");
        diag("Hanko under Default (host www.passkeys.io): all fields locate to null → silent dead tab, NOT a "
                + "banner. The live banner therefore needs the real request host/body (open question for 2c).");
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static String clientDataString(ClientData cd, String key) {
        return stringMember(cd.raw(), key);
    }

    /** Tiny direct-member string reader for assertions/diagnostics (test-only). */
    private static String stringMember(byte[] body, String key) {
        int[] span = JsonValueEditor.findStringValueSpan(body, key);
        return span == null ? null : new String(body, span[0], span[1] - span[0], StandardCharsets.UTF_8);
    }
}
