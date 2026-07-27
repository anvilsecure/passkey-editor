package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.ProfileValidator.CheckResult;
import com.anvil.passkeyeditor.profile.ProfileValidator.Status;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Gate + readout for {@link ProfileValidator} (the Check engine). Asserts the
 * status/decoded contract on the real Step-0 captures and prints each result (prefix {@code CHECK>>}) so
 * the output shape can be eyeballed before any UI is wired.
 */
class ProfileValidatorTest {

    private final ProfileRegistry registry = RpFixtureProfiles.seededRegistry();
    private final ProfileValidator validator = new ProfileValidator();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = ProfileValidatorTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    private Map<Field, CheckResult> checkAll(String fixture, String host, Phase phase) throws IOException {
        byte[] body = load(fixture);
        Map<Field, CheckResult> results = validator.checkAll(body, registry.resolve(host, phase));
        System.out.println("CHECK>> ===== " + fixture + "  (profile: " + registry.match(host).name() + ") =====");
        results.values().forEach(r -> System.out.println("CHECK>>   " + r.line()));
        return results;
    }

    /**
     * The out-of-box experience since the RP presets stopped shipping: a fresh project holds the Default
     * alone, so the very first Check an operator runs is a generic body against the Default. Everything the
     * body actually carries must come back green, or the tool looks broken before any target is configured.
     *
     * {@code userHandle} is optional (populated only for discoverable credentials) and this
     * fixture omits it, as do 2 of the 5 captured RP fixtures. It must therefore report {@link Status#ABSENT}
     * rather than a red {@code NOT_FOUND}: for an optional field a locator miss and a genuine omission are
     * indistinguishable, so calling it an error would train the operator to ignore red.
     */
    @Test
    void defaultProfileChecksGreenOnAGenericBody() throws Exception {
        ProfileRegistry fresh = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of());

        Map<Field, CheckResult> reg = validator.checkAll(load("reg-clean"),
                fresh.resolve("unprofiled.example", Phase.REG_VERIFY));
        assertTrue(reg.values().stream().allMatch(CheckResult::ok),
                "a generic registration is all-green under the Default: " + lines(reg));
        assertTrue(reg.get(Field.CLIENT_DATA_JSON).decoded().contains("webauthn.create"));
        assertTrue(reg.get(Field.ATTESTATION_OBJECT).decoded().contains("fmt="));

        Map<Field, CheckResult> auth = validator.checkAll(load("auth-clean"),
                fresh.resolve("unprofiled.example", Phase.AUTH_VERIFY));
        assertTrue(auth.entrySet().stream()
                        .filter(e -> e.getKey() != Field.USER_HANDLE)
                        .allMatch(e -> e.getValue().ok()),
                "every field the body carries is green under the Default: " + lines(auth));
        assertTrue(auth.get(Field.CLIENT_DATA_JSON).decoded().contains("webauthn.get"));
        assertEquals(Status.ABSENT, auth.get(Field.USER_HANDLE).status(),
                "an absent OPTIONAL userHandle is reported as absent, not as an error");
        assertTrue(auth.get(Field.USER_HANDLE).note().contains("optional"),
                auth.get(Field.USER_HANDLE).note());
    }

    private static String lines(Map<Field, CheckResult> r) {
        return r.values().stream().map(CheckResult::line).toList().toString();
    }

    @Test
    void webauthnIoAuthAllGreen() throws Exception {
        Map<Field, CheckResult> r = checkAll("webauthn-io-auth", "webauthn.io", Phase.AUTH_VERIFY);
        assertTrue(r.values().stream().allMatch(CheckResult::ok), "every webauthn.io auth field checks OK");
        assertEquals(Status.OK, r.get(Field.CLIENT_DATA_JSON).status());
        assertTrue(r.get(Field.CLIENT_DATA_JSON).decoded().contains("webauthn.get"), "ceremony type decoded");
        assertTrue(r.get(Field.SIGNATURE).decoded().contains("Ed25519")
                || r.get(Field.SIGNATURE).decoded().contains("DER"), "signature shape decoded");
    }

    @Test
    void yubicoRegThroughDollarBase64() throws Exception {
        Map<Field, CheckResult> r = checkAll("yubico-demo-reg", "demo.yubico.com", Phase.REG_VERIFY);
        assertEquals(Status.OK, r.get(Field.CLIENT_DATA_JSON).status(), "clientDataJSON via $base64 path");
        assertEquals(Status.OK, r.get(Field.ATTESTATION_OBJECT).status(), "attestationObject via $base64 path");
        assertTrue(r.get(Field.ATTESTATION_OBJECT).decoded().contains("fmt="), "attestation fmt decoded");
    }

    @Test
    void debuggerAuthSurfacesEd25519Signature() throws Exception {
        Map<Field, CheckResult> r = checkAll("passkeys-debugger-auth", "www.passkeys-debugger.io", Phase.AUTH_VERIFY);
        assertTrue(r.values().stream().allMatch(CheckResult::ok), "debugger auth decodes cleanly");
        assertTrue(r.get(Field.SIGNATURE).decoded().contains("Ed25519"),
                "the Check panel makes the Ed25519 signature visible (why a plain ES256 re-sign needs substitution)");
    }

    @Test
    void hankoCleanUnderProfileButNotFoundUnderDefault() throws Exception {
        Map<Field, CheckResult> matched = checkAll("passkeys-io-auth", "passkeys.hanko.io", Phase.AUTH_VERIFY);
        assertEquals(Status.OK, matched.get(Field.SIGNATURE).status(), "Hanko sig OK under the .hanko.io profile");

        // The same body under the Default profile: every field NOT_FOUND - exactly what the Check panel would
        // show an operator whose request host didn't match (the live banner's host-match story, made visible).
        Map<Field, CheckResult> def = checkAll("passkeys-io-auth", "www.passkeys.io", Phase.AUTH_VERIFY);
        // Every REQUIRED field is a hard NOT_FOUND (the Check panel pinpoints the mismatch); the optional
        // userHandle reports ABSENT, because a miss on an optional field is not evidence of a bad locator.
        assertTrue(def.entrySet().stream()
                        .filter(e -> e.getKey().required())
                        .allMatch(e -> e.getValue().status() == Status.NOT_FOUND),
                "under Default, Hanko's nested required fields are NOT_FOUND: " + def.values());
        assertEquals(Status.ABSENT, def.get(Field.USER_HANDLE).status(),
                "an optional field that misses is absent, not an error");
    }

    /**
     * The concise per-field verdict (the Check row's green line): OK results carry a short "what it is"
     * summary (type / fmt+alg / flags+signCount / sig-kind+len / len+peek); non-OK results carry {@code null}
     * (the row shows the note instead). Pins what the operator reads to confirm a locator is set right.
     */
    @Test
    void concisePerFieldSummary() throws Exception {
        Map<Field, CheckResult> auth = checkAll("webauthn-io-auth", "webauthn.io", Phase.AUTH_VERIFY);
        assertEquals("webauthn.get", auth.get(Field.CLIENT_DATA_JSON).summary(), "clientDataJSON verdict = the type");
        assertTrue(auth.get(Field.AUTHENTICATOR_DATA).summary().contains("signCount"),
                auth.get(Field.AUTHENTICATOR_DATA).summary());
        assertTrue(auth.get(Field.SIGNATURE).summary().contains("64B"), auth.get(Field.SIGNATURE).summary());
        assertTrue(auth.get(Field.USER_HANDLE).summary().contains("20B"), auth.get(Field.USER_HANDLE).summary());

        Map<Field, CheckResult> reg = checkAll("yubico-demo-reg", "demo.yubico.com", Phase.REG_VERIFY);
        assertEquals("webauthn.create", reg.get(Field.CLIENT_DATA_JSON).summary());
        assertTrue(reg.get(Field.ATTESTATION_OBJECT).summary().contains("fmt="),
                reg.get(Field.ATTESTATION_OBJECT).summary());
        assertTrue(reg.get(Field.ATTESTATION_OBJECT).summary().contains("key"),
                reg.get(Field.ATTESTATION_OBJECT).summary());

        // A NOT_FOUND result has no summary (the row falls back to the note).
        CheckResult miss = validator.check(load("webauthn-io-auth"), Field.SIGNATURE, FieldLocator.of("nope.not.here"));
        assertNull(miss.summary(), "non-OK results carry no concise summary");
    }

    /**
     * An empty-string {@code type} member is a malformed clientDataJSON, not a green OK with a blank verdict:
     * it must be SUSPECT (with no concise summary) so the Check row shows the problem, not a green blank verdict.
     */
    @Test
    void emptyClientDataTypeIsSuspectNotBlankGreen() {
        String cdj = "{\"type\":\"\",\"origin\":\"https://x.io\",\"challenge\":\"abc\"}";
        String b64 = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(cdj.getBytes(StandardCharsets.UTF_8));
        byte[] body = ("{\"clientDataJSON\":\"" + b64 + "\"}").getBytes(StandardCharsets.UTF_8);
        CheckResult r = validator.check(body, Field.CLIENT_DATA_JSON, FieldLocator.of("clientDataJSON"));
        assertEquals(Status.SUSPECT, r.status(), "empty type ⇒ SUSPECT: " + r.line());
        assertNull(r.summary(), "no concise verdict for a malformed empty-type clientDataJSON");
        assertNotNull(r.note());
    }

    @Test
    void wrongEncodingIsSuspectNotSilent() throws Exception {
        // Pin RAW (no base64) on a field that is actually base64url → the inner is the base64 text, not JSON.
        byte[] body = load("webauthn-io-auth");
        FieldLocator pinnedRaw = FieldLocator.of(EncodingSpec.raw(), "response.response.clientDataJSON");
        CheckResult r = validator.check(body, Field.CLIENT_DATA_JSON, pinnedRaw);
        assertEquals(Status.SUSPECT, r.status(), "a wrong pinned encoding surfaces as SUSPECT, not a silent pass");
        System.out.println("CHECK>> wrong-encoding demo → " + r.line() + "  (note: " + r.note() + ")");
    }

    @Test
    void notFoundWhenLocatorMisses() throws Exception {
        byte[] body = load("webauthn-io-auth");
        CheckResult r = validator.check(body, Field.SIGNATURE, FieldLocator.of("nope.not.here"));
        assertEquals(Status.NOT_FOUND, r.status());
        assertNotNull(r.note());
    }

    /**
     * AUDIT H2 regression: a ≥37-byte NON-authData value reports SUSPECT, not OK. The codec length-recovers a
     * 37-byte header for any such blob (rpIdHash is never null), so rpIdHash-presence alone must not greenlight.
     */
    @Test
    void misLocatedAuthDataIsSuspectNotGreen() {
        byte[] body = "{\"ad\":\"not authenticator data just plain text padded well beyond thirty seven bytes\"}"
                .getBytes(StandardCharsets.UTF_8);
        CheckResult r = validator.check(body, Field.AUTHENTICATOR_DATA, FieldLocator.of("ad"));
        assertEquals(Status.SUSPECT, r.status(), "a header-recovered authData must not report OK");
        assertNotNull(r.note());
        assertTrue(r.note().contains("header recovered"), "note: " + r.note());
    }

    /**
     * AUDIT M2 regression: an attestationObject locator pointed at a clientDataJSON value decodes to JSON,
     * not attestation CBOR - must be SUSPECT, not a greenlit garbage decode.
     */
    @Test
    void garbageAttestationIsSuspectNotGreen() throws Exception {
        byte[] body = load("webauthn-io-auth");
        CheckResult r = validator.check(body, Field.ATTESTATION_OBJECT,
                FieldLocator.of("response.response.clientDataJSON"));
        assertEquals(Status.SUSPECT, r.status(), "a non-attestation value must not report OK");
    }

    /**
     * AUDIT H1 follow-up: ticking URL-encoded on a value that isn't percent-encoded (the self-check drops the
     * layer) is surfaced in the encoding label, so a checked box with no effect doesn't read as confirmed.
     */
    @Test
    void urlTickWithNoEffectIsNoted() {
        byte[] body = "{\"sig\":\"//8=\"}".getBytes(StandardCharsets.UTF_8); // standard base64, has / and =
        CheckResult r = validator.check(body, Field.SIGNATURE,
                FieldLocator.of(EncodingSpec.autoUrlEncoded(), "sig"));
        assertTrue(r.encoding().contains("no %-escapes"), "ineffective url tick noted: " + r.encoding());
    }

    /**
     * A locator that resolves to an EMPTY value (a mis-addressed field, or a genuinely empty string) decodes
     * to 0 bytes; that must be SUSPECT, not a green "raw · 0B" - the Check panel exists to confirm a locator
     * is right, so an empty extraction reading as success says the exact opposite.
     */
    @Test
    void emptyLocatedSignatureIsSuspectNotGreen() {
        byte[] body = "{\"sig\":\"\"}".getBytes(StandardCharsets.UTF_8);
        CheckResult r = validator.check(body, Field.SIGNATURE, FieldLocator.of(EncodingSpec.raw(), "sig"));
        assertEquals(Status.SUSPECT, r.status(), "an empty located signature must not greenlight: " + r.line());
        assertNull(r.summary(), "no concise verdict for an empty extraction");
        assertNotNull(r.note());
    }

    @Test
    void emptyLocatedUserHandleIsSuspect() {
        byte[] body = "{\"uh\":\"\"}".getBytes(StandardCharsets.UTF_8);
        CheckResult r = validator.check(body, Field.USER_HANDLE, FieldLocator.of(EncodingSpec.raw(), "uh"));
        assertEquals(Status.SUSPECT, r.status(), "an empty located userHandle must not greenlight: " + r.line());
        assertNotNull(r.note());
    }
}
