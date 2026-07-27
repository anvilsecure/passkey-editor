package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.util.JsonValueEditor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * gate for the profile model + registry. Proves three things, all data-driven (no per-RP code):
 *   - Routing - a request host resolves to its seeded profile, and anything unknown (incl.
 *       localhost) falls to the Default.
 *   - Freeze-safety - the Default profile reproduces the baseline extraction on the fixtures
 *       with a byte-identical unedited round-trip (locate → unwrap → rewrap → splice == original),
 *       so the default path is never destabilised.
 *   - End-to-end - each seeded profile decodes its own real captured body via host → profile →
 *       path → existing codec.
 */
class ProfileRegistryTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();
    private final ProfileRegistry registry = RpFixtureProfiles.seededRegistry();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = ProfileRegistryTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, "fixture not on classpath: " + fixture);
            return in.readAllBytes();
        }
    }

    @Test
    void hostMatchRoutesToProfileElseDefault() {
        assertEquals("webauthn.io", registry.match("webauthn.io").id());
        assertEquals("passkeys-debugger", registry.match("www.passkeys-debugger.io").id());
        assertEquals("hanko", registry.match("tenant.hanko.io").id());
        assertEquals("yubico", registry.match("demo.yubico.com").id());
        assertEquals("lubu", registry.match("webauthn.lubu.ch").id());
        // localhost and any unknown host match no learned profile -> Default (the freeze-safe path).
        assertEquals("default", registry.match("localhost").id());
        assertEquals("default", registry.match("some-unknown-rp.example.com").id());
        assertEquals("default", registry.match(null).id());
    }

    @Test
    void defaultProfileIsByteIdenticalOnBaselineFixtures() throws IOException {
        byte[] reg = load("reg-clean");
        PhaseSpec regSpec = registry.resolve("localhost", Phase.REG_VERIFY);
        assertUneditedRoundTrip(reg, regSpec, Field.CLIENT_DATA_JSON);
        assertUneditedRoundTrip(reg, regSpec, Field.ATTESTATION_OBJECT);
        assertTrue(text(unwrap(reg, regSpec, Field.CLIENT_DATA_JSON)).contains("\"type\":\"webauthn.create\""),
                "baseline reg clientData");

        byte[] auth = load("auth-clean");
        PhaseSpec authSpec = registry.resolve("localhost", Phase.AUTH_VERIFY);
        assertUneditedRoundTrip(auth, authSpec, Field.CLIENT_DATA_JSON);
        assertUneditedRoundTrip(auth, authSpec, Field.AUTHENTICATOR_DATA);
        assertUneditedRoundTrip(auth, authSpec, Field.SIGNATURE);
        assertTrue(text(unwrap(auth, authSpec, Field.CLIENT_DATA_JSON)).contains("\"type\":\"webauthn.get\""),
                "baseline auth clientData");
    }

    @Test
    void seededProfilesDecodeTheirRealCaptures() throws IOException {
        record Rp(String host, String regFx, String authFx) {}
        Rp[] rps = {
            new Rp("webauthn.io", "webauthn-io-reg", "webauthn-io-auth"),
            new Rp("www.passkeys-debugger.io", "passkeys-debugger-reg", "passkeys-debugger-auth"),
            new Rp("tenant.hanko.io", "passkeys-io-reg", "passkeys-io-auth"),
            new Rp("demo.yubico.com", "yubico-demo-reg", "yubico-demo-auth"),
            new Rp("webauthn.lubu.ch", "webauthn-lubu-reg", "webauthn-lubu-auth"),
        };
        for (Rp rp : rps) {
            assertNotEquals("default", registry.match(rp.host()).id(), () -> rp.host() + " should match a profile");

            byte[] reg = load(rp.regFx());
            PhaseSpec rs = registry.resolve(rp.host(), Phase.REG_VERIFY);
            assertEquals((byte) 0xA3, unwrap(reg, rs, Field.ATTESTATION_OBJECT)[0],
                    () -> rp.regFx() + " attestationObject via profile should be a CBOR map(3)");
            assertTrue(text(unwrap(reg, rs, Field.CLIENT_DATA_JSON)).contains("\"type\":\"webauthn.create\""),
                    rp.regFx());

            byte[] auth = load(rp.authFx());
            PhaseSpec as = registry.resolve(rp.host(), Phase.AUTH_VERIFY);
            assertEquals(37, unwrap(auth, as, Field.AUTHENTICATOR_DATA).length,
                    () -> rp.authFx() + " assertion authData via profile should be 37 bytes");
            assertTrue(text(unwrap(auth, as, Field.CLIENT_DATA_JSON)).contains("\"type\":\"webauthn.get\""),
                    rp.authFx());
        }
    }

    @Test
    void userCanAddAndRemoveProfiles() {
        ProfileRegistry r = RpFixtureProfiles.seededRegistry();
        int before = r.profiles().size();
        TargetProfile custom = new TargetProfile("custom", "Custom RP", HostMatch.exact("my.rp.test"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(
                        Field.SIGNATURE, FieldLocator.of("data.signature")))));
        r.add(custom);
        assertEquals("custom", r.match("my.rp.test").id());
        assertEquals(before + 1, r.profiles().size());
        assertTrue(r.remove("custom"));
        assertEquals("default", r.match("my.rp.test").id(), "removed profile no longer matches");
    }

    @Test
    void defaultProfileLocatesFlatTopLevelFieldsForUnknownHost() throws IOException {
        // An unknown host falls to the Default, whose [response.X, X] candidates must locate a FLAT
        // top-level field via the SECOND candidate - the unprofiled-RP case promises, which the baseline
        // fixtures (all response.X, candidate[0]) never exercise. webauthn-lubu-auth is flat top-level.
        assertEquals("default", registry.match("unknown-flat-rp.example.com").id());
        byte[] body = load("webauthn-lubu-auth");
        PhaseSpec spec = registry.resolve("unknown-flat-rp.example.com", Phase.AUTH_VERIFY);
        assertTrue(text(unwrap(body, spec, Field.CLIENT_DATA_JSON)).contains("\"type\":\"webauthn.get\""),
                "Default locates a flat clientDataJSON via the 2nd candidate");
        assertEquals(37, unwrap(body, spec, Field.AUTHENTICATOR_DATA).length, "flat authenticatorData located");
    }

    @Test
    void deferredHostsFallToDefaultAndDeclineUnsupportedShapes() throws IOException {
        // ctap.dev (raw-JSON clientDataJSON) + Descope (api.descope.com, stringified-JSON credential) are
        // deferred to a later release: no profile, so they fall to the Default - which must DECLINE the shapes it
        // cannot safely splice (return null) rather than wrong bytes. Locks the boundary at the registry
        // level (JsonPathLocatorTest covers only the bare locator).
        assertEquals("default", registry.match("ctap.dev").id());
        assertEquals("default", registry.match("api.descope.com").id());

        PhaseSpec ctap = registry.resolve("ctap.dev", Phase.REG_VERIFY);
        byte[] ctapReg = load("ctap-dev-reg");
        assertNull(ctap.locate(Field.CLIENT_DATA_JSON, ctapReg), "ctap raw-JSON clientDataJSON declined");
        assertNotNull(ctap.locate(Field.ATTESTATION_OBJECT, ctapReg), "ctap flat attestationObject still locates");

        PhaseSpec descope = registry.resolve("api.descope.com", Phase.REG_VERIFY);
        byte[] guruReg = load("passkeys-guru-reg");
        assertNull(descope.locate(Field.CLIENT_DATA_JSON, guruReg), "Descope stringified clientDataJSON declined");
        assertNull(descope.locate(Field.ATTESTATION_OBJECT, guruReg), "Descope stringified attestationObject declined");
    }

    // ---- enabled-aware tab/colour disposition (TRACKED / SILENCED / UNPROFILED) ------------------

    private static TargetProfile rpProfile(boolean enabled, boolean scopedVerifyUrl) {
        PhaseSpec auth = scopedVerifyUrl
                ? new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")),
                        new UrlMatch(UrlMatch.Kind.CONTAINS, "/verify", null))
                : new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")));
        return new TargetProfile("rp", "RP", HostMatch.exact("rp.test"),
                Map.of(Phase.AUTH_VERIFY, auth), enabled);
    }

    @Test
    void enabledProfileTracksAndUrlScopesItsHost() {
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(rpProfile(true, true)));
        assertTrue(reg.isTracked("rp.test"), "an enabled specific profile is a tracked (colourable) target");
        assertTrue(reg.tabVisibleFor("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST"),
                "tab shows on the pinned verify URL");
        assertFalse(reg.tabVisibleFor("rp.test", Phase.AUTH_VERIFY, "https://rp.test/login", "POST"),
                "tab hidden on a non-verify endpoint (URL scope honoured)");
        assertTrue(reg.tabVisibleForHost("rp.test"), "options tab shows for a tracked host (host-scoped only)");
    }

    @Test
    void unknownRequestUrlKeepsTheTabButStillBlocksAuto() {
        // LIVE BUG: the ceremony tab vanished on a correctly-detected verify request. Burp binds editor
        // messages it cannot resolve a URL for (HttpRequest.url() throws MalformedRequestException with no
        // HttpService), so the editor passes url == null - and a null read as "URL mismatch" hid the tab on a
        // URL-scoped profile. Unknown != mismatch: visibility falls back to host + enabled.
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(rpProfile(true, true)));
        assertTrue(reg.tabVisibleFor("rp.test", Phase.AUTH_VERIFY, null, "POST"),
                "an unknowable URL must not hide the tab on a tracked host");
        assertTrue(reg.urlScopeAllows("rp.test", Phase.AUTH_VERIFY, null, null),
                "no URL and no method to test against ⇒ the scope cannot exclude");
        assertFalse(reg.tabVisibleFor("rp.test", Phase.AUTH_VERIFY, "https://rp.test/login", "POST"),
                "a KNOWN non-verify URL is still excluded - the operator's panel stays authoritative");

        // AUTO is deliberately stricter: it rewrites live traffic, so an unprovable endpoint means don't act.
        TargetProfile armed = rpProfile(true, true).withAutoResign(true);
        ProfileRegistry auto = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(armed));
        assertNull(auto.matchAuto("rp.test", Phase.AUTH_VERIFY, null, "POST"),
                "AUTO must NOT act when the request URL can't be matched against the pinned verify URL");
        assertNotNull(auto.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST"),
                "...but still acts on the pinned verify URL");
    }

    @Test
    void disabledProfileSilencesItsHostEvenWithDefaultEnabled() {
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(rpProfile(false, false)));
        assertTrue(reg.defaultProfile().enabled(), "the Default ships enabled");
        assertFalse(reg.isTracked("rp.test"), "a silenced host is not a tracked/coloured target");
        assertFalse(reg.tabVisibleFor("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST"),
                "a disabled profile silences its host - no request tab, despite an enabled Default");
        assertFalse(reg.tabVisibleForHost("rp.test"), "...and no options tab either");
    }

    @Test
    void unprofiledHostFollowsTheDefaultsOwnSwitch() {
        ProfileRegistry on = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of());
        assertTrue(on.tabVisibleForHost("unprofiled.local"),
                "Default enabled ⇒ an unprofiled host shows the tab structurally (freeze-safe)");
        assertTrue(on.tabVisibleFor("unprofiled.local", Phase.AUTH_VERIFY, "https://unprofiled.local/verify", "POST"));
        assertFalse(on.isTracked("unprofiled.local"), "the generic Default is never a tracked/coloured target");

        ProfileRegistry off = new ProfileRegistry(BuiltinProfiles.defaultProfile().withEnabled(false), List.of());
        assertFalse(off.tabVisibleForHost("unprofiled.local"), "Default disabled ⇒ an unprofiled host shows nothing");
        assertFalse(off.tabVisibleFor("unprofiled.local", Phase.AUTH_VERIFY, "https://unprofiled.local/verify", "POST"));
    }

    @Test
    void everyProfileDisabledMatchesNothing() {
        // The operator requirement: disable every profile, INCLUDING the Default, and nothing matches anywhere.
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile().withEnabled(false),
                List.of(rpProfile(false, false)));
        assertFalse(reg.tabVisibleForHost("rp.test"), "disabled profile host → nothing");
        assertFalse(reg.tabVisibleForHost("unprofiled.local"), "unprofiled host + disabled Default → nothing");
        assertFalse(reg.tabVisibleFor("any.test", Phase.REG_VERIFY, "https://any.test/x", "POST"));
    }

    @Test
    void seededDefaultKeepsTheUnprofiledTabVisible() {
        // Freeze-safety pin: the SHIPPED (seeded) Default is enabled, so an unprofiled localhost
        // still shows the ceremony tab (UNPROFILED → the Default's own switch). Locks the tab against an
        // accidental seed change shipping a disabled Default. An unprofiled host is never a coloured target.
        assertTrue(registry.tabVisibleForHost("localhost"), "seeded Default keeps the unprofiled host/options tab");
        assertTrue(registry.tabVisibleFor("localhost", Phase.REG_VERIFY, "https://localhost/attestation/result", "POST"),
                "seeded Default keeps the unprofiled registration tab");
        assertTrue(registry.tabVisibleFor("localhost", Phase.AUTH_VERIFY, "https://localhost/assertion/result", "POST"),
                "seeded Default keeps the unprofiled authentication tab");
        assertFalse(registry.isTracked("localhost"), "an unprofiled host falls to the generic Default - never a coloured target");
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    private static byte[] unwrap(byte[] body, PhaseSpec spec, Field field) {
        int[] span = spec.locate(field, body);
        assertNotNull(span, () -> "no value located for " + field);
        return CODEC.unwrap(Arrays.copyOfRange(body, span[0], span[1])).inner();
    }

    /** locate → unwrap → rewrap → splice must reproduce the original body byte-for-byte (no edit). */
    private static void assertUneditedRoundTrip(byte[] body, PhaseSpec spec, Field field) {
        int[] span = spec.locate(field, body);
        assertNotNull(span, () -> "no value located for " + field);
        byte[] value = Arrays.copyOfRange(body, span[0], span[1]);
        WrapperCodec.Unwrapped uw = CODEC.unwrap(value);
        byte[] rewrapped = CODEC.rewrap(uw.inner(), uw.spec());
        assertArrayEquals(value, rewrapped, () -> field + " codec round-trip not lossless");
        assertArrayEquals(body, JsonValueEditor.splice(body, span, rewrapped),
                () -> field + " unedited splice not byte-identical");
    }
}
