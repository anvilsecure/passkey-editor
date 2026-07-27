package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.WrapSpec.Padding;
import com.anvil.passkeyeditor.profile.EncodingSpec.Base64Kind;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Gates for the v2 model: per-profile {@code enabled} matching + {@link ProfileJson} v2 round-trip + v1 read. */
class ProfileV2Test {

    @Test
    void disabledProfileIsSkippedInMatching() {
        TargetProfile wio = new TargetProfile("webauthn.io", "wio", HostMatch.exact("webauthn.io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")))),
                false); // disabled
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(wio));
        assertSame(reg.defaultProfile(), reg.match("webauthn.io"), "a disabled profile is skipped → Default");

        ProfileRegistry reg2 = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(wio.withEnabled(true)));
        assertEquals("webauthn.io", reg2.match("webauthn.io").id(), "re-enabled → it matches again");
    }

    @Test
    void v2RoundTripPreservesKindEncodingUrlEnabled() {
        Map<Field, FieldLocator> fields = new LinkedHashMap<>();
        fields.put(Field.SIGNATURE,
                FieldLocator.regex("\"signature\":\"([^\"]+)\"", new EncodingSpec(true, Base64Kind.STANDARD, Padding.PADDED, null)));
        fields.put(Field.CLIENT_DATA_JSON, FieldLocator.of(EncodingSpec.base64Url(), "a.b.c"));
        PhaseSpec spec = new PhaseSpec(fields, new UrlMatch(UrlMatch.Kind.CONTAINS, "/verify", "POST"));
        TargetProfile p = new TargetProfile("x", "X", HostMatch.exact("x.io"), Map.of(Phase.AUTH_VERIFY, spec), false);

        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(List.of(p)));
        assertEquals(1, back.size());
        TargetProfile q = back.get(0);
        assertFalse(q.enabled(), "enabled persisted");

        PhaseSpec qs = q.phase(Phase.AUTH_VERIFY);
        assertEquals(UrlMatch.Kind.CONTAINS, qs.url().kind(), "url match persisted");
        assertEquals("/verify", qs.url().pattern());
        assertEquals("POST", qs.url().method());

        FieldLocator sig = qs.locator(Field.SIGNATURE);
        assertEquals(FieldLocator.Kind.REGEX, sig.kind(), "regex kind persisted");
        assertEquals("\"signature\":\"([^\"]+)\"", sig.regex());
        assertTrue(sig.encoding().urlEncoded(), "url-encode persisted");
        assertEquals(Base64Kind.STANDARD, sig.encoding().base64());
        assertEquals(Padding.PADDED, sig.encoding().padding());

        FieldLocator cdj = qs.locator(Field.CLIENT_DATA_JSON);
        assertEquals(FieldLocator.Kind.PATH, cdj.kind());
        assertEquals("a.b.c", cdj.candidates().get(0).toString());
        assertEquals(Base64Kind.URL_SAFE, cdj.encoding().base64());
    }

    @Test
    void v1FormatReadsAsPathAutoEnabledNoUrl() {
        String v1 = "{\"version\":1,\"profiles\":[{\"id\":\"x\",\"name\":\"X\","
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"x.io\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"paths\":[\"response.signature\"]}}}}}]}";
        List<TargetProfile> back = ProfileJson.fromJson(v1.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, back.size());
        TargetProfile q = back.get(0);
        assertTrue(q.enabled(), "v1 → enabled defaults true");
        PhaseSpec qs = q.phase(Phase.AUTH_VERIFY);
        assertNull(qs.url(), "v1 → no url scope");
        FieldLocator sig = qs.locator(Field.SIGNATURE);
        assertEquals(FieldLocator.Kind.PATH, sig.kind(), "v1 → PATH");
        assertEquals("response.signature", sig.candidates().get(0).toString());
        assertNull(sig.encoding(), "v1 → AUTO encoding");
    }

    /** AUDIT M3: replace keeps the edited profile's slot (host-match precedence) instead of reordering to tail. */
    @Test
    void replacePreservesPositionAndHandlesRename() {
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(),
                List.of(profile("a"), profile("b"), profile("c")));
        reg.replace("b", profile("b").withEnabled(false));
        assertEquals(List.of("a", "b", "c"), reg.profiles().stream().map(TargetProfile::id).toList(),
                "in-place replace keeps order");
        assertFalse(reg.profiles().get(1).enabled(), "b replaced in place");
        // rename a -> c: the existing c is dropped, a's slot becomes the new c.
        reg.replace("a", profile("c"));
        assertEquals(List.of("c", "b"), reg.profiles().stream().map(TargetProfile::id).toList(),
                "rename-onto-existing removes the old holder, keeps the edited slot");
    }

    /** AUDIT M1: one malformed profile is skipped; the valid ones survive. */
    @Test
    void fromJsonSkipsOneBadProfileKeepingTheRest() {
        String json = "{\"version\":2,\"profiles\":["
                + "{\"id\":\"good\",\"name\":\"G\",\"host\":{\"kind\":\"EXACT\",\"pattern\":\"g.io\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"kind\":\"PATH\",\"paths\":[\"response.signature\"]}}}}},"
                + "{\"id\":\"bad-no-phases\"}]}"; // missing phases → throws → skipped, not fatal
        List<TargetProfile> back = ProfileJson.fromJson(json.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, back.size(), "the malformed profile is skipped; the good one kept");
        assertEquals("good", back.get(0).id());
    }

    /** AUDIT M4: a non-boolean enabled does NOT flip to false; an explicit-null method is tolerated. */
    @Test
    void tolerantAccessorsHandleOddFields() {
        String json = "{\"version\":2,\"profiles\":[{\"id\":\"x\",\"name\":\"X\",\"enabled\":\"yes\","
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"x.io\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"url\":{\"kind\":\"CONTAINS\",\"pattern\":\"/v\",\"method\":null},"
                + "\"fields\":{\"SIGNATURE\":{\"kind\":\"PATH\",\"paths\":[\"a\"]}}}}}]}";
        List<TargetProfile> back = ProfileJson.fromJson(json.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, back.size());
        assertTrue(back.get(0).enabled(), "non-boolean enabled defaults true (not silently flipped to false)");
        assertNull(back.get(0).phase(Phase.AUTH_VERIFY).url().method(), "explicit-null method tolerated, not fatal");
    }

    /** AUDIT H2/H3 (persistence half): off-diagonal padding + an envelopeKey round-trip faithfully. */
    @Test
    void offDiagonalPaddingAndEnvelopeRoundTrip() {
        Map<Field, FieldLocator> fields = new LinkedHashMap<>();
        fields.put(Field.SIGNATURE, FieldLocator.of(new EncodingSpec(false, Base64Kind.STANDARD, Padding.UNPADDED, null), "a"));
        fields.put(Field.CLIENT_DATA_JSON, FieldLocator.of(new EncodingSpec(false, Base64Kind.URL_SAFE, Padding.PADDED, null), "b"));
        fields.put(Field.ATTESTATION_OBJECT, FieldLocator.of(new EncodingSpec(false, Base64Kind.STANDARD, Padding.PADDED, "$base64"), "c"));
        TargetProfile p = new TargetProfile("x", "X", HostMatch.exact("x.io"), Map.of(Phase.REG_VERIFY, new PhaseSpec(fields)));

        PhaseSpec qs = ProfileJson.fromJson(ProfileJson.toJson(List.of(p))).get(0).phase(Phase.REG_VERIFY);
        assertEquals(Padding.UNPADDED, qs.locator(Field.SIGNATURE).encoding().padding(), "STANDARD+UNPADDED preserved");
        assertEquals(Padding.PADDED, qs.locator(Field.CLIENT_DATA_JSON).encoding().padding(), "URL_SAFE+PADDED preserved");
        assertEquals("$base64", qs.locator(Field.ATTESTATION_OBJECT).encoding().envelopeKey(), "envelopeKey preserved");
    }

    /**
     * The core URL-strictness fix: a profile that pins a verify URL gates tab visibility - only a matching
     * URL/method is allowed; a wrong URL (the bug the operator hit) is rejected. No pinned URL ⇒ allowed.
     */
    @Test
    void urlScopeAllowsGatesByPinnedUrl() {
        UrlMatch ves = new UrlMatch(UrlMatch.Kind.EXACT, "https://webauthn.io/authentication/ves", "POST");
        TargetProfile wio = new TargetProfile("wio", "wio", HostMatch.exact("webauthn.io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.response.signature")), ves)));
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(wio));

        assertTrue(reg.urlScopeAllows("webauthn.io", Phase.AUTH_VERIFY, "https://webauthn.io/authentication/ves", "POST"),
                "matching URL+method → allowed");
        assertFalse(reg.urlScopeAllows("webauthn.io", Phase.AUTH_VERIFY, "https://webauthn.io/authentication/verify", "POST"),
                "wrong URL → NOT allowed (tab must hide)");
        assertFalse(reg.urlScopeAllows("webauthn.io", Phase.AUTH_VERIFY, "https://webauthn.io/authentication/ves", "GET"),
                "wrong method → NOT allowed");
        assertTrue(reg.urlScopeAllows("webauthn.io", Phase.REG_VERIFY, "https://anything", "POST"),
                "a phase with no pinned URL → allowed (structural)");
        assertTrue(reg.urlScopeAllows("other.com", Phase.AUTH_VERIFY, "https://other.com/x", "POST"),
                "unprofiled host → Default (no URL) → allowed");
    }

    /** Per-profile sample bodies persist with the profile (and null stays null / unserialized). */
    @Test
    void sampleBodiesRoundTrip() {
        TargetProfile p = new TargetProfile("x", "X", HostMatch.exact("x.io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("a")))),
                true, "{\"reg\":1}", "{\"auth\":2}");
        TargetProfile q = ProfileJson.fromJson(ProfileJson.toJson(List.of(p))).get(0);
        assertEquals("{\"reg\":1}", q.sampleRegBody());
        assertEquals("{\"auth\":2}", q.sampleAuthBody());

        TargetProfile noSamples = profile("y");
        assertNull(ProfileJson.fromJson(ProfileJson.toJson(List.of(noSamples))).get(0).sampleRegBody(),
                "absent samples stay null");
    }

    /** AUDIT-3 L2 regression: an oversized sample body is omitted on write, so it can't sink the whole store. */
    @Test
    void oversizedSampleBodyIsOmittedNotStoreWiping() {
        String huge = "x".repeat(300 * 1024); // > the 256 KiB per-field cap
        TargetProfile p = new TargetProfile("x", "X", HostMatch.exact("x.io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("a")))),
                true, huge, null);
        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(List.of(p)));
        assertEquals(1, back.size(), "profile survives - the oversized sample is omitted, store not wiped");
        assertNull(back.get(0).sampleRegBody(), "oversized sample body omitted on write");
    }

    private static TargetProfile profile(String id) {
        return new TargetProfile(id, id, HostMatch.exact(id + ".io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")))));
    }
}
