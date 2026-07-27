package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * gates: the per-profile {@link SignerSpec} (default signing algorithm) round-trips through
 * {@link ProfileJson}, is back-compat for stores written before it existed, carries the seeded built-in
 * defaults, and - the freeze-safety anchor - leaves the Default profile on ES256.
 */
final class ProfileSignerTest {

    private static TargetProfile profile(String id, SignerSpec signer) {
        Map<Field, FieldLocator> fields = Map.of(Field.SIGNATURE, FieldLocator.of("response.signature"));
        return new TargetProfile(id, id, HostMatch.exact(id + ".io"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(fields))).withSigner(signer);
    }

    @Test
    void signerRoundTripsThroughJson() {
        TargetProfile eddsa = profile("ed", SignerSpec.EDDSA);
        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(List.of(eddsa)));
        assertEquals(1, back.size());
        assertEquals(-8, back.get(0).signer().coseAlg(), "EdDSA (-8) default persists + reloads");

        TargetProfile rs256 = profile("rs", new SignerSpec(-257));
        TargetProfile rsBack = ProfileJson.fromJson(ProfileJson.toJson(List.of(rs256))).get(0);
        assertEquals(-257, rsBack.signer().coseAlg(), "any COSE id round-trips (RS256 here)");
    }

    @Test
    void jsonContainsSignerProperty() {
        String json = new String(ProfileJson.toJson(List.of(profile("ed", SignerSpec.EDDSA))),
                StandardCharsets.UTF_8);
        assertTrue(json.contains("\"signer\": -8"), "signer serialised as a COSE-id int: " + json);
    }

    @Test
    void legacyStoreWithoutSignerDefaultsEs256() {
        // A v2-shaped store (no "signer" field) must load with the profile defaulting to ES256 - the store
        // format is additive, so an older Burp project file keeps working unchanged.
        String v2 = "{\"version\":2,\"profiles\":[{"
                + "\"id\":\"x\",\"name\":\"X\",\"enabled\":true,"
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"x.io\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"paths\":[\"response.signature\"]}}}}"
                + "}]}";
        List<TargetProfile> back = ProfileJson.fromJson(v2.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, back.size());
        assertEquals(SignerSpec.ES256, back.get(0).signer(), "absent signer → ES256 (v2 back-compat)");
    }

    @Test
    void garbageSignerValueFallsBackToEs256() {
        // A non-numeric / absurd signer value must not nuke the profile - the tolerant accessor defaults it.
        String bad = "{\"version\":3,\"profiles\":[{"
                + "\"id\":\"x\",\"name\":\"X\",\"enabled\":true,\"signer\":\"oops\","
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"x.io\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"paths\":[\"response.signature\"]}}}}"
                + "}]}";
        List<TargetProfile> back = ProfileJson.fromJson(bad.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, back.size(), "a bad signer value does not discard the profile");
        assertEquals(SignerSpec.ES256, back.get(0).signer());
    }

    @Test
    void backCompatConstructorsDefaultEs256() {
        TargetProfile fourArg = new TargetProfile("a", "A", HostMatch.exact("a.io"), Map.of());
        assertEquals(SignerSpec.ES256, fourArg.signer(), "4-arg ctor → ES256");
        TargetProfile fiveArg = new TargetProfile("b", "B", HostMatch.exact("b.io"), Map.of(), false);
        assertEquals(SignerSpec.ES256, fiveArg.signer(), "5-arg ctor → ES256");
        // withEnabled / withSamples preserve the signer rather than resetting it.
        assertEquals(SignerSpec.EDDSA, profile("c", SignerSpec.EDDSA).withEnabled(false).signer());
        assertEquals(SignerSpec.EDDSA, profile("d", SignerSpec.EDDSA).withSamples("r", "a").signer());
    }

    @Test
    void nullSignerNormalisesToEs256() {
        TargetProfile p = new TargetProfile("n", "N", HostMatch.exact("n.io"), Map.of(),
                true, null, null, null);
        assertEquals(SignerSpec.ES256, p.signer(), "a null signer normalises to ES256 (compact ctor)");
    }

    @Test
    void builtinDefaultsMatchCapturedAlgorithms() {
        Map<String, TargetProfile> byId = new java.util.HashMap<>();
        for (TargetProfile p : RpFixtureProfiles.all()) {
            byId.put(p.id(), p);
        }
        // RPs captured defaulting to Ed25519 → seeded EdDSA so the chooser/AUTO plant what the RP accepts.
        assertEquals(-8, byId.get("webauthn.io").signer().coseAlg(), "webauthn.io → EdDSA");
        assertEquals(-8, byId.get("passkeys-debugger").signer().coseAlg(), "passkeys-debugger → EdDSA");
        assertEquals(-8, byId.get("lubu").signer().coseAlg(), "webauthn.lubu.ch → EdDSA");
        // The others stay on ES256.
        assertEquals(-7, byId.get("hanko").signer().coseAlg(), "Hanko → ES256");
        assertEquals(-7, byId.get("yubico").signer().coseAlg(), "Yubico → ES256");
    }

    @Test
    void defaultProfileStaysEs256ForFreezeSafety() {
        assertEquals(SignerSpec.ES256, BuiltinProfiles.defaultProfile().signer(),
                "Default profile must stay ES256 so the default path is byte-identical (freeze-safe)");
    }
}
