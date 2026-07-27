package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Persistence serialisation round-trips a profile list without changing routing or paths. */
class ProfileJsonTest {

    @Test
    void roundTripsSeededProfiles() {
        List<TargetProfile> seed = new ArrayList<>(RpFixtureProfiles.all());
        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(seed));
        assertEquals(seed.size(), back.size());

        ProfileRegistry original = new ProfileRegistry(BuiltinProfiles.defaultProfile(), seed);
        ProfileRegistry restored = new ProfileRegistry(BuiltinProfiles.defaultProfile(), back);
        for (String host : List.of("webauthn.io", "www.passkeys-debugger.io", "demo.yubico.com",
                "webauthn.lubu.ch", "tenant.hanko.io", "unknown.example.com")) {
            assertEquals(original.match(host).id(), restored.match(host).id(), host);
        }

        TargetProfile webauthn = back.stream().filter(p -> p.id().equals("webauthn.io")).findFirst().orElseThrow();
        assertEquals("response.response.signature",
                webauthn.phase(Phase.AUTH_VERIFY).locator(Field.SIGNATURE).candidates().get(0).toString());
        TargetProfile yubico = back.stream().filter(p -> p.id().equals("yubico")).findFirst().orElseThrow();
        assertEquals("attestation.attestationObject.$base64",
                yubico.phase(Phase.REG_VERIFY).locator(Field.ATTESTATION_OBJECT).candidates().get(0).toString());
    }

    @Test
    void defaultCandidatePathsSurviveRoundTrip() {
        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(List.of(BuiltinProfiles.defaultProfile())));
        FieldLocator loc = back.get(0).phase(Phase.REG_VERIFY).locator(Field.CLIENT_DATA_JSON);
        assertEquals(2, loc.candidates().size());
        assertEquals("response.clientDataJSON", loc.candidates().get(0).toString());
        assertEquals("clientDataJSON", loc.candidates().get(1).toString());
    }

    @Test
    void emptyOrGarbageYieldsEmptyList() {
        assertTrue(ProfileJson.fromJson(null).isEmpty());
        assertTrue(ProfileJson.fromJson(new byte[0]).isEmpty());
        assertTrue(ProfileJson.fromJson("not json".getBytes()).isEmpty());
        assertTrue(ProfileJson.fromJson("{\"version\":1}".getBytes()).isEmpty());
    }
}
