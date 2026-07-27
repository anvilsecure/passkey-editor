package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Pins the per-profile {@link PlantAttestation} setting: its freeze-safe default (NONE), that {@code with*}
 * copies preserve it, and that it (de)serialises through {@link ProfileJson} v5 - including that a pre-v5
 * store (no {@code plantAttestation} field) loads as NONE so an existing store is never silently changed.
 */
class PlantAttestationProfileTest {

    @Test
    void defaultsToNoneAndNullNormalises() {
        assertEquals(PlantAttestation.NONE, BuiltinProfiles.defaultProfile().plantAttestation(),
                "the built-in Default plants fmt=none (freeze-safe)");
        for (TargetProfile p : RpFixtureProfiles.all()) {
            assertEquals(PlantAttestation.NONE, p.plantAttestation(), p.id() + " defaults to NONE");
        }
        // A null in the canonical constructor normalises to NONE (never a null field).
        TargetProfile nulled = new TargetProfile("x", "x", new HostMatch(HostMatch.Kind.EXACT, "x"),
                BuiltinProfiles.defaultProfile().phases(), true, null, null, SignerSpec.ES256, false, false, null);
        assertEquals(PlantAttestation.NONE, nulled.plantAttestation(), "null plantAttestation normalises to NONE");
    }

    @Test
    void withCopiesPreservePlantAttestation() {
        TargetProfile packed = BuiltinProfiles.defaultProfile().withPlantAttestation(PlantAttestation.PACKED_SELF);
        assertEquals(PlantAttestation.PACKED_SELF, packed.plantAttestation());
        // Every unrelated with* copy must keep the setting (they reconstruct the whole record).
        assertEquals(PlantAttestation.PACKED_SELF, packed.withEnabled(true).plantAttestation());
        assertEquals(PlantAttestation.PACKED_SELF, packed.withSigner(SignerSpec.EDDSA).plantAttestation());
        assertEquals(PlantAttestation.PACKED_SELF, packed.withAutoPlant(true).plantAttestation());
        assertEquals(PlantAttestation.PACKED_SELF, packed.withAutoResign(true).plantAttestation());
        assertEquals(PlantAttestation.PACKED_SELF, packed.withSamples("r", "a").plantAttestation());
    }

    @Test
    void jsonRoundTripsPackedSelf() {
        TargetProfile p = RpFixtureProfiles.all().get(0).withPlantAttestation(PlantAttestation.PACKED_SELF);
        List<TargetProfile> back = ProfileJson.fromJson(ProfileJson.toJson(List.of(p)));
        assertEquals(1, back.size());
        assertEquals(PlantAttestation.PACKED_SELF, back.get(0).plantAttestation(),
                "PACKED_SELF survives a persistence round-trip");
    }

    @Test
    void preV5StoreWithoutFieldLoadsAsNone() {
        // A v4 document (no plantAttestation key) must load as NONE - an existing store is never silently changed.
        String v4 = "{\"version\":4,\"profiles\":[{\"id\":\"x\",\"name\":\"x\",\"enabled\":true,"
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"x\"},"
                + "\"phases\":{\"REG_VERIFY\":{\"fields\":{\"ATTESTATION_OBJECT\":"
                + "{\"kind\":\"PATH\",\"paths\":[\"attestationObject\"]}}}}}]}";
        List<TargetProfile> back = ProfileJson.fromJson(v4.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(1, back.size());
        assertEquals(PlantAttestation.NONE, back.get(0).plantAttestation());
    }

    @Test
    void fromNameIsTolerant() {
        assertEquals(PlantAttestation.NONE, PlantAttestation.fromName(null));
        assertEquals(PlantAttestation.NONE, PlantAttestation.fromName("BOGUS"));
        assertEquals(PlantAttestation.NONE, PlantAttestation.fromName("none")); // case-sensitive: not the constant
        assertEquals(PlantAttestation.NONE, PlantAttestation.fromName("NONE"));
        assertEquals(PlantAttestation.PACKED_SELF, PlantAttestation.fromName("PACKED_SELF"));
    }
}
