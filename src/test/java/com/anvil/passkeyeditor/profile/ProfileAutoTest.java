package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Per-profile AUTO model gates: the {@code enabled} / {@code autoPlant} / {@code autoResign} switches under
 * the arm ⟹ enabled invariant ({@code Enabled} is the master switch - arming forces it, so there is
 * no armed-but-disabled "auto-only" state), the {@link ProfileRegistry#matchAuto} gate (the Default is never
 * auto-eligible), and {@link ProfileJson} v4 round-trip + back-compat. The matching gates are the freeze /
 * safety story for AUTO at the data layer.
 */
class ProfileAutoTest {

    private static PhaseSpec authSpec() {
        return new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")));
    }

    private static PhaseSpec authSpecScoped(String contains) {
        return new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")),
                new UrlMatch(UrlMatch.Kind.CONTAINS, contains, null));
    }

    private static PhaseSpec regSpec() {
        return new PhaseSpec(Map.of(Field.ATTESTATION_OBJECT, FieldLocator.of("response.attestationObject")));
    }

    private static TargetProfile profile(String id, String host, boolean enabled, boolean autoPlant,
                                         boolean autoResign, Map<Phase, PhaseSpec> phases) {
        return new TargetProfile(id, id, HostMatch.exact(host), phases, enabled)
                .withAutoPlant(autoPlant).withAutoResign(autoResign);
    }

    private static ProfileRegistry registryOf(TargetProfile... profiles) {
        return new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(profiles));
    }

    @Test
    void matchAutoNeverReturnsDefaultForAnUnprofiledHost() {
        ProfileRegistry reg = registryOf();
        assertNull(reg.matchAuto("unprofiled.local", Phase.AUTH_VERIFY, "https://unprofiled.local/verify", "POST"),
                "an unprofiled host is structurally non-auto-eligible (the Default carries no auto flags)");
        assertNull(reg.matchAuto("unprofiled.local", Phase.REG_VERIFY, "https://unprofiled.local/reg", "POST"));
    }

    @Test
    void autoResignProfileMatchesAuthOnly_andArmImpliesEnabled() {
        TargetProfile ar = profile("ar", "rp.test", false, false, true, Map.of(Phase.AUTH_VERIFY, authSpec()));
        ProfileRegistry reg = registryOf(ar);
        // Arm ⟹ Enabled: the helper passed enabled=false, but autoResign forces it enabled (master switch),
        // so the profile is ALSO visible to the manual tab - no more "auto-only" invisible state.
        assertTrue(ar.enabled(), "arming auto-resign forces Enabled");
        assertEquals("ar", reg.match("rp.test").id(), "an armed profile is enabled ⇒ visible to the manual tab");
        assertEquals("ar", reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST").id());
        assertNull(reg.matchAuto("rp.test", Phase.REG_VERIFY, "https://rp.test/reg", "POST"),
                "autoResign does not arm registration");
    }

    @Test
    void armingForcesEnabled() {
        // The master-switch invariant: any AUTO flag implies Enabled even if constructed disabled.
        assertTrue(new TargetProfile("a", "A", HostMatch.exact("a"), Map.of(), false).withAutoPlant(true).enabled(),
                "autoPlant forces enabled");
        assertTrue(new TargetProfile("a", "A", HostMatch.exact("a"), Map.of(), false).withAutoResign(true).enabled(),
                "autoResign forces enabled");
        assertFalse(new TargetProfile("a", "A", HostMatch.exact("a"), Map.of(), false).enabled(),
                "no AUTO flag ⇒ a disabled profile stays disabled");
    }

    @Test
    void autoPlantProfileMatchesRegOnly() {
        TargetProfile ap = profile("ap", "rp.test", false, true, false, Map.of(Phase.REG_VERIFY, regSpec()));
        ProfileRegistry reg = registryOf(ap);
        assertEquals("ap", reg.matchAuto("rp.test", Phase.REG_VERIFY, "https://rp.test/reg", "POST").id());
        assertNull(reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST"));
    }

    @Test
    void allOffProfileIsInertToBothGates() {
        TargetProfile off = profile("off", "rp.test", false, false, false, Map.of(Phase.AUTH_VERIFY, authSpec()));
        ProfileRegistry reg = registryOf(off);
        assertEquals(reg.defaultProfile(), reg.match("rp.test"));
        assertNull(reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST"));
    }

    @Test
    void matchAutoRespectsThePhaseUrlScope() {
        TargetProfile ar = profile("ar", "rp.test", false, false, true,
                Map.of(Phase.AUTH_VERIFY, authSpecScoped("/verify")));
        ProfileRegistry reg = registryOf(ar);
        assertNull(reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/login", "POST"),
                "a pinned verify URL the request fails ⇒ AUTO does not act");
        assertEquals("ar", reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST").id());
    }

    @Test
    void matchAutoSkipsAnArmedButPhaselessProfile() {
        // "first" is armed for autoResign but defines only REG_VERIFY → it must NOT shadow a later profile
        // that actually defines AUTH_VERIFY (audit F9 - else the handler matches it then no-ops).
        TargetProfile first = profile("first", "rp.test", false, false, true, Map.of(Phase.REG_VERIFY, regSpec()));
        TargetProfile complete = profile("second", "rp.test", false, false, true, Map.of(Phase.AUTH_VERIFY, authSpec()));
        ProfileRegistry reg = registryOf(first, complete);
        assertEquals("second", reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST").id(),
                "an armed-but-phaseless profile is skipped so a later complete profile matches");
    }

    @Test
    void hasArmedProfileReflectsAnyAutoFlag() {
        assertFalse(registryOf(profile("m", "rp.test", true, false, false, Map.of(Phase.AUTH_VERIFY, authSpec())))
                .hasArmedProfile(), "an enabled-but-unarmed profile is not 'armed'");
        assertTrue(registryOf(profile("ar", "rp.test", false, false, true, Map.of(Phase.AUTH_VERIFY, authSpec())))
                .hasArmedProfile(), "an auto-resign profile counts as armed");
    }

    @Test
    void matchAutoIsFirstMatchWins() {
        TargetProfile a = profile("a", "rp.test", false, false, true, Map.of(Phase.AUTH_VERIFY, authSpec()));
        TargetProfile b = profile("b", "rp.test", false, false, true, Map.of(Phase.AUTH_VERIFY, authSpec()));
        ProfileRegistry reg = registryOf(a, b);
        assertEquals("a", reg.matchAuto("rp.test", Phase.AUTH_VERIFY, "https://rp.test/verify", "POST").id());
    }

    @Test
    void profileJsonV4RoundTripsAutoFlags() {
        TargetProfile armed = profile("x", "rp.test", true, true, true, Map.of(Phase.AUTH_VERIFY, authSpec()));
        TargetProfile back = ProfileJson.fromJson(ProfileJson.toJson(List.of(armed))).get(0);
        assertTrue(back.autoPlant(), "autoPlant round-trips");
        assertTrue(back.autoResign(), "autoResign round-trips");
    }

    @Test
    void preV4StoreLoadsAutoInert() {
        // A v3-shaped store (no autoPlant/autoResign keys) must load with BOTH false - freeze-safe.
        String v3 = "{\"version\":3,\"profiles\":[{\"id\":\"x\",\"name\":\"X\",\"enabled\":true,\"signer\":-7,"
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"rp.test\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"paths\":[\"response.signature\"]}}}}}]}";
        TargetProfile back = ProfileJson.fromJson(v3.getBytes(StandardCharsets.UTF_8)).get(0);
        assertFalse(back.autoPlant(), "absent autoPlant → false");
        assertFalse(back.autoResign(), "absent autoResign → false");
        assertTrue(back.enabled(), "enabled still honoured");
    }

    @Test
    void garbageAutoValueDefaultsFalse() {
        String bad = "{\"version\":4,\"profiles\":[{\"id\":\"x\",\"name\":\"X\",\"enabled\":true,\"autoResign\":\"yes\","
                + "\"host\":{\"kind\":\"EXACT\",\"pattern\":\"rp.test\"},"
                + "\"phases\":{\"AUTH_VERIFY\":{\"fields\":{\"SIGNATURE\":{\"paths\":[\"response.signature\"]}}}}}]}";
        TargetProfile back = ProfileJson.fromJson(bad.getBytes(StandardCharsets.UTF_8)).get(0);
        assertFalse(back.autoResign(), "a non-boolean autoResign must not flip the default (no silent arm)");
    }

    @Test
    void backCompatConstructorsDefaultAutoOff() {
        TargetProfile fourArg = new TargetProfile("a", "A", HostMatch.exact("a"), Map.of());
        assertFalse(fourArg.autoPlant());
        assertFalse(fourArg.autoResign());
        TargetProfile eightArg = new TargetProfile("a", "A", HostMatch.exact("a"), Map.of(),
                true, null, null, SignerSpec.ES256);
        assertFalse(eightArg.autoResign(), "the 8-arg (pre-AUTO) ctor defaults AUTO off");
    }

    @Test
    void autoActsForMapsPhaseToFlag() {
        TargetProfile ap = new TargetProfile("a", "A", HostMatch.exact("a"), Map.of()).withAutoPlant(true);
        assertTrue(ap.autoActsFor(Phase.REG_VERIFY));
        assertFalse(ap.autoActsFor(Phase.AUTH_VERIFY));
        TargetProfile ar = new TargetProfile("a", "A", HostMatch.exact("a"), Map.of()).withAutoResign(true);
        assertTrue(ar.autoActsFor(Phase.AUTH_VERIFY));
        assertFalse(ar.autoActsFor(Phase.REG_VERIFY));
    }
}
