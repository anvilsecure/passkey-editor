package com.anvil.passkeyeditor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.SignerSpec;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The load-time Output summary ({@link PasskeyEditorExtension#describeProfiles}) - the per-project visibility
 * the operator asked for: one readable line per profile (host, enabled, AUTO arming, default algorithm), so
 * the Output tab confirms which targets THIS Burp project carries and how each is configured. The builder is
 * pure / Burp-free, so it is pinned headlessly here even though it is logged from the Burp entry point.
 */
class PasskeyEditorExtensionTest {

    private static TargetProfile profile(String id, String name, HostMatch host) {
        return new TargetProfile(id, name, host, Map.<Phase, PhaseSpec>of());
    }

    @Test
    void seededRunDescribesHeaderTheDefaultAndEveryListedProfile() {
        ProfileRegistry reg = RpFixtureProfiles.seededRegistry();
        List<String> lines = PasskeyEditorExtension.describeProfiles(reg, true);

        assertEquals(reg.profiles().size() + 2, lines.size(), "header + Default + one line per listed profile");
        assertTrue(lines.get(0).contains("seeded"), "a seeded run says so: " + lines.get(0));
        // The Default counts towards the total and is rendered as an ordinary row, not a special "Default:"
        // prefix - it is just a profile that cannot be deleted or AUTO-armed.
        assertTrue(lines.get(0).contains((reg.profiles().size() + 1) + " profile(s)"), lines.get(0));
        assertTrue(lines.get(1).startsWith("  - ") && lines.get(1).contains("Default"),
                "the second line is the Default, bulleted like the rest: " + lines.get(1));

        // webauthn.io seeds enabled, AUTO off, EdDSA (Duo py_webauthn offers Ed25519).
        String io = lines.stream().filter(l -> l.contains("webauthn.io (Duo")).findFirst().orElseThrow();
        assertTrue(io.contains("[enabled]") && io.contains("plant=off") && io.contains("re-sign=off")
                && io.contains("alg=EdDSA") && io.contains("host=webauthn.io"), io);
    }

    /**
     * What a real fresh project now prints: the Default alone. RP presets no longer seed, so this two-line
     * summary (header + one bulleted row) is the first thing every operator sees.
     */
    @Test
    void freshProjectDescribesTheDefaultAlone() {
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of());

        List<String> lines = PasskeyEditorExtension.describeProfiles(reg, true);

        assertEquals(2, lines.size(), "header + the Default row only: " + lines);
        assertTrue(lines.get(0).startsWith("1 profile(s) seeded"), lines.get(0));
        assertTrue(lines.get(1).contains("Default (SimpleWebAuthn / generic)")
                && lines.get(1).contains("host=any") && lines.get(1).contains("[enabled]")
                && lines.get(1).contains("plant=off") && lines.get(1).contains("re-sign=off"), lines.get(1));
    }

    @Test
    void loadedRunHeaderDistinguishesFromSeeded() {
        List<String> lines = PasskeyEditorExtension.describeProfiles(RpFixtureProfiles.seededRegistry(), false);
        assertTrue(lines.get(0).contains("loaded from this Burp project"), lines.get(0));
    }

    @Test
    void rendersDisabledAndArmedFlagsAndHostKinds() {
        TargetProfile disabled = profile("d", "Disabled One", HostMatch.exact("ex.com")).withEnabled(false);
        TargetProfile armed = profile("a", "Armed One", HostMatch.suffix(".hanko.io"))
                .withAutoPlant(true).withAutoResign(true).withSigner(SignerSpec.EDDSA);
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(disabled, armed));

        List<String> lines = PasskeyEditorExtension.describeProfiles(reg, false);
        String d = lines.stream().filter(l -> l.contains("Disabled One")).findFirst().orElseThrow();
        String a = lines.stream().filter(l -> l.contains("Armed One")).findFirst().orElseThrow();

        assertTrue(d.contains("[disabled]") && d.contains("host=ex.com")
                && d.contains("plant=off") && d.contains("re-sign=off"), d);
        // Arming forces Enabled (the compact ctor), and the suffix host renders as *.hanko.io.
        assertTrue(a.contains("[enabled]") && a.contains("plant=on") && a.contains("re-sign=on")
                && a.contains("host=*.hanko.io") && a.contains("alg=EdDSA"), a);
    }
}
