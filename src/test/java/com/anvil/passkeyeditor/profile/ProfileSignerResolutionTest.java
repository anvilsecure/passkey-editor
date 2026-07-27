package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * composition gate (audit finding F7). The ceremony editor's chooser pre-selects the
 * matched profile's default algorithm and "Register with our key" plants a signer of that algorithm - but
 * the editor itself is Burp/Swing-coupled and cannot be instantiated headlessly. This gates the Burp-free
 * decision the editor delegates to: {@code profile.signer().coseAlg()} → {@link SignerAlgorithm#forCoseIdOrDefault}
 * → {@link SignerAlgorithm#generate()}, i.e. the headline claim that planting on webauthn.io defaults to EdDSA.
 */
final class ProfileSignerResolutionTest {

    private static Map<String, TargetProfile> mainstreamById() {
        Map<String, TargetProfile> m = new HashMap<>();
        for (TargetProfile p : RpFixtureProfiles.all()) {
            m.put(p.id(), p);
        }
        return m;
    }

    /** The Burp-free resolution the editor performs: a profile's signer COSE id → a concrete signer. */
    private static CoseSigner plantSignerFor(TargetProfile p) {
        return SignerAlgorithm.forCoseIdOrDefault(p.signer().coseAlg(), SignerAlgorithm.ES256).generate();
    }

    @Test
    void builtinProfilesResolveToTheExpectedSignerAlgorithm() {
        Map<String, TargetProfile> byId = mainstreamById();
        // The captured-Ed25519 RPs resolve to EdDSA, so the chooser pre-selects EdDSA and the plant is Ed25519.
        for (String id : new String[]{"webauthn.io", "passkeys-debugger", "lubu"}) {
            assertEquals(SignerAlgorithm.EDDSA,
                    SignerAlgorithm.forCoseIdOrDefault(byId.get(id).signer().coseAlg(), SignerAlgorithm.ES256),
                    id + " resolves to EdDSA");
            assertEquals(-8, plantSignerFor(byId.get(id)).coseAlg(), id + " plants an EdDSA (-8) signer");
        }
        // The others resolve to ES256.
        for (String id : new String[]{"hanko", "yubico"}) {
            assertEquals(SignerAlgorithm.ES256,
                    SignerAlgorithm.forCoseIdOrDefault(byId.get(id).signer().coseAlg(), SignerAlgorithm.ES256),
                    id + " resolves to ES256");
            assertEquals(-7, plantSignerFor(byId.get(id)).coseAlg(), id + " plants an ES256 (-7) signer");
        }
    }

    @Test
    void defaultProfilePlantsEs256() {
        // The freeze anchor at the resolution level: the Default plants ES256 end-to-end.
        assertEquals(-7, plantSignerFor(BuiltinProfiles.defaultProfile()).coseAlg(),
                "Default profile must plant ES256 (freeze-safe default path)");
    }

    @Test
    void forCoseIdOrDefaultRoundTripsEverySupportedAlgAndFallsBackOnUnknown() {
        for (SignerAlgorithm a : SignerAlgorithm.values()) {
            // A known id resolves to itself, never to the fallback (use EDDSA as a wrong-on-purpose fallback).
            assertEquals(a, SignerAlgorithm.forCoseIdOrDefault(a.coseId(), SignerAlgorithm.EDDSA),
                    a + " resolves to itself");
        }
        assertEquals(SignerAlgorithm.ES256, SignerAlgorithm.forCoseIdOrDefault(-999, SignerAlgorithm.ES256),
                "an unsupported COSE id degrades to the fallback (never throws)");
    }
}
