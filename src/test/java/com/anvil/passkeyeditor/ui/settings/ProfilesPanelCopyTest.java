package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.PlantAttestation;
import com.anvil.passkeyeditor.profile.SignerSpec;
import com.anvil.passkeyeditor.profile.TargetProfile;

import org.junit.jupiter.api.Test;

/**
 * Pins the "Copy profile" composition ({@link ProfilesPanel#duplicateProfile}) - the exact path a first-pass
 * review found silently dropped {@code plantAttestation} (it builds via the 8-arg TargetProfile ctor, which
 * defaults the field to NONE, then must re-apply it). A revert of that re-apply must fail this test.
 */
class ProfilesPanelCopyTest {

    @Test
    void copyPreservesOperatorConfigButStagesDisabledAndAutoOff() {
        TargetProfile src = BuiltinProfiles.defaultProfile()
                .withPlantAttestation(PlantAttestation.PACKED_SELF)
                .withSigner(SignerSpec.EDDSA)
                .withAutoPlant(true); // source is armed + enabled

        TargetProfile copy = ProfilesPanel.duplicateProfile(src, "default-copy");

        // Operator-chosen configuration is carried over...
        assertEquals(PlantAttestation.PACKED_SELF, copy.plantAttestation(),
                "copy carries the source's plant attestation format");
        assertEquals(SignerSpec.EDDSA.coseAlg(), copy.signer().coseAlg(), "copy carries the source's signer alg");
        assertEquals("default-copy", copy.id());
        // ...but activation state is NOT (a copy must be validated + re-armed before it touches traffic).
        assertFalse(copy.enabled(), "copy is staged disabled");
        assertFalse(copy.autoPlant(), "copy is AUTO-off");
        assertFalse(copy.autoResign(), "copy is AUTO-off");
    }
}
