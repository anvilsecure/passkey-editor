package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * Bug 1 - un-ticking Enabled must persist a disabled, UNARMED profile (one-click deactivate),
 * never a profile the {@link TargetProfile} compact ctor silently re-enables because an AUTO box stayed ticked.
 *
 * {@link ProfileConfigPanel} is pure Swing over the Burp-free {@link ProfileValidator} + a
 * {@code Consumer<TargetProfile>} Save sink, so the whole Save path runs headlessly here - {@code doClick()}
 * fires real {@code ActionEvent}s (the live-mouse path) and {@code setSelected()} fires none (a programmatic /
 * future-listener bypass). The three tests pin both directions of the master-switch coupling:
 *   - {@link #realClickUntickClearsAutoAndSavesDisabledUnarmed()} - the live-mouse un-tick (listener clears
 *       the AUTO boxes); green before AND after the buildProfile fix (characterization).
 *   - {@link #programmaticUntickStillSavesDisabledUnarmed()} - the REGRESSION PIN: a bypass that leaves the
 *       AUTO boxes ticked must STILL save disabled+unarmed because {@code buildProfile} gates the AUTO flags on
 *       Enabled. RED before the fix (the compact ctor re-enables), GREEN after.
 *   - {@link #armingAutoStillForcesEnabled()} - the forward invariant (arm ⟹ enabled) is intact.
 */
class ProfileConfigPanelBug1Test {

    static {
        // JComponent construction + doClick()/setSelected() need no display; force headless so the suite never
        // depends on a window server and never pops a real frame on a dev machine. (Harmless if AWT already up.)
        System.setProperty("java.awt.headless", "true");
    }

    private static PhaseSpec regSpec() {
        return new PhaseSpec(Map.of(Field.ATTESTATION_OBJECT, FieldLocator.of("response.attestationObject")));
    }

    private static PhaseSpec authSpec() {
        return new PhaseSpec(Map.of(Field.SIGNATURE, FieldLocator.of("response.signature")));
    }

    /** A fully-armed (enabled + autoPlant + autoResign), host-specific profile with both phases configured. */
    private static TargetProfile armedProfile() {
        return new TargetProfile("rp", "RP", HostMatch.exact("rp.test"),
                Map.of(Phase.REG_VERIFY, regSpec(), Phase.AUTH_VERIFY, authSpec()), true)
                .withAutoPlant(true).withAutoResign(true);
    }

    @Test
    void realClickUntickClearsAutoAndSavesDisabledUnarmed() {
        AtomicReference<TargetProfile> saved = new AtomicReference<>();
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), saved::set);
        panel.setProfile(armedProfile()); // 1-arg ⇒ not the Default ⇒ applyDefaultAutoGuard keeps the AUTO boxes

        assertTrue(panel.enabledBox.isSelected(), "armed profile loads Enabled");
        assertTrue(panel.autoPlantBox.isSelected(), "armed profile loads autoPlant ticked");
        assertTrue(panel.autoResignBox.isSelected(), "armed profile loads autoResign ticked");

        panel.enabledBox.doClick(); // live-mouse un-tick - fires the ActionListener that clears the AUTO boxes
        assertFalse(panel.enabledBox.isSelected(), "Enabled now unticked");
        assertFalse(panel.autoPlantBox.isSelected(), "un-tick cleared autoPlant (listener)");
        assertFalse(panel.autoResignBox.isSelected(), "un-tick cleared autoResign (listener)");

        panel.saveButton.doClick();
        TargetProfile p = saved.get();
        assertNotNull(p, "Save emitted a profile");
        assertFalse(p.enabled(), "saved profile is disabled");
        assertFalse(p.autoPlant(), "saved profile is not auto-plant");
        assertFalse(p.autoResign(), "saved profile is not auto-resign");
    }

    @Test
    void programmaticUntickStillSavesDisabledUnarmed() {
        // The regression pin for the REAL defect class. A programmatic enabledBox.setSelected(false) fires NO
        // ActionEvent, so the un-tick listener never runs and the AUTO boxes stay ticked. buildProfile must
        // STILL emit a disabled, unarmed profile - else the compact ctor (enabled = enabled||autoPlant||
        // autoResign) silently re-enables it (the exact Bug-1 shape). RED before the buildProfile gate; GREEN
        // after. Phrased as "the Save path never emits an armed/re-enabled profile after un-tick" - it would
        // also pass a model-level fix, so it pins the contract, not one implementation locus.
        AtomicReference<TargetProfile> saved = new AtomicReference<>();
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), saved::set);
        panel.setProfile(armedProfile());

        panel.enabledBox.setSelected(false); // bypasses the ActionListener - no ActionEvent fired
        assertTrue(panel.autoPlantBox.isSelected(), "AUTO boxes deliberately left ticked (listener not fired)");
        assertTrue(panel.autoResignBox.isSelected());

        panel.saveButton.doClick();
        TargetProfile p = saved.get();
        assertNotNull(p, "Save emitted a profile");
        assertFalse(p.enabled(), "buildProfile gates AUTO on Enabled - no silent re-enable");
        assertFalse(p.autoPlant(), "autoPlant cleared because Enabled is off");
        assertFalse(p.autoResign(), "autoResign cleared because Enabled is off");
    }

    @Test
    void armingAutoStillForcesEnabled() {
        // The downward gate must NOT break the upward one: arming an AUTO box on a disabled profile still ticks
        // Enabled (armTicksEnabled) and saves enabled + armed.
        AtomicReference<TargetProfile> saved = new AtomicReference<>();
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), saved::set);
        panel.setProfile(new TargetProfile("rp", "RP", HostMatch.exact("rp.test"),
                Map.of(Phase.REG_VERIFY, regSpec()), false)); // disabled, unarmed

        assertFalse(panel.enabledBox.isSelected(), "loads disabled");
        panel.autoPlantBox.doClick(); // arm - fires armTicksEnabled ⇒ Enabled ticks on
        assertTrue(panel.enabledBox.isSelected(), "arming auto-plant ticked Enabled");

        panel.saveButton.doClick();
        TargetProfile p = saved.get();
        assertNotNull(p, "Save emitted a profile");
        assertTrue(p.enabled(), "armed ⇒ enabled");
        assertTrue(p.autoPlant(), "auto-plant persisted");
    }
}
