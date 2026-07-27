package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The Check panel's verdict must not mislead - the panel exists so the operator can be SURE their
 * path/regex + encoding are set right, so a body present with ZERO configured locators must NOT report the
 * green "all fields extract cleanly" (it extracts nothing). Runs the whole Check path headlessly (pure Swing
 * over the Burp-free {@link ProfileValidator}), same pattern as {@link ProfileConfigPanelBug1Test}.
 */
class ProfileConfigPanelCheckTest {

    static {
        System.setProperty("java.awt.headless", "true");
    }

    /** A body pasted against a profile with NO locators configured is flagged, not greenlit. */
    @Test
    void bodyWithNoConfiguredLocatorsIsNotReportedAsSuccess() {
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        panel.setProfile(new TargetProfile("rp", "RP", HostMatch.exact("rp.test"), Map.of(), true)); // no phase specs → all rows blank
        panel.authBody.setText("{\"response\":{\"signature\":\"AAAA\"}}");

        panel.checkButton.doClick();

        assertFalse(panel.status.getText().contains("extract cleanly"),
                "a profile with no locators must NOT be greenlit: " + panel.status.getText());
        assertTrue(panel.status.getText().contains("no fields configured"), panel.status.getText());
    }

    /** With at least one locator configured and matching, Check reports the green success + the count. */
    @Test
    void configuredAndMatchingReportsGreenSuccessWithCount() {
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        panel.setProfile(new TargetProfile("rp", "RP", HostMatch.exact("rp.test"),
                Map.of(Phase.AUTH_VERIFY, new PhaseSpec(Map.of(
                        Field.SIGNATURE, FieldLocator.of("response.signature")))), true));
        panel.authBody.setText("{\"response\":{\"signature\":\"AAAA\"}}"); // decodes to raw bytes → signature OK

        panel.checkButton.doClick();

        assertTrue(panel.status.getText().contains("extract cleanly"), panel.status.getText());
        assertTrue(panel.status.getText().contains("1 configured"), panel.status.getText());
    }
}
