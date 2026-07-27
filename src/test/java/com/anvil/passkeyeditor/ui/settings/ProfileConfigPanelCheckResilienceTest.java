package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The live Check must survive a half-typed / syntactically invalid locator path. The debounced re-check fires
 * on every keystroke, and {@code JsonPath.parse} throws {@code IllegalArgumentException} on an unterminated
 * {@code '['}, a non-integer index, or an empty key. Before the fix that exception escaped uncaught on the EDT
 * (Check-button click and the live timer), aborting the row iteration and dumping a stack trace; the Check
 * path now degrades to a red per-row verdict, mirroring {@link ProfileValidator}'s never-throw contract, while
 * Save keeps surfacing the parse error via its own catch. Runs headlessly, same pattern as the sibling panel tests.
 */
class ProfileConfigPanelCheckResilienceTest {

    static {
        System.setProperty("java.awt.headless", "true");
    }

    private static ProfileConfigPanel panelWithBody() {
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        panel.setProfile(new TargetProfile("rp", "RP", HostMatch.exact("rp.test"), Map.of(), true));
        panel.authBody.setText("{\"response\":{\"signature\":\"AAAA\"}}"); // a body must be present for Check to iterate rows
        return panel;
    }

    @Test
    void checkDoesNotThrowOnUnterminatedBracketPath() {
        ProfileConfigPanel panel = panelWithBody();
        // The operator begins typing an array-root path ("[2].response.signature") and pauses after the '[':
        // JsonPath.parse rejects the unterminated bracket. The Check must not throw.
        panel.typeLocatorForTest(Phase.AUTH_VERIFY, Field.SIGNATURE, "[");

        assertDoesNotThrow(() -> panel.checkButton.doClick());
        assertFalse(panel.status.getText().contains("extract cleanly"),
                "an invalid path must not be greenlit: " + panel.status.getText());
        assertTrue(panel.status.getText().contains("not OK"),
                "the invalid row is flagged, and iteration completed: " + panel.status.getText());
    }

    @Test
    void checkDoesNotThrowOnNonIntegerIndexPath() {
        ProfileConfigPanel panel = panelWithBody();
        panel.typeLocatorForTest(Phase.AUTH_VERIFY, Field.SIGNATURE, "[abc].response");
        assertDoesNotThrow(() -> panel.checkButton.doClick());
    }

    @Test
    void checkRecoversWhenPathBecomesValid() {
        ProfileConfigPanel panel = panelWithBody();
        panel.typeLocatorForTest(Phase.AUTH_VERIFY, Field.SIGNATURE, "["); // invalid: flagged, no throw
        panel.checkButton.doClick();
        panel.typeLocatorForTest(Phase.AUTH_VERIFY, Field.SIGNATURE, "response.signature"); // now valid
        assertDoesNotThrow(() -> panel.checkButton.doClick());
        assertTrue(panel.status.getText().contains("extract cleanly"),
                "a valid path resolves cleanly after a prior invalid one: " + panel.status.getText());
    }
}
