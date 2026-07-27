package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.ProfileValidator;

import java.awt.Component;
import java.awt.Container;

import javax.swing.JScrollPane;

import org.junit.jupiter.api.Test;

/**
 * Guards the "squashed boxes" regression: laid out in a pane SHORTER than its content, the config must scroll
 * vertically and keep every box at full height - it must NOT collapse the Registration / Authentication field
 * rows or flatten the sample-body boxes to one line. That collapse happened once the field rows were wrapped
 * in a horizontal scroll pane: the box's minimum height dropped to a scrollbar's worth, and the GridBag glue
 * row (weighty=1, packs boxes to the top) then handed itself all the surplus and starved the boxes down to
 * that minimum. {@code RigidHeightPanel} pins min-height = preferred-height to stop it.
 */
class ProfileConfigPanelLayoutTest {

    @Test
    void shortPaneScrollsInsteadOfSquashingTheBoxes() {
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        panel.setProfile(RpFixtureProfiles.all().get(0));
        panel.regBody.setText("{\"username\":\"alice\",\"response\":{\"id\":\"AAAA\"}}");
        panel.authBody.setText("{\"username\":\"alice\",\"response\":{\"id\":\"AAAA\"}}");

        Container root = (Container) panel.component();
        // Deliberately short: less than the content's natural height, forcing the choice scroll-vs-squash.
        layoutTree(root, 900, 380);

        JScrollPane outer = (JScrollPane) root.getComponent(0);
        Container center = (Container) outer.getViewport().getView();

        assertTrue(outer.getVerticalScrollBar().isVisible(),
                "a short pane should scroll vertically, not shrink the content to fit");
        assertEquals(center.getPreferredSize().height, center.getSize().height,
                "the content column should be laid out at its full preferred height (scrolled), not clamped");

        // Boxes at GridBag rows 1/2/3 are Registration / Authentication / Sample-bodies. Each must keep its
        // full preferred height - if the glue starved any to its minimum, the rows/bodies would be hidden.
        for (int row : new int[]{1, 2, 3}) {
            Component box = center.getComponent(row);
            assertEquals(box.getPreferredSize().height, box.getSize().height,
                    "box at GridBag row " + row + " must not be squashed below its preferred height");
            // Also pin the RigidHeightPanel override directly (min-height == preferred-height). The size==pref
            // check above already fails on revert (GridBag collapses the box to its minimum, which drops to a
            // scroll pane's ~scrollbar height), but this second assertion documents the introduced invariant
            // independently of GridBag's deficit-distribution behavior.
            assertEquals(box.getPreferredSize().height, box.getMinimumSize().height,
                    "box at GridBag row " + row + " must pin its minimum height to preferred (RigidHeightPanel)");
        }
    }

    /** Top-down layout without a native peer - enough to exercise the GridBag / viewport / scroll-pane math. */
    private static void layoutTree(Component c, int w, int h) {
        c.setSize(w, h);
        if (c instanceof Container cont) {
            cont.doLayout();
            for (Component child : cont.getComponents()) {
                layoutTree(child, child.getWidth(), child.getHeight());
            }
        }
    }
}
