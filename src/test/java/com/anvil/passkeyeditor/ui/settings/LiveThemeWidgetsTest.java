package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.ui.Palette;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The panels that keep operator state cannot be rebuilt on a theme change, so they re-colour instead -
 * and the first cut of that missed everything except the titles. The "AUTO rewrites live traffic"
 * caption in particular stayed on the previous theme's red, which is exactly the kind of leftover that
 * reads as a broken extension.
 *
 * These tests flip the theme the way a host does and assert each individual widget followed,
 * including the ones whose colour carries a meaning that is chosen at runtime: the status line's
 * tone and a field's Check verdict must survive the switch without being recomputed by the caller.
 */
class LiveThemeWidgetsTest {

    private static final Color DARK_BG = new Color(0x3C, 0x3F, 0x41);
    private static final Color LIGHT_BG = new Color(0xF2, 0xF2, 0xF2);

    @AfterEach
    void resetTheme() {
        UIManager.put("Panel.background", null);
        UIManager.put("Label.foreground", null);
    }

    private static void theme(Color background, Color foreground) {
        UIManager.put("Panel.background", background);
        UIManager.put("Label.foreground", foreground);
    }

    private static void switchThemeTo(Color background, Color foreground, Component root) throws Exception {
        theme(background, foreground);
        SwingUtilities.updateComponentTreeUI(root);
        drain();
    }

    private static void drain() throws InterruptedException, InvocationTargetException {
        for (int i = 0; i < 3; i++) {
            SwingUtilities.invokeAndWait(() -> { });
        }
    }

    /** The armed-AUTO warning: coloured once at construction, and the first one seen to go stale. */
    @Test
    void autoWarningCaptionFollowsALiveThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        Component root = panel.component();

        Color onLight = captionColor(panel);
        assertEquals(Palette.error(), onLight, "the caption should start on the light theme's red");

        switchThemeTo(DARK_BG, Color.WHITE, root);

        Color onDark = captionColor(panel);
        assertNotEquals(onLight, onDark, "'AUTO rewrites live traffic' kept the light theme's red");
        assertEquals(Palette.error(), onDark, "the caption is not the dark theme's red");
        assertTrue(contrast(onDark, DARK_BG) >= 4.5, "the caption is only "
                + String.format("%.2f", contrast(onDark, DARK_BG)) + ":1 on dark");
    }

    /** The status line's tone is picked at runtime; whatever it last said must re-colour in that tone. */
    @Test
    void statusLineKeepsItsToneAcrossAThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        Component root = panel.component();
        panel.setProfile(RpFixtureProfiles.all().get(0));

        // Drive a real status message: Check with no bodies pasted reports the muted prompt.
        panel.checkButton.doClick();
        Color onLight = panel.status.getForeground();
        String text = panel.status.getText();

        switchThemeTo(DARK_BG, Color.WHITE, root);

        assertEquals(text, panel.status.getText(), "the status text should be untouched");
        assertNotEquals(onLight, panel.status.getForeground(), "the status line kept the light colour");
        assertTrue(contrast(panel.status.getForeground(), DARK_BG) >= 4.5,
                "the status line is unreadable on dark after the switch");
    }

    /** A per-field Check verdict must keep its meaning (green/amber/red), not just any new colour. */
    @Test
    void checkVerdictKeepsItsMeaningAcrossAThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });
        Component root = panel.component();
        panel.setProfile(RpFixtureProfiles.all().get(0));
        panel.regBody.setText("{\"nothing\":\"here\"}");   // fields will not be found -> red verdicts
        panel.checkButton.doClick();

        Color verdictOnLight = firstVerdictColor(root);
        assertEquals(Palette.error(), verdictOnLight, "expected a NOT_FOUND verdict in the light red");

        switchThemeTo(DARK_BG, Color.WHITE, root);

        Color verdictOnDark = firstVerdictColor(root);
        assertNotEquals(verdictOnLight, verdictOnDark, "the verdict kept the light theme's red");
        assertEquals(Palette.error(), verdictOnDark, "the verdict lost its meaning across the switch");
    }

    /** Section headings colour their text and their underline from the accent; both must follow. */
    @Test
    void sectionHeadingFollowsALiveThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        Component heading = UiStyle.heading("Profiles");
        Color onLight = firstLabel(heading).getForeground();

        switchThemeTo(DARK_BG, Color.WHITE, heading);

        Color onDark = firstLabel(heading).getForeground();
        assertNotEquals(onLight, onDark, "the heading kept the light theme's accent");
        assertEquals(Palette.accent(), onDark, "the heading is not the dark theme's accent");
    }

    // ---- harness -----------------------------------------------------------------------------------

    /** The AUTO caption is the label carrying that exact text. */
    private static Color captionColor(ProfileConfigPanel panel) {
        JLabel found = findLabel(panel.component(), "AUTO rewrites live traffic");
        assertTrue(found != null, "AUTO caption label not found - the harness is broken");
        return found.getForeground();
    }

    /** The first per-field Check verdict label carrying a real message. */
    private static Color firstVerdictColor(Component root) {
        JLabel verdict = findVerdict(root);
        assertTrue(verdict != null, "no Check verdict label found - the harness is broken");
        return verdict.getForeground();
    }

    private static JLabel findVerdict(Component c) {
        if (c instanceof JLabel l && l.getText() != null && !l.getText().isBlank()
                && l.getForeground() != null
                && (l.getForeground().equals(Palette.error()) || l.getForeground().equals(Palette.ok())
                    || l.getForeground().equals(Palette.warn()))
                && !"AUTO rewrites live traffic".equals(l.getText())) {
            return l;
        }
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) {
                JLabel hit = findVerdict(child);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    private static JLabel findLabel(Component c, String text) {
        if (c instanceof JLabel l && text.equals(l.getText())) {
            return l;
        }
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) {
                JLabel hit = findLabel(child, text);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    private static JLabel firstLabel(Component c) {
        if (c instanceof JLabel l) {
            return l;
        }
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) {
                JLabel hit = firstLabel(child);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    private static double contrast(Color a, Color b) {
        double la = luminance(a);
        double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    private static double luminance(Color c) {
        return 0.2126 * channel(c.getRed()) + 0.7152 * channel(c.getGreen()) + 0.0722 * channel(c.getBlue());
    }

    private static double channel(int v) {
        double s = v / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }
}
