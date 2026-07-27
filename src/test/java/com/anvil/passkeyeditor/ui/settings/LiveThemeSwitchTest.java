package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JEditorPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.LabelView;
import javax.swing.text.View;
import javax.swing.text.html.HTML;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Burp switches Light/Dark live, and its own widgets follow because their colours come from the
 * look and feel. Ours do not - a colour set with {@code setForeground} is not a {@code UIResource}, so
 * Swing leaves it alone, and a colour baked into an HTML string is further out of reach still. Left
 * alone the extension keeps the old palette until it is reloaded, which reads as the extension being
 * broken rather than stale.
 *
 * {@code ThemedPanel} closes that: Swing calls {@code updateUI()} on every component when the look
 * and feel changes, and by then {@link com.anvil.passkeyeditor.ui.Palette} already reports the new
 * theme. These tests drive the same sequence a host does - swap the theme, walk the tree - and assert
 * the rendered colour actually followed, with no rebuild by the caller.
 */
class LiveThemeSwitchTest {

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

    /** What a host does on a theme change: new defaults, then a walk over the component tree. */
    private static void switchThemeTo(Color background, Color foreground, Component root) throws Exception {
        theme(background, foreground);
        SwingUtilities.updateComponentTreeUI(root);
        drainEventQueue();   // ThemedPanel defers its rebuild off the tree walk
    }

    /** ThemedPanel re-applies via invokeLater; let that run before asserting. */
    private static void drainEventQueue() throws InterruptedException, InvocationTargetException {
        for (int i = 0; i < 3; i++) {
            SwingUtilities.invokeAndWait(() -> { });
        }
    }

    @Test
    void aboutTabFollowsALiveThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        AboutPanel panel = new AboutPanel();
        Component root = panel.component();
        layoutTree(root, 1000, 800);
        Color onLight = linkColorIn(root);

        switchThemeTo(DARK_BG, Color.WHITE, root);
        layoutTree(root, 1000, 800);
        Color onDark = linkColorIn(root);

        assertNotEquals(onLight, onDark, "the About link kept the light theme's colour after the switch");
        assertTrue(contrast(onDark, DARK_BG) >= 4.5, "after the switch the link is only "
                + String.format("%.2f", contrast(onDark, DARK_BG)) + ":1 on dark");
    }

    @Test
    void guideTabFollowsALiveThemeSwitch() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        GuidePanel panel = new GuidePanel();
        Component root = panel.component();
        layoutTree(root, 1200, 1400);
        Color onLight = linkColorIn(root);

        switchThemeTo(DARK_BG, Color.WHITE, root);
        layoutTree(root, 1200, 1400);
        Color onDark = linkColorIn(root);

        assertNotEquals(onLight, onDark, "the Guide link kept the light theme's colour after the switch");
        assertTrue(contrast(onDark, DARK_BG) >= 4.5, "after the switch the link is only "
                + String.format("%.2f", contrast(onDark, DARK_BG)) + ":1 on dark");
    }

    /** Switching back must restore the light palette, not leave the panel stuck on dark. */
    @Test
    void switchingBackRestoresTheLightPalette() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        AboutPanel panel = new AboutPanel();
        Component root = panel.component();
        layoutTree(root, 1000, 800);
        Color first = linkColorIn(root);

        switchThemeTo(DARK_BG, Color.WHITE, root);
        layoutTree(root, 1000, 800);
        switchThemeTo(LIGHT_BG, Color.BLACK, root);
        layoutTree(root, 1000, 800);

        assertEquals(first, linkColorIn(root), "did not return to the light palette");
    }

    /** A tree walk with the theme unchanged must not disturb anything. */
    @Test
    void aWalkWithoutAThemeChangeIsANoop() throws Exception {
        theme(LIGHT_BG, Color.BLACK);
        AboutPanel panel = new AboutPanel();
        Component root = panel.component();
        layoutTree(root, 1000, 800);
        Color before = linkColorIn(root);

        SwingUtilities.updateComponentTreeUI(root);
        drainEventQueue();
        layoutTree(root, 1000, 800);

        assertEquals(before, linkColorIn(root), "an unrelated updateUI changed the palette");
    }

    // ---- harness -----------------------------------------------------------------------------------

    private static Color linkColorIn(Component root) {
        View anchor = findAnchorIn(root);
        assertNotNull(anchor, "no rendered link found - the harness, not the colour, is broken");
        return ((LabelView) anchor).getForeground();
    }

    private static View findAnchorIn(Component c) {
        if (c instanceof JEditorPane pane) {
            View root = pane.getUI().getRootView(pane);
            int w = pane.getWidth() > 0 ? pane.getWidth() : pane.getPreferredSize().width;
            root.setSize(w, Math.max(pane.getHeight(), pane.getPreferredSize().height));
            return findAnchor(root);
        }
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) {
                View hit = findAnchorIn(child);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }

    private static View findAnchor(View v) {
        Element e = v.getElement();
        AttributeSet a = e == null ? null : e.getAttributes();
        if (a != null && a.getAttribute(HTML.Tag.A) != null && v instanceof LabelView) {
            return v;
        }
        for (int i = 0; i < v.getViewCount(); i++) {
            View hit = findAnchor(v.getView(i));
            if (hit != null) {
                return hit;
            }
        }
        return null;
    }

    private static void layoutTree(Component c, int w, int h) {
        c.setSize(w, h);
        if (c instanceof Container cont) {
            cont.doLayout();
            for (Component child : cont.getComponents()) {
                layoutTree(child, child.getWidth(), child.getHeight());
            }
        }
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
