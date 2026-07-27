package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;

import javax.swing.JEditorPane;
import javax.swing.UIManager;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.LabelView;
import javax.swing.text.StyleConstants;
import javax.swing.text.View;
import javax.swing.text.html.HTML;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Guards the "invisible link" regression: Swing's HTML renderer paints {@code <a>} a fixed dark blue,
 * which against Burp's dark theme measures about 1.1:1 and all but disappears. {@link UiStyle} therefore
 * supplies its own per-theme link colour.
 *
 * Two traps, both checked against the colour the renderer actually resolves rather than the HTML
 * source. First, one hardcoded blue cannot serve both themes. Second, the pane-wide {@code a} rule loses
 * to an ancestor's inline {@code color} - Swing resolves an inherited inline attribute ahead of a
 * tag rule - so the Guide's link inside its muted closing note needs the inline colour that
 * {@link UiStyle#link} emits. Contrast is asserted at WCAG AA for body text (4.5:1).
 */
class DocLinkColorTest {

    private static final Color DARK_BG = new Color(0x3C, 0x3F, 0x41);   // Burp's dark theme panels
    private static final Color LIGHT_BG = new Color(0xF2, 0xF2, 0xF2);
    private static final double AA = 4.5;

    @AfterEach
    void resetTheme() {
        UIManager.put("Panel.background", null);
        UIManager.put("Label.foreground", null);
    }

    /** Point the LaF defaults that {@link UiStyle} probes at a given theme. */
    private static void theme(Color background, Color foreground) {
        UIManager.put("Panel.background", background);
        UIManager.put("Label.foreground", foreground);
    }

    /** The real About tab: its "Anvil Secure" link is the one that vanished on the dark theme. */
    @Test
    void aboutTabLinkReadsOnBothThemes() {
        theme(DARK_BG, Color.WHITE);
        assertAA(linkColorIn(new AboutPanel().component()), DARK_BG, "About on dark");

        theme(LIGHT_BG, Color.BLACK);
        assertAA(linkColorIn(new AboutPanel().component()), LIGHT_BG, "About on light");
    }

    /** The real Guide tab, whose link sits inside the muted closing note. */
    @Test
    void guideTabLinkReadsOnBothThemes() {
        theme(DARK_BG, Color.WHITE);
        assertAA(linkColorIn(new GuidePanel().component()), DARK_BG, "Guide on dark");

        theme(LIGHT_BG, Color.BLACK);
        assertAA(linkColorIn(new GuidePanel().component()), LIGHT_BG, "Guide on light");
    }

    @Test
    void theTwoThemesGetDifferentLinkColours() {
        theme(DARK_BG, Color.WHITE);
        String onDark = UiStyle.linkHex();
        theme(LIGHT_BG, Color.BLACK);
        assertNotEquals(onDark, UiStyle.linkHex(), "one hardcoded link colour cannot read on both themes");
    }

    /** The mechanism: a link wrapped in a muted span must not inherit that span's grey. */
    @Test
    void linkInsideAMutedSpanKeepsTheLinkColour() {
        theme(DARK_BG, Color.WHITE);
        JEditorPane pane = UiStyle.doc("<span style='color:" + UiStyle.mutedHex() + "'>Reference: "
                + UiStyle.link("https://x", "GitHub repository") + ".</span>", 720);

        assertEquals(UiStyle.linkHex(), hex(linkColorIn(pane)), "link inherited the muted span colour");
    }

    /** Underlining marks it as a link when the colour is missed; it must survive the colour override. */
    @Test
    void linksStayUnderlined() {
        theme(DARK_BG, Color.WHITE);
        View anchor = findAnchor(rootView(UiStyle.doc(UiStyle.link("https://x", "GitHub repository"), 720)));
        assertTrue(StyleConstants.isUnderline(anchor.getAttributes()), "the link lost its underline");
    }

    // ---- rendering harness -------------------------------------------------------------------------

    /** The colour the renderer resolves for the first link anywhere under {@code root}. */
    private static Color linkColorIn(Component root) {
        layoutTree(root, 900, 1400);
        View anchor = findAnchorIn(root);
        assertNotNull(anchor, "no rendered link found - the harness, not the colour, is broken");
        return ((LabelView) anchor).getForeground();
    }

    private static View findAnchorIn(Component c) {
        if (c instanceof JEditorPane pane) {
            return findAnchor(rootView(pane));
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

    /** A pane's view tree, sized so its views resolve their attributes. */
    private static View rootView(JEditorPane pane) {
        View root = pane.getUI().getRootView(pane);
        int w = pane.getWidth() > 0 ? pane.getWidth() : pane.getPreferredSize().width;
        root.setSize(w, Math.max(pane.getHeight(), pane.getPreferredSize().height));
        return root;
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

    private static void assertAA(Color link, Color background, String where) {
        assertTrue(contrast(link, background) >= AA, where + ": link " + hex(link) + " is only "
                + String.format("%.2f", contrast(link, background)) + ":1 against " + hex(background));
    }

    // ---- WCAG contrast ----------------------------------------------------------------------------

    private static double contrast(Color a, Color b) {
        double la = luminance(a);
        double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    /** WCAG relative luminance. */
    private static double luminance(Color c) {
        return 0.2126 * channel(c.getRed()) + 0.7152 * channel(c.getGreen()) + 0.0722 * channel(c.getBlue());
    }

    private static double channel(int v) {
        double s = v / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }

    private static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }
}
