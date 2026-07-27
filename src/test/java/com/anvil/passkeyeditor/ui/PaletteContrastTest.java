package com.anvil.passkeyeditor.ui;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.swing.UIManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Holds the line on {@link Palette}: every semantic colour must stay legible on both Burp themes.
 *
 * The colours this replaced were picked against a light panel and were never checked against the dark
 * one, where they landed between 1.4:1 and 3.2:1 - a red status line at 1.6:1 is still red, but it stops
 * reading as an alarm. Each colour is asserted at WCAG AA for body text (4.5:1).
 *
 * The two reference backgrounds stand in for Burp's themes. They are the shallow end on purpose: a
 * darker panel than {@link #DARK_BG} or a lighter one than {@link #LIGHT_BG} only raises contrast,
 * so passing here means passing on the real thing.
 */
class PaletteContrastTest {

    private static final Color DARK_BG = new Color(0x3C, 0x3F, 0x41);
    private static final Color LIGHT_BG = new Color(0xF2, 0xF2, 0xF2);
    private static final double AA = 4.5;

    /** The panel-background colours, by the name used in failure messages. */
    private static Map<String, Supplier<Color>> semanticColors() {
        Map<String, Supplier<Color>> m = new LinkedHashMap<>();
        m.put("accent", Palette::accent);
        m.put("ok", Palette::ok);
        m.put("error", Palette::error);
        m.put("warn", Palette::warn);
        m.put("muted", Palette::muted);
        m.put("link", Palette::link);
        return m;
    }

    @AfterEach
    void resetTheme() {
        UIManager.put("Panel.background", null);
    }

    private static void theme(Color background) {
        UIManager.put("Panel.background", background);
    }

    @Test
    void everySemanticColorClearsAaOnTheDarkTheme() {
        theme(DARK_BG);
        semanticColors().forEach((name, color) -> assertAA(name, color.get(), DARK_BG));
    }

    @Test
    void everySemanticColorClearsAaOnTheLightTheme() {
        theme(LIGHT_BG);
        semanticColors().forEach((name, color) -> assertAA(name, color.get(), LIGHT_BG));
    }

    /** JSON syntax colours resolve against the text pane's background, which is passed in explicitly. */
    @Test
    void jsonSyntaxColorsClearAaOnBothThemes() {
        for (Color bg : new Color[] {DARK_BG, LIGHT_BG}) {
            assertAA("jsonKey", Palette.jsonKey(bg), bg);
            assertAA("jsonString", Palette.jsonString(bg), bg);
            assertAA("jsonNumber", Palette.jsonNumber(bg), bg);
        }
    }

    /** The changed-value highlight paints its own background, so it is checked against that. */
    @Test
    void changedHighlightIsLegibleAgainstItsOwnBackground() {
        assertAA("changed", Palette.changedForeground(), Palette.changedBackground());
    }

    /** A colour that ignored the theme would be the regression; every pair must actually differ. */
    @Test
    void everySemanticColorActuallyChangesWithTheTheme() {
        theme(DARK_BG);
        Map<String, Color> onDark = new LinkedHashMap<>();
        semanticColors().forEach((name, color) -> onDark.put(name, color.get()));

        theme(LIGHT_BG);
        semanticColors().forEach((name, color) ->
                assertNotEquals(onDark.get(name), color.get(), name + " is the same on both themes"));
    }

    @Test
    void darkThemeDetectionFollowsTheBackground() {
        assertTrue(Palette.isDark(DARK_BG), "a dark panel must read as dark");
        assertTrue(!Palette.isDark(LIGHT_BG), "a light panel must not read as dark");
        assertTrue(!Palette.isDark(null), "an unknown background must not read as dark");
    }

    private static void assertAA(String name, Color fg, Color bg) {
        double ratio = contrast(fg, bg);
        assertTrue(ratio >= AA, String.format("%s %s on %s is only %.2f:1 (need %.1f:1)",
                name, hex(fg), hex(bg), ratio, AA));
    }

    // ---- WCAG contrast ----------------------------------------------------------------------------

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

    private static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }
}
