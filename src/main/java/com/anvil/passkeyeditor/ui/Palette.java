package com.anvil.passkeyeditor.ui;

import java.awt.Color;

import javax.swing.JPanel;
import javax.swing.UIManager;

/**
 * Semantic colours for the whole extension UI, one value per Burp theme.
 *
 * Swing hands a component a theme-appropriate foreground and background, but any colour the code
 * picks itself is on its own. A green or red chosen to look right on a white panel lands at 1.6-2.5:1
 * against the dark theme's panels - present, but no longer reading as a signal - and Swing's built-in
 * link blue is worse still at 1.1:1. Every colour here is therefore a pair, each side picked to
 * clear WCAG AA for body text (4.5:1) against that theme's panel background. {@code PaletteContrastTest}
 * holds that line, so a future colour cannot be added by eye alone.
 *
 * Burp switches theme live, without a restart, so these are read per call rather than cached.
 * That is only half the job: a colour already handed to a component stays put, because
 * {@code setForeground} is not a {@code UIResource} for Swing to replace. {@link ThemedPanel} is what
 * re-applies them, and every panel holding a colour from here is expected to use it.
 */
public final class Palette {

    /** Panel background below this Rec. 601 luma means a dark theme. */
    private static final double DARK_BELOW = 128;

    // The accent (burnt orange) behind titles, underlines, and armed-profile rows. The light side is a
    // shade deeper than the original #B85C00, which read at 4.1:1 - fine for a bold heading, short for
    // the profile rows that also use it.
    private static final Color ACCENT_LIGHT = new Color(0xA8, 0x54, 0x00);
    private static final Color ACCENT_DARK = new Color(0xE5, 0x9C, 0x48);

    private static final Color OK_LIGHT = new Color(0x00, 0x7A, 0x00);
    private static final Color OK_DARK = new Color(0x73, 0xC9, 0x91);

    private static final Color ERROR_LIGHT = new Color(0xC0, 0x00, 0x00);
    private static final Color ERROR_DARK = new Color(0xFF, 0x8A, 0x80);

    // Amber rather than orange, deliberately: the accent is orange too, and at equal lightness the two
    // were within a few degrees of hue - an armed profile row and a SUSPECT verdict read as one colour.
    private static final Color WARN_LIGHT = new Color(0x8A, 0x62, 0x00);
    private static final Color WARN_DARK = new Color(0xE8, 0xBC, 0x5C);

    /** Secondary text: disabled rows, placeholder status lines, grip dots, thin borders. */
    private static final Color MUTED_LIGHT = new Color(0x6B, 0x6E, 0x70);
    private static final Color MUTED_DARK = new Color(0xA8, 0xAB, 0xAE);

    private static final Color LINK_LIGHT = new Color(0x1A, 0x5F, 0xB4);
    private static final Color LINK_DARK = new Color(0x6F, 0xB3, 0xFF);

    // JSON syntax colouring, resolved against the text pane's own background rather than the panel's.
    // Close to the familiar editor palette, with two nudged off it to make the contrast bar: the dark
    // string salmon measured 4.0:1 and the light number green 4.1:1 against the reference backgrounds.
    private static final Color JSON_KEY_LIGHT = new Color(0x0B, 0x52, 0x9E);
    private static final Color JSON_KEY_DARK = new Color(0x9C, 0xDC, 0xFE);
    private static final Color JSON_STRING_LIGHT = new Color(0xA3, 0x15, 0x15);
    private static final Color JSON_STRING_DARK = new Color(0xD9, 0xA1, 0x83);
    private static final Color JSON_NUMBER_LIGHT = new Color(0x0A, 0x7A, 0x4F);
    private static final Color JSON_NUMBER_DARK = new Color(0xB5, 0xCE, 0xA8);

    /**
     * The "value changed here" highlight. Alone in this class it is one colour rather than a pair: it
     * paints its own background, so it does not depend on the theme behind it.
     */
    private static final Color CHANGED_BACKGROUND = new Color(0xFF, 0xD5, 0x4F);
    private static final Color CHANGED_FOREGROUND = Color.BLACK;

    private Palette() {
    }

    /**
     * Whether the look and feel is a dark theme, judged by a panel's background. Read straight from the
     * look and feel rather than by constructing a panel: this sits on a display path
     * ({@code uiComponent()}), which Burp may call often, and building a Swing component installs a UI
     * delegate every time. Only a look and feel that declares no panel background pays for one.
     */
    public static boolean isDark() {
        Color background = UIManager.getColor("Panel.background");
        return isDark(background != null ? background : new JPanel().getBackground());
    }

    /** Whether {@code background} is a dark surface; pass the component's own background. */
    public static boolean isDark(Color background) {
        if (background == null) {
            return false;
        }
        double luma = 0.299 * background.getRed()
                + 0.587 * background.getGreen()
                + 0.114 * background.getBlue();   // Rec. 601
        return luma < DARK_BELOW;
    }

    /** The Passkey Editor accent: titles, heading underlines, armed-profile rows. */
    public static Color accent() {
        return isDark() ? ACCENT_DARK : ACCENT_LIGHT;
    }

    /** Success: a field decoded, a profile saved, a re-sign landed. */
    public static Color ok() {
        return isDark() ? OK_DARK : OK_LIGHT;
    }

    /** Failure: a decode threw, a field was not found, a save was rejected. */
    public static Color error() {
        return isDark() ? ERROR_DARK : ERROR_LIGHT;
    }

    /** Caution: decoded but suspect, nothing to change, an armed setting worth noticing. */
    public static Color warn() {
        return isDark() ? WARN_DARK : WARN_LIGHT;
    }

    /** Secondary text and hairlines. */
    /**
     * The look and feel's own component-outline colour, so a box we draw sits at the same weight as the
     * group borders Burp draws beside it. {@link #muted()} is a TEXT colour and reads far too bright as an
     * outline - it made the sample-body boxes glow white against everything around them.
     */
    public static Color border() {
        for (String key : new String[]{"Component.borderColor", "Separator.foreground",
                                       "TitledBorder.borderColor", "controlShadow"}) {
            Color c = UIManager.getColor(key);
            if (c != null) {
                return c;
            }
        }
        return muted();
    }

    public static Color muted() {
        return isDark() ? MUTED_DARK : MUTED_LIGHT;
    }

    /** Hyperlink text. Swing's own link blue ignores the theme, so it is never used. */
    public static Color link() {
        return isDark() ? LINK_DARK : LINK_LIGHT;
    }

    public static Color jsonKey(Color background) {
        return isDark(background) ? JSON_KEY_DARK : JSON_KEY_LIGHT;
    }

    public static Color jsonString(Color background) {
        return isDark(background) ? JSON_STRING_DARK : JSON_STRING_LIGHT;
    }

    public static Color jsonNumber(Color background) {
        return isDark(background) ? JSON_NUMBER_DARK : JSON_NUMBER_LIGHT;
    }

    public static Color changedBackground() {
        return CHANGED_BACKGROUND;
    }

    public static Color changedForeground() {
        return CHANGED_FOREGROUND;
    }
}
