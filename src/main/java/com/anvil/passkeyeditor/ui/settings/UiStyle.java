package com.anvil.passkeyeditor.ui.settings;

import com.anvil.passkeyeditor.ui.Fonts;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.ui.ThemedPanel;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.net.URI;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLDocument;

/**
 * Shared visual style for the settings tabs: a consistent section heading (accent-coloured bold label
 * with a matching underline and a little top padding) and the documentation panes. Used by the left
 * {@code Profiles} pane and the right config title so both read as the same kind of header.
 *
 * Colours come from {@link Palette}; this class only decides how they are applied.
 */
final class UiStyle {

    private UiStyle() {
    }

    /** A standalone section heading with the given text; its colour follows the theme. */
    static JComponent heading(String text) {
        JLabel label = new JLabel(text);
        // Scale with Burp's font setting rather than pinning 14pt: the body text around a heading
        // grows, and a heading that stays put ends up smaller than the prose beneath it.
        label.setFont(Fonts.ui().deriveFont(Font.BOLD, Fonts.ui().getSize() + 2f));
        return underline(label);      // tints the label and the underline together
    }

    /** A section heading whose underline stops at {@code width} (so it matches a bounded text column). */
    static JComponent heading(String text, int width) {
        JComponent h = heading(text);
        h.setMaximumSize(new Dimension(width, h.getPreferredSize().height));
        return h;
    }

    /** {@code #rrggbb} for use inside an inline style attribute. */
    static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    /**
     * Body CSS for a documentation pane, taken from the look and feel so the text follows Burp's font
     * scale and theme. Swing's HTML renderer defaults to a serif face at a fixed size and does not
     * follow a dark theme on its own, so both are set explicitly.
     */
    static String bodyCss() {
        JLabel probe = new JLabel();
        Font f = probe.getFont();
        return "font-family:'" + f.getFamily() + "',sans-serif; font-size:" + f.getSize() + "px;"
                + " color:" + hex(probe.getForeground()) + "; margin:0";
    }

    /**
     * A theme-appropriate secondary text colour. This used to fade the body colour toward the
     * background, which produced whatever contrast the theme's own foreground happened to give -
     * around 3:1 on a dark theme whose text is grey rather than white. {@link Palette#muted} is a
     * measured pair instead.
     */
    static String mutedHex() {
        return hex(Palette.muted());
    }

    /** A link colour legible under the current theme; see {@link Palette#link}. */
    static String linkHex() {
        return hex(Palette.link());
    }

    /**
     * An anchor carrying the theme's link colour inline. Prefer this over a bare {@code <a>}: the
     * pane-wide rule in {@link #doc} loses to an ancestor's inline {@code color} (Swing resolves
     * an inherited inline attribute ahead of a tag rule), so a link inside, say, a muted span would come
     * out muted. An inline colour on the anchor itself wins everywhere; the underline still comes from
     * the renderer's own {@code a} rule.
     */
    static String link(String url, String text) {
        return "<a href='" + url + "' style='color:" + linkHex() + "'>" + text + "</a>";
    }

    /**
     * A documentation pane laid out to an explicit pixel width. Swing's HTML renderer ignores
     * {@code max-width}, so the width is forced and the wrapped height measured from it; without this
     * the text stretches across the whole Burp window. Non-opaque so it blends into the panel, and
     * links open in the desktop browser.
     */
    static JEditorPane doc(String bodyHtml, int width) {
        JEditorPane pane = new JEditorPane();
        pane.setContentType("text/html");     // installs the HTML kit and a stylesheet private to this pane
        // The renderer's built-in link blue is a fixed dark blue, unreadable on the dark theme. This rule
        // is the pane-wide default so even a bare <a> reads; {@link #link} is what nested links need.
        ((HTMLDocument) pane.getDocument()).getStyleSheet()
                .addRule("a { color: " + linkHex() + "; text-decoration: underline }");
        pane.setText("<html><body style='" + bodyCss() + "'>" + bodyHtml + "</body></html>");
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
                browse(e.getURL().toString());
            }
        });
        pane.setSize(width, Short.MAX_VALUE);             // force a reflow at this width...
        Dimension dim = new Dimension(width, pane.getPreferredSize().height); // ...then measure it.
        pane.setPreferredSize(dim);
        pane.setMaximumSize(dim);
        pane.setMinimumSize(dim);
        pane.setAlignmentX(Component.LEFT_ALIGNMENT);
        pane.setCaretPosition(0);
        return pane;
    }

    /** Open a URL in the desktop browser; silently does nothing where that is unavailable. */
    static void browse(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
            }
        } catch (Exception ignored) {
            // No browser available here; nothing opens. Burp normally runs with a desktop.
        }
    }

    /**
     * Wrap an already-styled label as a section heading: an accent underline beneath it plus top
     * padding. The width is unconstrained so the underline spans the full pane; the height is pinned
     * to preferred so it behaves inside a vertical {@code BoxLayout}.
     *
     * The wrapper is a {@link ThemedPanel} so a heading re-colours itself - text and underline - when
     * Burp's theme changes. Doing it here covers every heading in the extension, including those in
     * panels that are never rebuilt.
     */
    static JComponent underline(JLabel label) {
        ThemedPanel p = new ThemedPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(label, BorderLayout.CENTER);
        p.tint(label, Palette::accent);
        p.onTheme(() -> p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(10, 2, 4, 2),
                BorderFactory.createMatteBorder(0, 0, 2, 0, Palette.accent()))));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }
}
