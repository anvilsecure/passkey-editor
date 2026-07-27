package com.anvil.passkeyeditor.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.LayoutManager;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * A panel that re-applies its {@link Palette} colours when Burp's theme changes.
 *
 * Burp switches Light/Dark live, and its own widgets follow because their colours come from the look
 * and feel. Ours do not: a colour set with {@code setForeground} is not a {@code UIResource}, so Swing
 * deliberately leaves it alone on a theme change, and anything baked into an HTML string is further out
 * of reach still. Without this class the extension keeps the previous theme's palette until it is
 * reloaded - which looks like the extension being broken rather than merely stale.
 *
 * The hook is {@link #updateUI()}, which Swing calls on every component when the look and feel
 * changes. By then {@link Palette} already reads the new theme, so re-running the panel's own build
 * step is enough. The work is deferred to the end of the event queue because the change arrives in the
 * middle of a walk over this component's own tree, and rebuilding children underneath that walk is not
 * safe. It is skipped unless the appearance actually changed, so an ordinary {@code updateUI} - Swing
 * fires one at construction, and hosts fire more - costs an equality check.
 *
 * Appearance is theme AND font. Raising Burp's font size fires {@code updateUI} without
 * flipping light/dark, so keying the rebuild on the dark verdict alone left the documentation panels
 * rendering at their construction-time size: the HTML carries a baked {@code font-size} and a height
 * measured for it, so the text grew while its container did not, and the panels clipped. Both halves
 * are compared here.
 */
public class ThemedPanel extends JPanel {

    /** Components whose foreground is a palette colour, against the colour's <i>meaning</i>. */
    private final Map<JComponent, Supplier<Color>> tints = new LinkedHashMap<>();

    private Runnable applyTheme;

    /** The appearance behind what is currently on screen; {@code null} until something is set. */
    private Appearance applied;

    /**
     * The look-and-feel state a build depends on. The font matters as much as the palette: sizes are baked
     * into measured layouts and HTML, so a font change needs the same rebuild a theme change does.
     */
    private record Appearance(boolean dark, Font ui, Font editor) {
        static Appearance current() {
            return new Appearance(Palette.isDark(), UIManager.getFont("Label.font"), Fonts.mono());
        }
    }

    public ThemedPanel(LayoutManager layout) {
        super(layout);
    }

    /**
     * Paint {@code component}'s text in a palette colour, and keep painting it correctly across theme
     * changes. The colour is passed as its meaning ({@code Palette::error}), not as a value, so
     * it can be resolved again later.
     *
     * Re-registering replaces the previous meaning, which is what a status line wants: whatever it
     * last said - and in whatever tone - is what follows the theme.
     */
    public void tint(JComponent component, Supplier<Color> tone) {
        tints.put(component, tone);
        component.setForeground(tone.get());
        markApplied();
    }

    /**
     * Install an extra build step, run now and again on each theme change - for anything {@link #tint}
     * cannot express, such as rebuilding content with colours baked into it. It must be safe to run more
     * than once. Panels holding state the operator typed should re-colour rather than rebuild.
     */
    public void onTheme(Runnable applyTheme) {
        this.applyTheme = applyTheme;
        markApplied();
        applyTheme.run();
    }

    @Override
    public void updateUI() {
        super.updateUI();     // also runs from JPanel's constructor, before anything is registered
        themeChanged();
    }

    /**
     * Re-apply if the theme flipped since the last apply; otherwise do nothing. Cheap enough to call
     * from a display path as a second chance, for a host that changes the theme without walking this
     * component's tree.
     */
    public void themeChanged() {
        Appearance now = Appearance.current();
        if (applied == null || now.equals(applied)) {
            return;
        }
        applied = now;
        SwingUtilities.invokeLater(this::reapply);
    }

    private void markApplied() {
        if (applied == null) {
            applied = Appearance.current();
        }
    }

    private void reapply() {
        tints.forEach((component, tone) -> component.setForeground(tone.get()));
        if (applyTheme != null) {
            applyTheme.run();
        }
    }
}
