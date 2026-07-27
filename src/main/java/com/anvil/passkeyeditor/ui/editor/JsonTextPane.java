package com.anvil.passkeyeditor.ui.editor;

import com.anvil.passkeyeditor.ui.Fonts;
import java.awt.Font;

import javax.swing.JTextPane;
import javax.swing.text.AbstractDocument;
import javax.swing.text.BoxView;
import javax.swing.text.ComponentView;
import javax.swing.text.Element;
import javax.swing.text.IconView;
import javax.swing.text.LabelView;
import javax.swing.text.ParagraphView;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.View;
import javax.swing.text.ViewFactory;

/**
 * The shared JSON editor pane for the Passkey Editor request + response tabs: a monospaced {@link JTextPane}
 * with (a) a line-wrap toggle, (b) built-in undo/redo ({@link UndoSupport}), and (c)
 * character-level wrapping so a long UNBROKEN token (a hex / base64 value with no spaces) still wraps
 * instead of overflowing and being clipped.
 *
 * Line wrap: Burp's own "line wrapping" toolbar button only drives Burp's built-in editors, so it is
 * greyed out on a custom editor tab like ours. This pane carries its own toggle - {@link #setWrap(boolean)}
 * flips {@link #getScrollableTracksViewportWidth()}, which is what makes a {@code JTextPane} in a scroll pane
 * either wrap long values to the viewport width (default) or lay them out full-width with a horizontal
 * scrollbar. Wrapping ON is the default.
 *
 * Why the custom {@link StyledEditorKit}: a stock {@code JTextPane} only breaks lines at word
 * boundaries, so a single long token with no whitespace (a signature / credentialId hex, a base64url blob)
 * runs off the right edge - and because wrap mode reports {@code getScrollableTracksViewportWidth()==true}
 * there is no horizontal scrollbar, so the overflow is simply CLIPPED and the operator loses content when the
 * pane is narrowed. The {@link WrapEditorKit} installs a {@link LabelView} whose X-axis minimum span is 0, so
 * the layout may break a run at ANY character - long tokens wrap to the next line. In no-wrap mode the pane
 * is sized to its full preferred width, so nothing is force-broken and the horizontal scrollbar shows.
 */
final class JsonTextPane extends JTextPane {

    private boolean wrap = true;
    private final UndoSupport.Handle undo;

    JsonTextPane() {
        // Install the character-wrapping kit FIRST (setEditorKit resets the document), then attach undo to
        // that document so Ctrl-Z records against the pane the operator actually edits.
        setEditorKit(new WrapEditorKit());
        setFont(Fonts.mono());
        this.undo = UndoSupport.install(this);
    }

    /** When wrapping, the pane tracks the viewport width (long lines wrap); when off, it lays out full-width
     *  so the scroll pane shows a horizontal scrollbar instead. */
    @Override
    public boolean getScrollableTracksViewportWidth() {
        return wrap;
    }

    void setWrap(boolean w) {
        if (w != wrap) {
            wrap = w;
            revalidate();
            repaint();
        }
    }

    boolean isWrap() {
        return wrap;
    }

    /** Call before a programmatic rebuild (decode/render) so it is not recorded as an undoable step. */
    void beginProgrammatic() {
        undo.suppress(true);
    }

    /** Call after a programmatic rebuild: the rendered text becomes the undo floor, recording resumes. */
    void endProgrammatic() {
        undo.reset();
        undo.suppress(false);
    }

    /**
     * Bracket a re-colouring that leaves the text alone (a theme change). Attribute changes are undoable
     * edits, so recording is suppressed - but unlike {@link #endProgrammatic()} the undo history is
     * kept: re-colouring is not a new floor, and the operator must not lose the ability to undo
     * what they typed just because Burp's theme changed underneath them.
     */
    void beginRestyle() {
        undo.suppress(true);
    }

    void endRestyle() {
        undo.suppress(false);
    }

    // ---- character-level wrapping (break a long unbroken token at any char, not just at word boundaries) ----

    /** A {@link StyledEditorKit} whose view factory breaks content runs at any character (see class doc). */
    private static final class WrapEditorKit extends StyledEditorKit {
        private final ViewFactory factory = new WrapColumnFactory();

        @Override
        public ViewFactory getViewFactory() {
            return factory;
        }
    }

    /** Mirrors the default styled view factory but returns a {@link WrapLabelView} for content runs. */
    private static final class WrapColumnFactory implements ViewFactory {
        @Override
        public View create(Element elem) {
            String kind = elem.getName();
            if (kind != null) {
                switch (kind) {
                    case AbstractDocument.ContentElementName:
                        return new WrapLabelView(elem);
                    case AbstractDocument.ParagraphElementName:
                        return new ParagraphView(elem);
                    case AbstractDocument.SectionElementName:
                        return new BoxView(elem, View.Y_AXIS);
                    case StyleConstants.ComponentElementName:
                        return new ComponentView(elem);
                    case StyleConstants.IconElementName:
                        return new IconView(elem);
                    default:
                        break;
                }
            }
            return new LabelView(elem);
        }
    }

    /** A {@link LabelView} reporting a zero X-axis minimum span, so the flow layout may break a long unbroken
     *  token (no whitespace) at any character instead of letting it overflow and clip. */
    private static final class WrapLabelView extends LabelView {
        WrapLabelView(Element elem) {
            super(elem);
        }

        @Override
        public float getMinimumSpan(int axis) {
            return switch (axis) {
                case View.X_AXIS -> 0f;
                case View.Y_AXIS -> super.getMinimumSpan(axis);
                default -> throw new IllegalArgumentException("Invalid axis: " + axis);
            };
        }
    }
}
