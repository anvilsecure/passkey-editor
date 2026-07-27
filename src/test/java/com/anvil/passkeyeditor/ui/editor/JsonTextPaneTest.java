package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.event.ActionEvent;

import javax.swing.Action;

import org.junit.jupiter.api.Test;

/**
 * The shared JSON editor pane's two operator-facing behaviours: the line-wrap toggle and undo/redo
 *, both headless-verifiable. The wire path is untouched; this is pure Swing UX.
 */
class JsonTextPaneTest {

    static {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void wrapToggleFlipsViewportWidthTracking() {
        JsonTextPane p = new JsonTextPane();
        assertTrue(p.isWrap(), "wrapping is on by default (unchanged behaviour)");
        assertTrue(p.getScrollableTracksViewportWidth(), "wrapping tracks the viewport width");
        p.setWrap(false);
        assertFalse(p.isWrap());
        assertFalse(p.getScrollableTracksViewportWidth(), "no-wrap lays out full width => horizontal scrollbar");
        p.setWrap(true);
        assertTrue(p.getScrollableTracksViewportWidth());
    }

    @Test
    void undoRevertsUserEditsButNotTheProgrammaticRenderFloor() throws Exception {
        JsonTextPane p = new JsonTextPane();
        assertNotNull(p.getActionMap().get("pk-undo"), "undo action installed");
        assertNotNull(p.getActionMap().get("pk-redo"), "redo action installed");

        // A programmatic rebuild (decode/render) must NOT be undoable; endProgrammatic() makes it the floor.
        p.beginProgrammatic();
        p.getDocument().insertString(0, "baseline", null);
        p.endProgrammatic();

        // A subsequent operator edit IS recorded + undoable.
        p.getDocument().insertString(p.getDocument().getLength(), "EDIT", null);
        assertEquals("baselineEDIT", p.getText());

        Action undo = p.getActionMap().get("pk-undo");
        undo.actionPerformed(new ActionEvent(p, ActionEvent.ACTION_PERFORMED, "undo"));
        assertEquals("baseline", p.getText(), "undo reverts the operator edit");

        // Cannot undo past the render floor (the baseline render was suppressed).
        undo.actionPerformed(new ActionEvent(p, ActionEvent.ACTION_PERFORMED, "undo"));
        assertEquals("baseline", p.getText(), "undo stops at the programmatic render floor");
    }
}
