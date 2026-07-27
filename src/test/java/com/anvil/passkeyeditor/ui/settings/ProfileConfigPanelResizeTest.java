package com.anvil.passkeyeditor.ui.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.profile.ProfileValidator;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

/**
 * Pins the sample-body resize contract headlessly: dragging the bottom drag-bar down by N pixels grows the
 * body box's preferred height by N. This is the regression this guards - a large UI font left the tiny
 * corner nub out of easy reach, so the grip was replaced by a full-width, font-scaled bar. The layout
 * propagation itself is only observable in a live Burp, but the drag → preferred-size mechanic is provable
 * off-EDT here.
 */
class ProfileConfigPanelResizeTest {

    @Test
    void draggingTheBodyDragBarGrowsTheBoxOneToOne() {
        ProfileConfigPanel panel = new ProfileConfigPanel(new ProfileValidator(), p -> { });

        // regBody → viewport → the body JScrollPane (nearest JScrollPane ancestor).
        JScrollPane bodyScroll =
                (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, panel.regBody);
        Container box = bodyScroll.getParent(); // BorderLayout: scroll at CENTER, drag-bar strip at SOUTH
        Component gripStrip = ((BorderLayout) box.getLayout()).getLayoutComponent(BorderLayout.SOUTH);
        Component grip = ((Container) gripStrip).getComponent(0);

        int before = bodyScroll.getPreferredSize().height;

        // The grip's own drag handler is a MouseAdapter (registered as both listeners); pick it by type so
        // the ToolTipManager listener that setToolTipText() also registers is skipped. Drive a press at
        // screen-y=100 then a drag to y=180.
        MouseAdapter handler = adapterOf(grip.getMouseListeners());
        assertEquals(handler, adapterOf(grip.getMouseMotionListeners()),
                "the same adapter should handle both press and drag");
        handler.mousePressed(mouse(grip, MouseEvent.MOUSE_PRESSED, 100));
        handler.mouseDragged(mouse(grip, MouseEvent.MOUSE_DRAGGED, 180));

        int after = bodyScroll.getPreferredSize().height;
        assertTrue(after > before, "body box should be taller after dragging the bar down");
        assertEquals(before + 80, after, "an 80px drag should grow the box 80px (1:1)");
    }

    /**
     * The grip's own drag adapter among {@code listeners}. Skips {@link javax.swing.ToolTipManager} - which
     * setToolTipText() registers and which itself extends MouseAdapter, so a bare instanceof would catch it.
     */
    private static MouseAdapter adapterOf(Object[] listeners) {
        for (Object l : listeners) {
            if (l instanceof MouseAdapter ma && !(l instanceof javax.swing.ToolTipManager)) {
                return ma;
            }
        }
        throw new AssertionError("no ResizeGrip drag adapter registered on the grip");
    }

    /** A synthetic mouse event whose on-screen Y is {@code yAbs} - what ResizeGrip reads via getYOnScreen(). */
    private static MouseEvent mouse(Component src, int id, int yAbs) {
        return new MouseEvent(src, id, 0L, 0, 5, 5, /*xAbs*/ 0, /*yAbs*/ yAbs, 0, false,
                id == MouseEvent.MOUSE_PRESSED ? MouseEvent.BUTTON1 : MouseEvent.NOBUTTON);
    }
}
