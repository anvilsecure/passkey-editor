package com.anvil.passkeyeditor.ui.editor;

import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;

/**
 * Installs undo / redo on a Swing text component - {@code Cmd/Ctrl-Z} to undo, {@code Cmd/Ctrl-Y} and
 * {@code Cmd/Ctrl-Shift-Z} to redo - so the JSON editor boxes behave like an ordinary text field (the operator's
 * ask: {@code Ctrl-Z} should work, not just exit-and-re-enter the tab).
 *
 * The editors REBUILD their document programmatically (decode -> pretty-print -> syntax-colour); those
 * rebuilds must NOT become undoable steps (undoing back into a stale render would be nonsense). The returned
 * {@link Handle} lets the caller {@link Handle#suppress(boolean) suppress} recording around a rebuild and
 * {@link Handle#reset() reset} the history so the freshly-rendered text is the undo floor - exactly the
 * "re-enter the tab resets it" baseline, now reachable via a keystroke.
 *
 * Burp-free + headless-safe (the menu-shortcut mask lookup falls back to Ctrl when no toolkit/display is
 * available, so the panel can be built in headless unit tests).
 */
final class UndoSupport {

    private UndoSupport() {
    }

    static Handle install(JTextComponent comp) {
        UndoManager manager = new UndoManager();
        Handle handle = new Handle(manager);
        comp.getDocument().addUndoableEditListener(e -> {
            if (!handle.suppressed) {
                manager.addEdit(e.getEdit());
            }
        });

        int mask;
        try {
            mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx(); // Cmd on macOS, Ctrl elsewhere
        } catch (Throwable t) {
            mask = InputEvent.CTRL_DOWN_MASK; // headless / no display
        }
        InputMap im = comp.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = comp.getActionMap();
        bind(im, am, "pk-undo", KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask), () -> {
            if (manager.canUndo()) {
                manager.undo();
            }
        });
        bind(im, am, "pk-redo", KeyStroke.getKeyStroke(KeyEvent.VK_Y, mask), () -> {
            if (manager.canRedo()) {
                manager.redo();
            }
        });
        // Cmd/Ctrl-Shift-Z is the other common redo binding (macOS convention).
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask | InputEvent.SHIFT_DOWN_MASK), "pk-redo");
        // Also honour plain Ctrl on platforms whose menu mask is not Ctrl (e.g. macOS Cmd), so both work.
        if (mask != InputEvent.CTRL_DOWN_MASK) {
            im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), "pk-undo");
            im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), "pk-redo");
        }
        return handle;
    }

    private static void bind(InputMap im, ActionMap am, String key, KeyStroke ks, Runnable action) {
        im.put(ks, key);
        am.put(key, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    /** Controls undo recording around programmatic rebuilds. */
    static final class Handle {
        private final UndoManager manager;
        private boolean suppressed;

        private Handle(UndoManager manager) {
            this.manager = manager;
        }

        /** Suppress (true) recording of document edits - set around a programmatic rebuild. */
        void suppress(boolean s) {
            this.suppressed = s;
        }

        /** Drop the undo history so the current document text becomes the undo floor. */
        void reset() {
            manager.discardAllEdits();
        }
    }
}
