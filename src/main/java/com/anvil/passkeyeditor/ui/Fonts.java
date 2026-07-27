package com.anvil.passkeyeditor.ui;

import java.awt.Font;
import java.util.function.Supplier;

import javax.swing.UIManager;

/**
 * The fonts the extension draws with, resolved from Burp rather than hardcoded.
 *
 * Burp exposes two size settings, and both must be honoured or the extension becomes the one panel a
 * reader cannot enlarge:
 *
 *   - Message editor font ({@code currentEditorFont()}) drives {@link #mono()}. The decoded
 *       ceremony sits in the same tab strip as Pretty / Raw / Hex, so someone who enlarges the editor to
 *       read a request expects the decoded view of that same request to follow. The sample-body boxes in
 *       the profile editor hold request bodies too, so they take it as well.
 *   - Display font (the look and feel's {@code Label.font}) drives {@link #ui()}, for ordinary
 *       chrome such as the status line.
 *
 * The editor font arrives as a {@link Supplier} installed at extension load, because reaching it needs
 * a {@code MontoyaApi} that the settings widgets have no other reason to hold, and because it must be
 * re-read on every call: Burp changes it live. With no supplier installed - a headless test - {@link #mono()}
 * degrades to a monospaced face at a fixed fallback size.
 */
public final class Fonts {

    /** Burp's own default message-editor size; used only when the live value cannot be read. */
    private static final int FALLBACK_MONO_SIZE = 12;

    private static volatile Supplier<Font> editorFont = () -> null;

    private Fonts() {
    }

    /** Install Burp's message-editor font source. Called once at extension load. */
    public static void useEditorFont(Supplier<Font> supplier) {
        editorFont = supplier != null ? supplier : () -> null;
    }

    /** Drop the Burp-backed source (extension unload), so nothing holds a stale API reference. */
    public static void clear() {
        editorFont = () -> null;
    }

    /**
     * The face for decoded payloads: Burp's message-editor font when it can be read, else a monospaced
     * face at the look and feel's size. Never cached - Burp changes the setting live, and callers re-apply
     * it when {@link ThemedPanel} reports the appearance changed.
     */
    public static Font mono() {
        try {
            Font f = editorFont.get();
            if (f != null) {
                return f;
            }
        } catch (RuntimeException ignored) {
            // Burp not available (headless test, or called after unload): fall through to the L&F size.
        }
        // Deliberately NOT the display size: Burp's UI font and its message-editor font are separate
        // settings, and borrowing the UI size here rendered the decoded JSON far larger than the Pretty
        // tab beside it whenever the editor font could not be read.
        return new Font(Font.MONOSPACED, Font.PLAIN, FALLBACK_MONO_SIZE);
    }

    /** The look-and-feel's own label font, so ordinary chrome follows Burp's display-size setting. */
    public static Font ui() {
        Font f = UIManager.getFont("Label.font");
        return f != null ? f : new Font(Font.SANS_SERIF, Font.PLAIN, 12);
    }
}
