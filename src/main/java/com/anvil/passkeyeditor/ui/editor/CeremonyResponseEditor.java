package com.anvil.passkeyeditor.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.detect.Detector.OptionsKind;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.ui.ThemedPanel;
import com.anvil.passkeyeditor.util.EditDiffCache;

import com.google.gson.JsonElement;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.function.Supplier;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * The "Passkey Editor" tab for the options phase - a WebAuthn {@code generate-*-options}
 * response (server->client). One instance per host editor (Proxy, Repeater, ...).
 *
 * Aligned with the request tab: it shows the options response as editable, syntax-highlighted JSON
 * with changed values highlighted amber vs. the original, and drives attacks from an
 * Attacks &#9662; dropdown (currently one preset - {@code Downgrade UV -> discouraged}; more slot in
 * later). Because the options message is unsigned, arbitrary edits are possible: an attack preset just writes
 * its change into the JSON, and any hand-edit is forwarded as-is. This is the earlier, unsigned policy
 * message; the signed verify-request structures live in {@link CeremonyRequestEditor}.
 *
 * Montoya must-fixes baked in (LOCKED - identical discipline to {@link CeremonyRequestEditor}):
 *   - {@link #uiComponent()} returns a cached final field built in the constructor.
 *   - {@link #setRequestResponse} resets per-message state up front and runs decode in try/catch ->
 *       render always, decode best-effort; logs to the error stream and never throws.
 *   - {@link #getResponse()} is idempotent - an unedited response is byte-identical to the original
 *       (the pane text is compared to the rendered baseline); only a genuine edit is re-serialized.
 *   - {@link #isEnabledFor} is cheap, side-effect-free, and swallows detector errors (defaults false).
 */
public final class CeremonyResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private static final String CAPTION = "Passkey Editor";

    // Banner tone - the message carries no emoji; the colour alone signals severity, so it comes from
    // Palette (green/amber/red per theme) rather than a mid-tone that washes out on the dark one.

    private final MontoyaApi api;
    private final Detector detector;
    private final ProfileRegistry registry;
    /** READ_ONLY editor context (Proxy history / Scanner): the persistent-amber cache lookup is gated to it. */
    private final boolean readOnly;

    /** Root component - built ONCE here; {@link #uiComponent()} only ever returns it. */
    private final ThemedPanel root;
    private final JButton attacksButton;
    private final JLabel phaseLabel;
    private final JsonTextPane jsonPane;
    private final JLabel banner;

    /** The message currently bound to this editor. */
    private HttpRequestResponse requestResponse;

    /** Verbatim original response body - the idempotent base for {@link #getResponse()}. */
    private byte[] originalBody;

    /** The parsed original response (pristine diff baseline), or {@code null} if the body is not JSON. */
    private JsonElement originalTree;

    /** The rendered baseline text in the pane; the pane differing from it means the operator edited it. */
    private String initialText = "";

    /** The styling currently on screen, so a theme change can re-colour it without a re-render. */
    private OptionsJson.Rendered styled;

    /** Which options kind was detected; {@code null} if this response is not a renderable options object. */
    private OptionsKind kind;

    public CeremonyResponseEditor(MontoyaApi api, EditorCreationContext context, Detector detector,
                                  ProfileRegistry registry) {
        this.api = api;
        this.detector = detector;
        this.registry = registry;
        this.readOnly = context != null && context.editorMode() == EditorMode.READ_ONLY;

        this.attacksButton = new JButton("Attacks ▾");
        this.attacksButton.addActionListener(e -> showAttacksMenu());

        this.jsonPane = new JsonTextPane();
        this.jsonPane.setEditable(false);

        JCheckBox wrapCheck = new JCheckBox("Wrap", true);
        wrapCheck.setToolTipText("Wrap long lines to the pane width; uncheck for a horizontal scrollbar.");
        wrapCheck.addActionListener(e -> jsonPane.setWrap(wrapCheck.isSelected()));

        this.phaseLabel = new JLabel(" ");

        this.banner = new JLabel(" ");
        this.banner.setVisible(false);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controls.add(attacksButton);
        controls.add(wrapCheck);
        controls.add(phaseLabel);
        controls.add(banner);

        this.root = new ThemedPanel(new BorderLayout());
        this.root.add(controls, BorderLayout.NORTH);
        this.root.add(new JScrollPane(jsonPane), BorderLayout.CENTER);
        // The banner and the JSON re-colour on their next render; the phase label is set once, so it is
        // the one that would otherwise hold the previous theme's grey.
        this.root.tint(phaseLabel, Palette::muted);
        this.root.onTheme(this::restyleJson);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse == null || !requestResponse.hasResponse() || requestResponse.response() == null) {
                return false;
            }
            // EDT path, and the response side sees genuinely unbounded bodies (media, downloads): cap on the
            // O(1) length before bodyToString() would allocate the whole thing.
            if (requestResponse.response().body().length() > detector.maxScanChars()) {
                return false;
            }
            if (!detector.isOptions(requestResponse.response().bodyToString())) {
                return false;
            }
            // Enabled-aware (mirrors the request tab): show only when the initiating host is tracked (enabled
            // profile) or unprofiled-with-Default-enabled; a disabled-profile host is silenced. Options carry
            // no verify-URL, so this is host-scoped only.
            return registry.tabVisibleForHost(hostOf(requestResponse));
        } catch (Throwable t) {
            // Throwable, not RuntimeException: an allocation failure on a huge response body must degrade to
            // "no tab" rather than escape into Burp. Matches the Proxy handlers.
            return false;
        }
    }

    /** The initiating request's host, or {@code null} if unavailable (then treated as an unprofiled host). */
    private static String hostOf(HttpRequestResponse rr) {
        if (rr.request() == null || rr.request().httpService() == null) {
            return null;
        }
        return rr.request().httpService().host();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        // Editor instances are REUSED - reset ALL per-message state up front so nothing from the prior
        // binding survives a failure before decodeBestEffort() repopulates it.
        this.requestResponse = requestResponse;
        this.kind = null;
        this.originalTree = null;
        this.initialText = "";
        this.phaseLabel.setText(" ");
        this.attacksButton.setEnabled(false);
        clearBanner();
        try {
            this.originalBody = requestResponse != null && requestResponse.hasResponse()
                    && requestResponse.response() != null
                    ? requestResponse.response().body().getBytes()
                    : new byte[0];
            decodeBestEffort();
        } catch (RuntimeException e) {
            this.kind = null;
            this.attacksButton.setEnabled(false);
            setPlain("Decode failed for this response; showing none.");
            api.logging().logToError("Passkey Editor: failed to decode options response", e);
            showBanner("decode failed: " + e.getMessage(), Palette::error);
        }
    }

    @Override
    public HttpResponse getResponse() {
        if (requestResponse == null || !requestResponse.hasResponse() || requestResponse.response() == null) {
            return requestResponse != null ? requestResponse.response() : null;
        }
        HttpResponse original = requestResponse.response();
        if (kind == null) {
            return original; // not a renderable options object - never touched
        }
        String current = jsonPane.getText();
        if (current.equals(initialText)) {
            return original; // unedited => byte-identical original (freeze-safe)
        }
        JsonElement edited = OptionsJson.parse(current);
        if (edited == null) {
            return original; // invalid JSON mid-edit => never send a broken response
        }
        try {
            byte[] wire = OptionsJson.toWireBytes(edited);
            EditDiffCache.record(wire, originalBody); // remember edited->original so a re-opened row shows the amber diff
            return original.withBody(ByteArray.byteArray(wire));
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: failed to rebuild edited options response", e);
            return original; // never produce a broken response
        }
    }

    @Override
    public boolean isModified() {
        return kind != null && !jsonPane.getText().equals(initialText);
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public String caption() {
        return CAPTION;
    }

    @Override
    public Component uiComponent() {
        root.themeChanged();   // cheap: a boolean compare unless the theme actually flipped
        return root;
    }

    // ---- decode + render -----------------------------------------------------------------------

    /** Best-effort decode: render the options JSON editable + coloured, or a plain read-only message. Never throws. */
    private void decodeBestEffort() {
        clearBanner();
        String bodyStr = new String(originalBody, StandardCharsets.UTF_8);

        OptionsKind detected = detector.detectOptions(bodyStr);
        if (detected == null) {
            setPlain("No WebAuthn options detected in this response body.");
            return;
        }
        JsonElement tree = OptionsJson.parse(bodyStr);
        if (tree == null || !tree.isJsonObject()) {
            setPlain(bodyStr); // options detected but not a JSON object - show raw, read-only
            showBanner("options detected but the body is not a JSON object; showing raw", Palette::warn);
            return;
        }

        this.kind = detected;
        this.originalTree = tree;
        this.phaseLabel.setText(detected == OptionsKind.REGISTRATION ? "Registration options" : "Authentication options");
        // Persistent amber (READ-ONLY only, e.g. a Proxy-history row): recover the pre-edit original from the
        // cache and highlight what changed, mirroring the request tab. Gated to read-only - not every decode -
        // so a live/editable response can never mis-attribute an edit from an unrelated body that happens to
        // share bytes with a prior recorded edit (the content-addressed cache is not host/phase-scoped). In an
        // editable context the amber comes from applying an attack in-session instead.
        Set<String> changed = Set.of();
        if (readOnly) {
            byte[] cachedOriginal = EditDiffCache.originalFor(originalBody);
            if (cachedOriginal != null) {
                JsonElement origTree = OptionsJson.parse(cachedOriginal);
                if (origTree != null) {
                    changed = OptionsJson.changedLeafPaths(origTree, tree);
                }
            }
        }
        renderTree(tree, changed);
        this.initialText = jsonPane.getText();
        // Only interactive in an editable context. In READ_ONLY (Proxy HTTP history, Scanner) Burp never calls
        // getResponse(), so a live Attacks ▾ would silently discard the edit; gate it off, mirroring the request tab.
        this.attacksButton.setEnabled(!readOnly);

        String uv = OptionsJson.userVerification(tree);
        if (uv == null) {
            showBanner("no userVerification policy present: edit the JSON freely, or add one", Palette::warn);
        } else if (OptionsJson.DISCOURAGED.equals(uv)) {
            showBanner("userVerification already 'discouraged'", Palette::warn);
        }
    }

    /** Render {@code tree} as editable coloured JSON, amber-highlighting the leaves in {@code changed}. */
    private void renderTree(JsonElement tree, Set<String> changed) {
        OptionsJson.Rendered r = OptionsJson.render(tree, changed);
        jsonPane.beginProgrammatic();  // the rebuild is not an undoable step
        jsonPane.setEditable(false);   // suppress edits during the programmatic rebuild
        StyledDocument doc = jsonPane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            doc.insertString(0, r.text(), null);
            paintSpans(doc, r);
            this.styled = r;           // remember it, so a theme change can re-colour without re-rendering
        } catch (RuntimeException | BadLocationException e) {
            // Widened beyond BadLocationException so ANY render fault degrades to plain text AND still reaches
            // endProgrammatic() below - a mid-render throw must never strand undo suppression (which would
            // silently disable Ctrl-Z). onDowngradeUv calls this without its own try/catch.
            jsonPane.setText(r.text());
        }
        jsonPane.setCaretPosition(0);
        // Editable only when the editor is; a READ_ONLY pane still renders styled text + amber diff, but must
        // not accept typing (Burp discards it) — matches CeremonyRequestEditor.editable()'s !readOnly gate.
        jsonPane.setEditable(!readOnly);
        jsonPane.endProgrammatic(); // rendered text is the undo floor; recording resumes
    }

    /** Plain (unstyled, read-only) message / raw body - for non-options or non-JSON responses. */
    private void setPlain(String text) {
        jsonPane.beginProgrammatic();
        jsonPane.setEditable(false);
        StyledDocument doc = jsonPane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            doc.insertString(0, text, null);
        } catch (BadLocationException e) {
            jsonPane.setText(text);
        }
        jsonPane.setCaretPosition(0);
        jsonPane.endProgrammatic();
    }

    /** Colour one rendered options view's spans. Reads the pane's own background, so it follows the theme. */
    private void paintSpans(StyledDocument doc, OptionsJson.Rendered r) {
        Color bg = jsonPane.getBackground();   // the pane's own background, not the panel's
        SimpleAttributeSet key = attr(Palette.jsonKey(bg), true, null);
        SimpleAttributeSet str = attr(Palette.jsonString(bg), false, null);
        SimpleAttributeSet num = attr(Palette.jsonNumber(bg), false, null);
        SimpleAttributeSet chg = attr(Palette.changedForeground(), true, Palette.changedBackground());
        for (OptionsJson.Span s : r.keys()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), key, false);
        }
        for (OptionsJson.Span s : r.strings()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), str, false);
        }
        for (OptionsJson.Span s : r.scalars()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), num, false);
        }
        for (OptionsJson.Span s : r.changed()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), chg, false);
        }
    }

    /**
     * Re-colour the options JSON already on screen after a theme change, leaving text and caret alone.
     * Syntax colours are character attributes, which a look-and-feel change does not touch. Skipped once
     * the operator has typed - the offsets would no longer line up, and the next render re-colours it.
     * See {@code CeremonyRequestEditor.restyleJson} for the full reasoning.
     */
    private void restyleJson() {
        if (styled == null) {
            return;
        }
        StyledDocument doc = jsonPane.getStyledDocument();
        try {
            if (!doc.getText(0, doc.getLength()).equals(styled.text())) {
                return;
            }
            jsonPane.beginRestyle();
            try {
                paintSpans(doc, styled);
            } finally {
                jsonPane.endRestyle();
            }
        } catch (BadLocationException e) {
            // Nothing sensible to repaint; the next render will re-colour.
        }
    }

    private static SimpleAttributeSet attr(Color fg, boolean bold, Color bg) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setForeground(a, fg);
        StyleConstants.setBold(a, bold);
        if (bg != null) {
            StyleConstants.setBackground(a, bg);
        }
        return a;
    }

    // ---- attacks -------------------------------------------------------------------------------

    private void showAttacksMenu() {
        JPopupMenu menu = new JPopupMenu();
        JsonElement current = OptionsJson.parse(jsonPane.getText());
        String uv = OptionsJson.userVerification(current != null ? current : originalTree);
        JMenuItem uvItem = new JMenuItem("Downgrade UV → discouraged");
        uvItem.setEnabled(kind != null && uv != null && !OptionsJson.DISCOURAGED.equals(uv));
        uvItem.addActionListener(e -> onDowngradeUv());
        menu.add(uvItem);
        menu.show(attacksButton, 0, attacksButton.getHeight());
    }

    /** Set userVerification to 'discouraged' in the current JSON, re-render with the change amber-highlighted. */
    private void onDowngradeUv() {
        if (kind == null || originalTree == null) {
            return;
        }
        // Work from the current pane content (so a prior hand-edit is preserved); fall back to the original if
        // the pane is mid-edit-invalid. parse() returns a FRESH tree, so mutating it never touches originalTree.
        JsonElement base = OptionsJson.parse(jsonPane.getText());
        if (base == null) {
            base = OptionsJson.parse(originalBody);
        }
        if (base == null) {
            return;
        }
        if (!OptionsJson.downgradeUv(base)) {
            showBanner("no downgradeable userVerification to change", Palette::warn);
            return;
        }
        Set<String> changed = OptionsJson.changedLeafPaths(originalTree, base);
        renderTree(base, changed);
        showBanner("userVerification set to 'discouraged': forward this response to the authenticator", Palette::ok);
    }

    // ---- banner --------------------------------------------------------------------------------

    /**
     * Show the banner in a tone carried as its meaning ({@code Palette::warn}), not as a value, so the
     * message currently on screen re-colours itself if Burp's theme changes while it is showing.
     */
    private void showBanner(String text, Supplier<Color> tone) {
        root.tint(banner, tone);
        banner.setText(text);
        banner.setVisible(true);
    }

    private void clearBanner() {
        banner.setText(" ");
        banner.setVisible(false);
    }
}
