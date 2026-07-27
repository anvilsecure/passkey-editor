package com.anvil.passkeyeditor.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import com.anvil.passkeyeditor.attacks.AssertionForger;
import com.anvil.passkeyeditor.attacks.CrossOriginForgeAttack;
import com.anvil.passkeyeditor.attacks.RegistrationEditor;
import com.anvil.passkeyeditor.attacks.SigStripAttack;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapSpec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.crypto.KeyStoreService.KeyId;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CeremonyModel;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.model.ClientData;
import com.anvil.passkeyeditor.ui.Fonts;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.ui.PlantAttestationRenderer;
import com.anvil.passkeyeditor.ui.SignerAlgorithmRenderer;
import com.anvil.passkeyeditor.ui.ThemedPanel;
import com.anvil.passkeyeditor.util.AuthDataEditor;
import com.anvil.passkeyeditor.util.EditDiffCache;
import com.anvil.passkeyeditor.util.JsonValueEditor;
import com.anvil.passkeyeditor.util.SelfEcho;

import com.anvil.passkeyeditor.profile.Encodings;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.PlantAttestation;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.TargetProfile;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * The "Passkey Editor" tab for a verify request - one instance per host editor (Proxy,
 * Repeater, …).
 *
 * Montoya must-fixes baked in (LOCKED):
 *   - {@link #uiComponent()} returns a cached final field built in the constructor - never
 *       constructs on call (the real silent-tab cause).
 *   - {@link #setRequestResponse} resets ALL per-message state up front, then runs the decode pipeline
 *       in try/catch → render always, decode best-effort; logs to the error stream, never throws.
 *   - {@link #getRequest()} is idempotent - it splices the precomputed wire overrides into the
 *       ORIGINAL body every call, so re-sign/strip is never double-applied and a no-op returns the
 *       byte-identical original. The crypto runs once, at the moment an attack is armed.
 *   - {@link #isEnabledFor} is cheap, side-effect-free, and swallows detector errors (defaults false).
 *
 * Surface. An Attacks ▾ dropdown drives the canned one-click attacks; on an assertion the
 * editable decoded JSON, the single-tick flag controls (UP/UV/BE/BS, which re-sign on toggle), and the
 * bottom Apply edits + re-sign / Re-sign with our key buttons drive arbitrary combinations.
 * All converge on a single forge path: an edit is applied as a surgical byte change to the inner
 * {@code authData} / {@code clientDataJSON}, then the assertion is re-signed with the tool's stored key
 * ({@link AssertionForger}) and the new value(s) re-wrapped + spliced back into the body. The CREATE
 * (registration) tab is symmetric: a bottom-right Register with our key button (alg chooser
 * + a short confirmation badge), UP/UV/BE/BS flag ticks, a Clear edits button, and an Attacks ▾
 * whose first move is a credentialId swap - all composed into one attestationObject re-encode by
 * {@link RegistrationEditor} (registration fields live inside the CBOR, so they are decoded → modified →
 * re-encoded → spliced, never re-signed: {@code fmt="none"} carries no attestation signature). A status area
 * below the JSON lists every armed edit (one per line) or any error.
 */
public final class CeremonyRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private static final String CAPTION = "Passkey Editor";

    // Body field names (also the JSON member names whose string values we splice).
    private static final String F_CLIENT_DATA = "clientDataJSON";
    private static final String F_AUTH_DATA = "authenticatorData";
    private static final String F_SIGNATURE = "signature";
    private static final String F_ATTESTATION = "attestationObject";

    private final MontoyaApi api;
    private final Detector detector;
    private final KeyStoreService keyStore;
    private final ProfileRegistry registry;

    /** READ_ONLY editor mode (Proxy history, Scanner, …): no editing - show only the decoded JSON + amber diff. */
    private final boolean readOnly;

    // Burp-free core collaborators (cheap, reusable).
    private final WrapperCodec wrapperCodec = new WrapperCodec.Default();
    private final CborCodec cborCodec = new Webauthn4jCborCodec();
    private final RegistrationEditor regEditor = new RegistrationEditor(cborCodec);
    private final AssertionForger forger = new AssertionForger();

    // ---- UI (built ONCE in the constructor; uiComponent() only returns the cached root) ----
    private final ThemedPanel root;
    private final JButton attacksButton;
    /** Short green confirmation shown beside the algorithm chooser after a plant (registration only). */
    private final JLabel substituteBadge;
    /** Dedicated status area below the JSON (plain JTextArea - robust across L&Fs): the cumulative re-sign
     * summary (green, one line per edit) or an error (red). Hidden when read-only / nothing armed. */
    private final JTextArea statusArea;
    /** The single editable, syntax-highlighted decoded-JSON view - the whole editor surface. */
    private final JsonTextPane jsonPane;
    /** "Apply edits + re-sign" - re-signs the (JSON-edited) assertion; shown only for GET. */
    private final JButton applyButton;
    /** "Re-sign with our key" - pure re-sign of the current assertion (a button, not an attack); GET only. */
    private final JButton resignButton;
    /** "Register with our key" - plants our key into the registration (a bottom-right button, the
     * CREATE counterpart of "Re-sign with our key", not an Attacks-menu item); CREATE only. */
    private final JButton registerButton;
    /** "Clear edits" - drops every armed override (a button, not an attack); shown for BOTH phases. */
    private final JButton clearButton;
    /** Restored single-tick flag controls (GET): toggling one re-signs the assertion immediately. */
    private final JCheckBox upBox;
    private final JCheckBox uvBox;
    private final JCheckBox beBox;
    private final JCheckBox bsBox;
    /** Rows toggled in {@link #applyPhaseVisibility}: alg chooser (CREATE), ticks + buttons (GET); all hidden
     * in a read-only (Proxy-history) view. (The Attacks row stays visible always - only its button is gated -
     * so it is a constructor local, not a field.) */
    private final JPanel algRow;
    private final JPanel flagsRow;
    private final JPanel buttonRow;
    /** Manual algorithm chooser: the algorithm "Register with our key" plants (the alg-confusion lever). */
    private final JComboBox<SignerAlgorithm> algCombo = new JComboBox<>(SignerAlgorithm.values());
    /** Manual attestation-format chooser: the attestation "Register with our key" plants (None / packed self). */
    private final JComboBox<PlantAttestation> attestationCombo = new JComboBox<>(PlantAttestation.values());
    /** Label of the algorithm last used to plant / re-sign - drives the alg-aware status summary (self-echo too). */
    private String lastSignerLabel = SignerAlgorithm.ES256.label();
    /** True when the last emitted body was a {@link #onStripSignature} (a deliberately-INVALID, un-re-signed
     * signature) - so a self-echo re-bind does not falsely mark it as "re-signed". */
    private boolean lastEmissionWasStrip;
    /** Which degradation the last strip applied, so the status names it rather than saying "stripped". */
    private SigStripAttack.Mode lastStripMode = SigStripAttack.Mode.FLIP;
    /** True once the operator manually picks an algorithm for the current binding - suppresses the
     * profile-default pre-select so {@link #applyProfileDefaultAlg} never stomps a deliberate choice. Cleared
     * on each genuinely-new message. */
    private boolean userPickedAlg;
    /** Guards the {@link #algCombo} and {@link #attestationCombo} listeners while their value is set
     * programmatically ({@link #applyProfileDefaultAlg}'s profile-default pre-select, and the per-message
     * reset of the attestation chooser to NONE), so a programmatic set is never mistaken for a manual pick. */
    private boolean suppressAlgListener;
    /** Guards the flag-tick listeners while {@link #syncFlagTicks} sets them programmatically. */
    private boolean suppressFlagListeners;
    /** The styling currently on screen, so a theme change can re-colour it without a re-render. */
    private CeremonyJson.Rendered styled;

    /** Current error text shown (red) in the status area, or {@code null} when none. Takes precedence over
     * the re-sign summary so an error never overlaps it (the old top-bar red/green overlap is gone). */
    private String statusError;

    // ---- per-message state ----
    private HttpRequestResponse requestResponse;
    private byte[] originalBody;
    private CeremonyModel model;
    /** The {@link PhaseSpec} driving extraction for the current request (also resolves credId). */
    private PhaseSpec activeSpec;

    /** Field → byte span [start,end) of its string value in {@link #originalBody}. */
    private final Map<String, int[]> spans = new LinkedHashMap<>();
    /** Field → precomputed new WIRE bytes to splice on send (idempotent base for getRequest). */
    private final Map<String, byte[]> overrides = new LinkedHashMap<>();

    // Accumulated assertion edit state (null = "unchanged from the captured value").
    private Integer editFlags;
    private Long editSignCount;
    private byte[] editClientData;
    private byte[] editRpIdHash;
    /** The human-readable rpId behind {@link #editRpIdHash} (a hash can't be reversed), for the summary. */
    private String editRpIdLabel;

    // Accumulated REGISTRATION (CREATE) edit state (null = "unchanged from the captured registration"). These
    // compose into one attestationObject re-encode via {@link RegistrationEditor} (see applyRegistrationEdits).
    /** Our signer to substitute as the credential key (the plant), or {@code null}. */
    private CoseSigner regPlantSigner;
    /** The algorithm label of {@link #regPlantSigner}, for the badge + summary. */
    private String regPlantAlgLabel;
    /** A swapped credentialId (collision / overwrite), or {@code null} to keep the captured one. */
    private byte[] regCredId;
    /** Edited registration authData flags (UP/UV/BE/BS; AT/ED preserved), or {@code null}. */
    private Integer regFlags;
    /** The body last emitted from {@link #getRequest()} - drives self-echo re-bind detection. */
    private byte[] lastEmittedBody;

    public CeremonyRequestEditor(MontoyaApi api, EditorCreationContext context, Detector detector,
                                 KeyStoreService keyStore, ProfileRegistry registry) {
        this.api = api;
        this.detector = detector;
        this.keyStore = keyStore;
        this.registry = registry;
        // Editability follows the editor context: editable in Repeater + Proxy intercept (EditorMode.DEFAULT);
        // strictly read-only in Proxy history / Scanner / Intruder views (decoded JSON + persistent amber diff).
        this.readOnly = context != null && context.editorMode() == EditorMode.READ_ONLY;

        // The whole editor surface is ONE decoded-JSON view: syntax-highlighted, with the
        // values changed by a plant / re-sign / manual edit coloured against the original. Editable on an
        // assertion (GET) so the operator can tamper a field and re-sign; read-only display on a registration.
        this.jsonPane = new JsonTextPane();
        this.jsonPane.setEditable(false);

        this.attacksButton = new JButton("Attacks ▾");
        this.attacksButton.addActionListener(e -> showAttacksMenu());
        JCheckBox wrapCheck = new JCheckBox("Wrap", true);
        wrapCheck.setToolTipText("Wrap long lines to the pane width; uncheck for a horizontal scrollbar.");
        wrapCheck.addActionListener(e -> jsonPane.setWrap(wrapCheck.isSelected()));
        JPanel attacksRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        attacksRow.add(attacksButton);
        attacksRow.add(wrapCheck);

        // Registration (CREATE) only: the algorithm "Register with our key" plants (the alg-confusion lever),
        // with a short confirmation badge right beside it. Re-sign on an assertion follows the stored key's
        // algorithm automatically, so this chooser is hidden on authentication - it would do nothing there.
        algCombo.setRenderer(new SignerAlgorithmRenderer());
        algCombo.setToolTipText("Algorithm to plant with 'Register with our key'. Re-sign uses the stored "
                + "key's algorithm automatically. Pre-set from the matched profile's default.");
        algCombo.addActionListener(e -> {
            if (!suppressAlgListener) {
                userPickedAlg = true; // a real operator pick - not the programmatic profile-default pre-select
                // If a plant is already armed, re-apply it with the newly-picked algorithm (auto re-plant) so
                // the operator does not have to click "Register with our key" again after changing the alg.
                if (regPlantSigner != null) {
                    onRegisterPlant();
                }
            }
        });
        // Attestation-format chooser (CREATE only): None (fmt="none") or Packed self-attestation. Orthogonal
        // to the algorithm - the plant works with whatever alg is selected under either format. Show the
        // human label rather than the enum constant name; re-apply an armed plant when the format changes.
        attestationCombo.setRenderer(new PlantAttestationRenderer());
        attestationCombo.setToolTipText("Attestation the plant emits. 'None' (fmt=none) for RPs that accept "
                + "it; 'Packed self-attestation' for RPs that REQUIRE attestation but don't pin a trusted root.");
        attestationCombo.addActionListener(e -> {
            if (!suppressAlgListener && regPlantSigner != null) {
                // Re-apply the armed plant under the newly-picked attestation format (mirrors the alg chooser).
                onRegisterPlant();
            }
        });
        this.substituteBadge = new JLabel(" ");
        this.substituteBadge.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0)); // padding from the chooser
        this.substituteBadge.setVisible(false);
        this.algRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        algRow.add(new JLabel("Signing algorithm:"));
        algRow.add(algCombo);
        algRow.add(new JLabel("Attestation:"));
        algRow.add(attestationCombo);
        algRow.add(substituteBadge);
        algRow.setVisible(false);

        // Authentication (GET) only: the restored single-tick flag controls, below Attacks, before the JSON.
        // Toggling a tick re-signs the assertion immediately (it flips the matching flag, then re-signs).
        this.upBox = new JCheckBox("UP");
        this.uvBox = new JCheckBox("UV");
        this.beBox = new JCheckBox("BE");
        this.bsBox = new JCheckBox("BS");
        upBox.setToolTipText("User Present");
        uvBox.setToolTipText("User Verified");
        beBox.setToolTipText("Backup Eligible");
        bsBox.setToolTipText("Backup State");
        for (JCheckBox b : new JCheckBox[]{upBox, uvBox, beBox, bsBox}) {
            b.addActionListener(e -> onFlagTick());
        }
        this.flagsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        flagsRow.add(new JLabel("Flags:"));
        flagsRow.add(upBox);
        flagsRow.add(uvBox);
        flagsRow.add(beBox);
        flagsRow.add(bsBox);
        flagsRow.setVisible(false);

        // North = a vertical stack: Attacks, then the phase-specific row (alg chooser for CREATE, flag ticks
        // for GET). Placed in BorderLayout.NORTH, so each row keeps its natural height; hidden rows collapse.
        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        attacksRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        algRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        flagsRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        north.add(attacksRow);
        north.add(algRow);
        north.add(flagsRow);

        // Status area: a dedicated multi-line space BELOW the JSON and ABOVE the buttons - each armed edit on
        // its own line; errors in red. A plain JTextArea (NOT an HTML JLabel, which Burp's L&F rendered as
        // literal markup); wraps long values; blends with the panel; never focusable/editable.
        this.statusArea = new JTextArea();
        this.statusArea.setEditable(false);
        this.statusArea.setFocusable(false);
        this.statusArea.setOpaque(false);
        this.statusArea.setLineWrap(true);
        this.statusArea.setWrapStyleWord(true);
        this.statusArea.setFont(Fonts.ui());
        this.statusArea.setBorder(BorderFactory.createEmptyBorder(4, 8, 6, 8));
        this.statusArea.setVisible(false);

        // Bottom buttons. GET: Re-sign with our key + Clear edits + Apply edits + re-sign. CREATE:
        // Register with our key + Clear edits. None is an attack, so all live here, not in the Attacks menu.
        // Per-button visibility is set in applyPhaseVisibility; the add order gives [Register][Clear] for
        // CREATE and [Re-sign][Clear][Apply] for GET once the off-phase buttons are hidden.
        this.registerButton = new JButton("Register with our key");
        this.registerButton.addActionListener(e -> onRegisterPlant());
        this.resignButton = new JButton("Re-sign with our key");
        this.resignButton.addActionListener(e -> onReSign());
        this.clearButton = new JButton("Clear edits");
        this.clearButton.addActionListener(e -> onClearEdits());
        this.clearButton.setEnabled(false);
        this.applyButton = new JButton("Apply edits + re-sign");
        this.applyButton.addActionListener(e -> onApplyJsonEdits());
        this.buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        buttonRow.add(registerButton);
        buttonRow.add(resignButton);
        buttonRow.add(clearButton);
        buttonRow.add(applyButton);
        buttonRow.setVisible(false);

        JPanel south = new JPanel(new BorderLayout());
        south.add(statusArea, BorderLayout.NORTH);
        south.add(buttonRow, BorderLayout.SOUTH);

        this.root = new ThemedPanel(new BorderLayout());
        this.root.add(north, BorderLayout.NORTH);
        this.root.add(new JScrollPane(jsonPane), BorderLayout.CENTER);
        this.root.add(south, BorderLayout.SOUTH);
        // renderStatus() recomputes the status line's text and tone from current state, so re-running it
        // is all a theme change needs there; the badge's colour is set once, so it is tinted.
        this.root.tint(substituteBadge, Palette::ok);
        this.root.onTheme(() -> {
            // Re-read both fonts: ThemedPanel fires this for a font change as well as a theme flip, so a
            // reader who enlarges Burp's message-editor font sees the decoded ceremony grow with it.
            jsonPane.setFont(Fonts.mono());
            statusArea.setFont(Fonts.ui());
            renderStatus();
            restyleJson();
        });
    }

    // ---- decoded-JSON view (render + styling) --------------------------------------------------

    /**
     * Repaint the decoded-JSON view: the decoded request as pretty, syntax-highlighted JSON; once any field is
     * overridden, the OUTGOING (edited) decode is shown with the values that changed from the original coloured.
     * Best-effort - never throws on the EDT (falls back to a plain note). Called on decode / Attacks action /
     * Apply, never while the operator is typing.
     */
    private void renderJson() {
        if (model == null) {
            setJsonPlain("No WebAuthn ceremony decoded in this request.");
            return;
        }
        try {
            JsonObject modelTree = CeremonyJson.tree(model);
            JsonObject viewTree = modelTree;
            Set<String> changed = Set.of();
            if (!overrides.isEmpty()) {
                // Editable context: show the OUTGOING (edited) decode, amber on what changed vs the captured original.
                byte[] outgoing = buildOutgoingBody();
                EditDiffCache.record(outgoing, originalBody); // so a read-only Proxy-history view can diff
                CeremonyModel edited = decodeModelFrom(outgoing, activeSpec, model.type());
                viewTree = CeremonyJson.tree(edited);
                changed = CeremonyJson.changedLeafPaths(modelTree, viewTree);
            } else if (readOnly) {
                // Read-only (Proxy history): the bound request is the final/edited one. Recover its ORIGINAL
                // from the edit cache (populated by the manual editor on send + the AUTO handler at its Proxy
                // rewrite) and diff, so the amber persists without toggling Original/Edited (point 1).
                byte[] bound = requestResponse != null && requestResponse.request() != null
                        ? requestResponse.request().body().getBytes() : null;
                byte[] original = EditDiffCache.originalFor(bound);
                if (original != null) {
                    CeremonyModel om = decodeModelFrom(original, activeSpec, model.type());
                    changed = CeremonyJson.changedLeafPaths(CeremonyJson.tree(om), modelTree);
                }
                // Intentionally silent: logging here would spam on every history selection/scroll - the amber
                // diff itself is the signal, and a non-cached row simply shows the plain decode.
            }
            applyStyledJson(CeremonyJson.render(viewTree, changed));
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: JSON render failed", e);
            setJsonPlain("Decode/render failed; see the Errors tab.");
        }
        syncFlagTicks();   // keep the GET flag ticks mirroring the rendered (effective) flags
        updateButtons();   // Clear edits is enabled only when something is armed
    }

    /** Plain (unstyled, read-only) message in the JSON pane - for decode failures / no-ceremony. */
    private void setJsonPlain(String text) {
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
        jsonPane.setEditable(editable());
        jsonPane.endProgrammatic();
    }

    /** Set the JSON text and colour keys / strings / scalars + the changed values (theme-aware). */
    private void applyStyledJson(CeremonyJson.Rendered r) {
        jsonPane.beginProgrammatic(); // the rebuild is not an undoable step
        jsonPane.setEditable(false); // suppress edits during the programmatic rebuild
        StyledDocument doc = jsonPane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            doc.insertString(0, r.text(), null);
            paintSpans(doc, r);
        } catch (BadLocationException e) {
            jsonPane.setText(r.text());
        }
        this.styled = r;               // remember it, so a theme change can re-colour without re-rendering
        jsonPane.setCaretPosition(0);
        jsonPane.setEditable(editable());
        jsonPane.endProgrammatic(); // rendered text is the undo floor; recording resumes
    }

    /** Colour one rendered decode's spans. Reads the pane's own background, so it follows the theme. */
    private void paintSpans(StyledDocument doc, CeremonyJson.Rendered r) {
        Color bg = jsonPane.getBackground();   // the pane's own background, not the panel's
        SimpleAttributeSet key = attr(Palette.jsonKey(bg), true, null);
        SimpleAttributeSet str = attr(Palette.jsonString(bg), false, null);
        SimpleAttributeSet num = attr(Palette.jsonNumber(bg), false, null);
        SimpleAttributeSet chg = attr(Palette.changedForeground(), true, Palette.changedBackground());
        for (CeremonyJson.Span s : r.keys()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), key, false);
        }
        for (CeremonyJson.Span s : r.strings()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), str, false);
        }
        for (CeremonyJson.Span s : r.scalars()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), num, false);
        }
        for (CeremonyJson.Span s : r.changed()) {
            doc.setCharacterAttributes(s.start(), s.end() - s.start(), chg, false);
        }
    }

    /**
     * Re-colour the JSON already on screen after a theme change, leaving the text and the caret alone.
     *
     * Syntax colours live in the document as character attributes, which a look-and-feel change does
     * not touch - so without this the decode keeps the previous theme's palette until something forces a
     * re-render. Re-rendering is not an option here: {@link #renderJson()} rebuilds the text from the
     * model and would throw away whatever the operator is part-way through typing, which on Intercept is
     * the likeliest thing to be happening. So the spans are re-painted onto the existing text instead,
     * and only while that text is still exactly what was rendered - once it has been typed into, the
     * offsets no longer line up, and the next real render re-colours it anyway.
     */
    private void restyleJson() {
        if (styled == null) {
            return;
        }
        StyledDocument doc = jsonPane.getStyledDocument();
        try {
            if (!doc.getText(0, doc.getLength()).equals(styled.text())) {
                return;   // edited since the render: leave it to the next renderJson()
            }
            jsonPane.beginRestyle();   // an attribute change is undoable; this one must not be recorded
            try {
                paintSpans(doc, styled);
            } finally {
                jsonPane.endRestyle(); // keeps the undo history: re-colouring is not a new floor
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

    /** The algorithm currently selected in the chooser (defaults ES256 if somehow unset). */
    private SignerAlgorithm selectedAlgorithm() {
        Object sel = algCombo.getSelectedItem();
        return sel instanceof SignerAlgorithm a ? a : SignerAlgorithm.ES256;
    }

    /** The attestation format currently selected in the chooser (defaults NONE if somehow unset). */
    private PlantAttestation selectedAttestation() {
        Object sel = attestationCombo.getSelectedItem();
        return sel instanceof PlantAttestation a ? a : PlantAttestation.NONE;
    }

    /** The registration's inner clientDataJSON wire bytes (the packed self-attestation signed input), or null. */
    private byte[] registrationClientDataJson() {
        return model != null && model.clientData() != null ? model.clientData().raw() : null;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse == null || requestResponse.request() == null) {
                return false;
            }
            HttpRequest req = requestResponse.request();
            // Runs on the EDT for every message Burp offers a tab for: cap before stringifying so a large
            // body cannot allocate its whole (UTF-16, ~2x) String on the UI thread.
            if (req.body().length() > detector.maxScanChars()) {
                return false;
            }
            CeremonyType type = detector.detect(req.bodyToString());
            if (type == null) {
                return false;
            }
            // Enabled-aware visibility (NOT just structural detection): a host with an ENABLED profile shows
            // the tab scoped to that profile's pinned verify URL; a host whose profile is DISABLED is silenced
            // (no tab) even though the Default is enabled; an UNPROFILED host falls to the
            // Default, honouring the Default's own enabled switch. See ProfileRegistry.tabVisibleFor.
            Phase phase = type == CeremonyType.CREATE ? Phase.REG_VERIFY : Phase.AUTH_VERIFY;
            return registry.tabVisibleFor(hostOf(req), phase, urlOf(req), methodOf(req));
        } catch (Throwable t) {
            // Throwable, not RuntimeException: an allocation failure on a huge body must degrade to "no tab"
            // rather than escape into Burp. Matches the deliberate catch (Throwable) in both Proxy handlers.
            return false;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        // Re-read Burp's message-editor font on every binding. Changing it is a settings change, not a
        // look-and-feel change, so no updateUI() fires and the ThemedPanel hook never runs - without this the
        // decoded view kept whichever size it was built with until the extension was reloaded. Selecting
        // another request is the natural moment to pick the new size up.
        jsonPane.setFont(Fonts.mono());
        // SELF-ECHO GUARD. Burp re-invokes setRequestResponse() with the request the editor itself just
        // emitted from getRequest() - the documented getRequest→setRequestResponse round-trip on a sub-tab
        // switch / refresh / send (the editor reports isModified()==true, so Burp pulls our edited bytes
        // and hands them straight back). Re-baselining to that ALREADY-FORGED body would wipe the
        // accumulated edit state AND shift the diff baseline, collapsing the cumulative summary to only the
        // last action. When the incoming body equals our last emission, treat it as a self-echo: keep the
        // pristine baseline + edit state + overrides + spans intact (getRequest stays idempotent off the
        // real original), just re-bind the request skeleton and re-render the surviving summary.
        byte[] incomingBody = requestResponse != null && requestResponse.request() != null
                ? requestResponse.request().body().getBytes() : null;
        if (SelfEcho.isSelfEcho(incomingBody, lastEmittedBody, !overrides.isEmpty())) {
            this.requestResponse = requestResponse;
            renderJson();          // re-bound to our edited body → coloured diff + ticks re-synced
            renderStatus();   // summary / strip notice derived from the surviving edit state
            return;
        }

        // Genuinely new (or differing) message - editor instances are REUSED, so reset ALL per-message
        // state up front so nothing from the prior binding survives a failure before decodeBestEffort().
        this.requestResponse = requestResponse;
        this.model = null;
        this.activeSpec = null;
        this.spans.clear();
        this.overrides.clear();
        this.editFlags = null;
        this.editSignCount = null;
        this.editClientData = null;
        this.editRpIdHash = null;
        this.editRpIdLabel = null;
        this.regPlantSigner = null;
        this.regPlantAlgLabel = null;
        this.regCredId = null;
        this.regFlags = null;
        this.lastEmittedBody = null;
        this.lastEmissionWasStrip = false;
        this.userPickedAlg = false; // a genuinely-new message → the matched profile's default alg wins again
        // Reset the manual attestation chooser to its NONE default for each genuinely-new message (a per-edit
        // choice, not sticky across messages - keeps "default NONE everywhere" literally true per binding).
        // Suppress the listener around the programmatic set (this is what makes the shared suppressAlgListener
        // guard on the attestation listener load-bearing rather than inert).
        suppressAlgListener = true;
        try {
            attestationCombo.setSelectedItem(PlantAttestation.NONE);
        } finally {
            suppressAlgListener = false;
        }
        clearStatus();
        substituteBadge.setVisible(false);
        applyPhaseVisibility(null); // rows stay hidden until the decode determines the phase
        try {
            this.originalBody = requestResponse != null && requestResponse.request() != null
                    ? requestResponse.request().body().getBytes()
                    : new byte[0];
            decodeBestEffort();
        } catch (RuntimeException e) {
            this.model = null;
            applyPhaseVisibility(null);
            setJsonPlain("Decode failed for this request; showing none.");
            api.logging().logToError("Passkey Editor: failed to decode ceremony", e);
            showError("decode failed: " + e.getMessage());
        }
    }

    @Override
    public HttpRequest getRequest() {
        // Idempotent: splice the PRECOMPUTED overrides into the ORIGINAL body every call.
        if (requestResponse == null || requestResponse.request() == null) {
            return null;
        }
        HttpRequest original = requestResponse.request();
        if (overrides.isEmpty()) {
            lastEmittedBody = originalBody; // we emit the unmodified original
            return original; // no edits ⇒ byte-identical original
        }
        try {
            byte[] out = buildOutgoingBody();
            lastEmittedBody = out; // record so a Burp re-bind with this body is recognised as a self-echo
            EditDiffCache.record(out, originalBody); // remember edited→original for a read-only Proxy-history diff
            return original.withBody(ByteArray.byteArray(out));
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: failed to rebuild request", e);
            lastEmittedBody = originalBody;
            return original; // never produce a broken request
        }
    }


    @Override
    public boolean isModified() {
        return !overrides.isEmpty();
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

    // ---- outgoing body assembly ----------------------------------------------------------------

    /**
     * Splice every armed override into {@link #originalBody}. Splices are applied in descending
     * start offset so that replacing one field's value never shifts the spans of fields earlier in the
     * body - letting clientDataJSON + authenticatorData + signature all be replaced in one pass.
     */
    private byte[] buildOutgoingBody() {
        List<int[]> spliceSpans = new ArrayList<>();
        List<byte[]> values = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : overrides.entrySet()) {
            int[] span = spans.get(e.getKey());
            if (span != null) {
                spliceSpans.add(span);
                values.add(e.getValue());
            }
        }
        return JsonValueEditor.spliceAll(originalBody, spliceSpans, values);
    }

    private void rewrapInto(String field, byte[] inner, WrapSpec wrap) {
        overrides.put(field, wrapperCodec.rewrap(inner, wrap != null ? wrap : new WrapSpec()));
    }

    // ---- Attacks ▾ menu ------------------------------------------------------------------------

    private void showAttacksMenu() {
        JPopupMenu menu = new JPopupMenu();
        if (model == null) {
            addDisabled(menu, "No ceremony decoded");
        } else if (model.type() == CeremonyType.CREATE) {
            // the plant is now the bottom-right "Register with our key" button (not an attack). The
            // CREATE Attacks ▾ holds the genuinely-offensive registration move - a credentialId swap (a
            // credential collision / overwrite if the RP keys by credId and allows overwrite).
            JMenuItem swap = item("Swap credentialId (collision / overwrite)", this::onSwapCredId);
            swap.setEnabled(createEditable() && model.attestationObject().authData().credentialId() != null);
            menu.add(swap);
        } else { // GET - Re-sign with our key + Clear edits are buttons below (neither is an attack)
            menu.add(item("Forge UV=0 (clear UV) + re-sign", this::onForgeUv0));
            menu.add(item("Mutate origin + re-sign", this::onMutateOrigin));
            menu.add(item("Mutate RP-ID + re-sign", this::onMutateRpId));
            menu.add(item("Forge cross-origin (clickjacking) + re-sign", this::onForgeCrossOrigin));
            menu.addSeparator();
            // All four degradation modes, not just the default: they are DIFFERENT probes, and naming the
            // menu "strip" while only flipping a byte misled a tester into expecting an emptied signature.
            JMenu strip = new JMenu("Invalidate signature (no re-sign)");
            strip.add(describedItem("Flip trailing byte", "same length, structure intact; fails verification",
                    () -> onStripSignature(SigStripAttack.Mode.FLIP)));
            strip.add(describedItem("Empty", "probes whether a signature is required at all",
                    () -> onStripSignature(SigStripAttack.Mode.EMPTY)));
            strip.add(describedItem("Zeroed", "all-zero bytes, original length",
                    () -> onStripSignature(SigStripAttack.Mode.ZEROED)));
            strip.add(describedItem("Random bytes", "original length",
                    () -> onStripSignature(SigStripAttack.Mode.GARBAGE)));
            menu.add(strip);
        }
        menu.show(attacksButton, 0, attacksButton.getHeight());
    }

    /**
     * A menu item reading {@code Title: description}.
     *
     * Plain text, never HTML. Burp's look-and-feel renders an HTML menu label as literal
     * markup - the item shows the tags themselves. This is the same trap that forced the status area to
     * be a {@code JTextArea} rather than an HTML {@code JLabel}, so it is a property of the L&F, not of
     * one widget: do not reach for {@code <html>} to style anything inside the editor.
     */
    private static JMenuItem describedItem(String title, String description, Runnable action) {
        return item(title + ": " + description, action);
    }

    private static JMenuItem item(String label, Runnable action) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(e -> action.run());
        return mi;
    }

    private static void addDisabled(JPopupMenu menu, String label) {
        JMenuItem mi = new JMenuItem(label);
        mi.setEnabled(false);
        menu.add(mi);
    }

    // ---- attack actions ------------------------------------------------------------------------

    /**
     * Registration plant (CREATE): arm our key as the credential key + re-encode ({@code fmt="none"}). This
     * is the bottom-right "Register with our key" button - symmetric to the GET tab's "Re-sign with our key"
     *. The key is stored (keyed by credentialId) so a later GET assertion re-signs with it.
     */
    private void onRegisterPlant() {
        if (!createEditable()) {
            showError("No substitutable registration in this request.");
            return;
        }
        SignerAlgorithm alg = selectedAlgorithm();
        // Snapshot the current plant so a refused/failed re-plant rolls back to it, mirroring onSwapCredId /
        // onFlagTick. Nulling instead would desync state: applyRegistrationEdits only rewrites the
        // attestationObject override on success, so after a prior successful plant a failed re-plant would
        // otherwise leave that override (and the badge) armed while the tracking fields claim nothing is planted.
        CoseSigner previousSigner = regPlantSigner;
        String previousAlgLabel = regPlantAlgLabel;
        String previousSignerLabel = lastSignerLabel;
        try {
            regPlantSigner = alg.generate();
            regPlantAlgLabel = alg.label();
            lastSignerLabel = alg.label();
            if (applyRegistrationEdits()) {
                String attSuffix = selectedAttestation() == PlantAttestation.PACKED_SELF
                        ? " (packed self-attestation)" : "";
                substituteBadge.setText(alg.label() + " key planted" + attSuffix);
                substituteBadge.setVisible(true);
            } else {
                regPlantSigner = previousSigner; // refused - restore the prior plant (override still matches it)
                regPlantAlgLabel = previousAlgLabel;
                lastSignerLabel = previousSignerLabel;
            }
        } catch (RuntimeException e) {
            regPlantSigner = previousSigner;
            regPlantAlgLabel = previousAlgLabel;
            lastSignerLabel = previousSignerLabel;
            api.logging().logToError("Passkey Editor: key substitution failed", e);
            showError("substitution failed: " + e.getMessage());
        }
    }

    /**
     * Swap the registration credentialId (CREATE Attacks ▾): set our registration's credentialId to another
     * account's, testing credential collision / overwrite. If the RP keys by credentialId and allows
     * overwrite, planting our key too (Register with our key) lands it under the victim's credential =
     * ATO-at-registration. Accepts hex (pre-filled current value) or base64 / base64url.
     */
    private void onSwapCredId() {
        AttestationObject att = model != null ? model.attestationObject() : null;
        byte[] current = att != null && att.authData() != null ? att.authData().credentialId() : null;
        if (!createEditable() || current == null) {
            showError("No registration credentialId to swap.");
            return;
        }
        String input = JOptionPane.showInputDialog(suiteFrame(),
                "New credentialId: hex (pre-filled), or base64 / base64url. Set it to another account's\n"
                        + "credentialId to test credential collision / overwrite (length may differ).",
                HexFormat.of().formatHex(current));
        if (input == null) {
            return; // cancelled
        }
        byte[] swapped = parseCredId(input.trim());
        if (swapped == null) {
            showError("credentialId must be hex or base64: could not parse it.");
            return;
        }
        byte[] previous = regCredId;
        regCredId = swapped;
        if (!applyRegistrationEdits()) {
            regCredId = previous; // refused (e.g. an ED registration) - roll back, mirroring onRegisterPlant / onFlagTick
        }
    }

    /**
     * Re-encode the registration attestationObject with every armed CREATE edit composed in one pass - the
     * plant (our key + {@code fmt="none"}), a swapped credentialId, edited authData flags - then re-wrap +
     * splice it into the body via {@link RegistrationEditor}. {@code fmt="none"} carries no attestation
     * signature, so there is nothing to re-sign; the bytes only round-trip. Idempotent: always rebuilds from
     * the CAPTURED original, so clearing an edit cleanly drops it. The CREATE-side counterpart of
     * {@link #forgeWith}.
     *
     * @return {@code true} if applied (or cleanly cleared); {@code false} if refused (no decodable registration)
     */
    private boolean applyRegistrationEdits() {
        AttestationObject att = model != null ? model.attestationObject() : null;
        if (model == null || model.type() != CeremonyType.CREATE || att == null
                || att.authData() == null || !spans.containsKey(F_ATTESTATION)) {
            showError("No editable registration in this request.");
            return false;
        }
        // Nothing armed → drop the override (idempotent clear): toggling an edit back to neutral leaves the
        // body byte-identical to the captured original (getRequest short-circuits on an empty override set).
        if (regPlantSigner == null && regCredId == null && regFlags == null) {
            overrides.remove(F_ATTESTATION);
            statusError = null;
            renderJson();
            renderStatus();
            return true;
        }
        // Packed self-attestation signs over authData ‖ SHA-256(clientDataJSON), so a plant in that mode needs
        // the registration's clientDataJSON. Refuse up front with a clear message if it is not locatable.
        PlantAttestation attestation = regPlantSigner != null ? selectedAttestation() : PlantAttestation.NONE;
        byte[] clientDataJson = attestation == PlantAttestation.PACKED_SELF ? registrationClientDataJson() : null;
        if (attestation == PlantAttestation.PACKED_SELF && clientDataJson == null) {
            showError("packed self-attestation needs the registration clientDataJSON, which is not decodable "
                    + "in this request.");
            return false;
        }
        try {
            // Rebuild from a FRESH decode of the CAPTURED original so the on-screen display model is never
            // mutated and clearing one edit cleanly removes it (RegistrationEditor.edit mutates its argument).
            byte[] sourceCbor = att.raw() != null ? att.raw() : cborCodec.encodeAttestationObject(att);
            AttestationObject fresh = cborCodec.decodeAttestationObject(sourceCbor);
            byte[] wire = regEditor.edit(fresh, regPlantSigner, regCredId, regFlags, attestation, clientDataJson);
            rewrapInto(F_ATTESTATION, wire, model.attestationObjectWrap());

            // Keep the keystore credId↔planted-key linkage consistent: store the planted signer under the
            // EFFECTIVE credentialId (swapped if armed) - the id the RP will key by and the GET re-sign will
            // look up. Without this a credId swap would orphan the planted key at re-sign time.
            if (regPlantSigner != null) {
                byte[] effectiveCredId = regCredId != null ? regCredId : fresh.authData().credentialId();
                if (effectiveCredId != null) {
                    keyStore.storeSigner(new KeyId(rpIdHost(), "",
                            HexFormat.of().formatHex(effectiveCredId)), regPlantSigner);
                }
            }
            lastEmissionWasStrip = false;
            statusError = null;
            renderJson(); // show the planted key / swapped credId / flags amber-highlighted in the JSON
            renderStatus();
            return true;
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: registration re-encode failed", e);
            showError("registration edit failed: " + e.getMessage());
            return false;
        }
    }

    /** Parse a credentialId the operator typed: hex when it looks like hex (even length, hex digits), else
     * base64url, else base64. Returns {@code null} if blank or unparseable. */
    private static byte[] parseCredId(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        if (s.length() % 2 == 0 && s.matches("[0-9a-fA-F]+")) {
            try {
                return HexFormat.of().parseHex(s);
            } catch (RuntimeException ignored) {
                // fall through to base64
            }
        }
        for (Base64.Decoder dec : new Base64.Decoder[]{Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                byte[] out = dec.decode(s);
                if (out.length > 0) {
                    return out;
                }
            } catch (RuntimeException ignored) {
                // try the next flavor
            }
        }
        return null;
    }

    /** Re-sign the (current) assertion with our stored key - the pure forgery. */
    private void onReSign() {
        forgeWith(null, null, null, null);
    }

    /**
     * Forge a UV=0 assertion: clear the UV flag bit, re-sign.
     *
     * UV=0 is not a bypass against a UV-enforcing RP. A relying party that requires user
     * verification rejects {@code !uv} on policy before it checks the signature, so it returns an
     * error regardless of how valid the forged signature is. Only a relying party that does not enforce UV
     * accepts a UV=0 assertion - the same acceptance shape as the client-side UV-downgrade attack, but
     * reached here by forgery rather than a policy downgrade. To forge an assertion a UV-enforcing RP
     * accepts, keep UV=1 ("Re-sign with our key").
     */
    private void onForgeUv0() {
        if (model == null || model.authenticatorData() == null) {
            return;
        }
        int cleared = model.authenticatorData().flags() & ~AuthenticatorData.FLAG_UV;
        if (forgeWith(cleared, null, null, null)) {
            renderStatus();
        }
    }

    /** Surgically swap clientDataJSON.origin, re-sign (origin-mutation attack). */
    private void onMutateOrigin() {
        ClientData cd = model != null ? model.clientData() : null;
        if (cd == null || cd.raw() == null) {
            showError("No clientDataJSON to edit.");
            return;
        }
        int[] originSpan = JsonValueEditor.findStringValueSpan(cd.raw(), "origin");
        if (originSpan == null) {
            showError("No editable 'origin' member in clientDataJSON.");
            return;
        }
        String current = new String(cd.raw(), originSpan[0], originSpan[1] - originSpan[0], StandardCharsets.UTF_8);
        String input = JOptionPane.showInputDialog(suiteFrame(), "New origin:", current);
        if (input == null) {
            return; // cancelled
        }
        byte[] edited = JsonValueEditor.splice(cd.raw(), originSpan, input.getBytes(StandardCharsets.UTF_8));
        forgeWith(null, null, edited, null);
    }

    /**
     * Forge a cross-origin (framing / clickjacking) clientDataJSON, re-sign (CWE-1021). Sets
     * {@code crossOrigin=true} + a {@code topOrigin} the operator supplies and leaves {@code origin}
     * byte-identical - isolating the framing check ({@code crossOrigin}/{@code topOrigin}) that most RPs
     * miss from the {@code origin} check they all already do (use "Mutate origin" for the latter). The edit
     * is byte-surgical; the assertion is then re-signed so the RP cannot reject on the signature and the
     * framing check is what decides accept vs reject.
     */
    private void onForgeCrossOrigin() {
        ClientData cd = model != null ? model.clientData() : null;
        if (cd == null || cd.raw() == null) {
            showError("No clientDataJSON to edit.");
            return;
        }
        String input = JOptionPane.showInputDialog(suiteFrame(),
                "Top origin (attacker-controlled top document):", "https://attacker.example");
        if (input == null) {
            return; // cancelled
        }
        CrossOriginForgeAttack.Result r = new CrossOriginForgeAttack().forge(cd.raw(), input);
        if (forgeWith(null, null, r.clientData(), null)) {
            renderStatus();
        }
    }

    /** Replace the rpIdHash with SHA-256(new rpId), re-sign (RP-ID mutation attack). */
    private void onMutateRpId() {
        String input = JOptionPane.showInputDialog(suiteFrame(),
                "New RP ID (rpIdHash = SHA-256(rpId)):", rpIdHost());
        if (input == null) {
            return; // cancelled
        }
        byte[] hash = sha256(input.getBytes(StandardCharsets.UTF_8));
        // Set the display label only if the forge actually arms (forgeWith can refuse), so a refused edit
        // never leaves a dangling rpId label. forgeWith owns all edit state - mirror onMutateOrigin.
        if (forgeWith(null, null, null, hash)) {
            editRpIdLabel = input; // the rpId string for the summary (the hash can't be reversed)
        }
    }

    /**
     * "Apply edits + re-sign": read the operator's edited JSON, diff its editable fields against the original,
     * and re-sign over the combination via the existing forge path. GET only (a registration has no assertion
     * signature to re-sign - its move is the plant via the Register with our key button). Bad JSON → a
     * status error, no change.
     */
    private void onApplyJsonEdits() {
        if (model == null || model.type() != CeremonyType.GET) {
            return;
        }
        CeremonyJson.Edits e = CeremonyJson.diffEdits(jsonPane.getText(), model);
        if (e.parseError()) {
            showError(e.error() != null ? e.error() : "invalid JSON: fix the syntax and try again.");
            return;
        }
        forgeWith(e.flags(), e.signCount(), e.clientData(), e.rpIdHash());
    }

    /**
     * The clientDataJSON bytes the assertion signature must cover, or {@code null} when they are unavailable
     * (the caller must then refuse to forge). Returns the operator's edited bytes if present; otherwise the
     * exact wire bytes off the decoded model. Never a placeholder: signing over an empty stand-in
     * while the wire still carries the real clientDataJSON yields a signature the RP rejects, so an
     * unavailable clientData must fail closed, not degrade to {@code new byte[0]}.
     */
    static byte[] signingClientData(byte[] editClientData, ClientData modelClientData) {
        if (editClientData != null) {
            return editClientData;
        }
        return (modelClientData != null && modelClientData.raw() != null) ? modelClientData.raw() : null;
    }

    /**
     * The single forge path. Non-null arguments update the accumulated edit state; the (possibly edited)
     * authData + clientDataJSON are then re-signed with our stored key and the new wire values staged as
     * overrides. Idempotent at the byte level - {@link #getRequest()} only splices these results.
     *
     * @return {@code true} if a forge was armed; {@code false} if it was refused (no assertion, no stored
     *     key, or an edited field cannot be written back to this body)
     */
    private boolean forgeWith(Integer flags, Long signCount, byte[] clientData, byte[] rpIdHash) {
        if (model == null || model.type() != CeremonyType.GET || model.authenticatorData() == null
                || model.authenticatorData().raw() == null) {
            showError("No assertion to forge (need a decoded webauthn.get).");
            return false;
        }
        CoseSigner signer = signerForCurrentAssertion();
        if (signer == null) {
            showError("No stored key: plant one first with the 'Register with our key' button on a "
                    + "registration (webauthn.create) request.");
            return false;
        }
        lastSignerLabel = labelFor(signer); // re-sign uses the held key's algorithm
        lastEmissionWasStrip = false;
        // Validate write-back BEFORE mutating edit state: every field we sign over must be splice-able back
        // onto the wire, else the RP would verify our signature against bytes the body never carries.
        if (!spans.containsKey(F_SIGNATURE)) {
            showError("no signature field to write on this body: cannot forge.");
            return false;
        }
        boolean willEditAuthData = rpIdHash != null || flags != null || signCount != null
                || editRpIdHash != null || editFlags != null || editSignCount != null;
        boolean willEditClientData = clientData != null || editClientData != null;
        if (willEditAuthData && !spans.containsKey(F_AUTH_DATA)) {
            showError("cannot write edited authenticatorData back to this body: not forging.");
            return false;
        }
        if (willEditClientData && !spans.containsKey(F_CLIENT_DATA)) {
            showError("cannot write edited clientDataJSON back to this body: not forging.");
            return false;
        }
        // clientDataJSON is half of the assertion signed input (authData ‖ SHA-256(clientDataJSON)). When we
        // are NOT editing it, the signature must cover the exact clientDataJSON bytes already on the wire; if
        // that field failed to decode on this body we don't have them, and signing over SHA-256("") would
        // emit a signature the RP rejects while the UI reports a successful forgery. Refuse instead.
        if (!willEditClientData && (model.clientData() == null || model.clientData().raw() == null)) {
            showError("cannot re-sign: clientDataJSON did not decode on this body.");
            return false;
        }

        if (flags != null) {
            editFlags = flags;
        }
        if (signCount != null) {
            editSignCount = signCount;
        }
        if (clientData != null) {
            editClientData = clientData;
        }
        if (rpIdHash != null) {
            editRpIdHash = rpIdHash;
        }
        try {
            byte[] ad = model.authenticatorData().raw();
            boolean adEdited = false;
            if (editRpIdHash != null) {
                ad = AuthDataEditor.withRpIdHash(ad, editRpIdHash);
                adEdited = true;
            }
            if (editFlags != null) {
                ad = AuthDataEditor.withFlags(ad, editFlags);
                adEdited = true;
            }
            if (editSignCount != null) {
                ad = AuthDataEditor.withSignCount(ad, editSignCount);
                adEdited = true;
            }
            // Non-null in every branch: editClientData covers the edited case; otherwise the guard above
            // already refused when the wire bytes are unavailable. signingClientData() never returns a
            // placeholder, so a future removal of that guard degrades to a loud null (rejected by the
            // forger) rather than a silent signature over SHA-256("").
            byte[] cd = signingClientData(editClientData, model.clientData());

            byte[] sig = forger.sign(ad, cd, signer);

            // The write-back guards above guarantee the needed spans exist when adEdited / editClientData.
            overrides.remove(F_AUTH_DATA);
            overrides.remove(F_CLIENT_DATA);
            if (adEdited) {
                rewrapInto(F_AUTH_DATA, ad, model.authenticatorDataWrap());
            }
            if (editClientData != null) {
                rewrapInto(F_CLIENT_DATA, cd, model.clientDataWrap());
            }
            rewrapInto(F_SIGNATURE, sig, model.signatureWrap());

            // Repaint the JSON with the coloured diff, then show the cumulative summary in the status area
            // below - each armed edit on its own line, so a stacked attack (e.g. UV=0 then origin) shows
            // every change that will go on the wire.
            renderJson();
            statusError = null;
            renderStatus();
            return true;
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: forge failed", e);
            showError("forge failed: " + e.getMessage());
            return false;
        }
    }

    /** The cumulative, one-entry-per-line description of every currently-armed edit (drives the status area). */
    private List<String> armedEditLines() {
        List<String> parts = new ArrayList<>();
        if (editRpIdHash != null) {
            parts.add("rpId = " + (editRpIdLabel != null ? editRpIdLabel : "<edited>"));
        }
        if (editFlags != null) {
            parts.add(flagsLabel(editFlags));
        }
        if (editSignCount != null) {
            parts.add("signCount = " + editSignCount);
        }
        if (editClientData != null) {
            parts.add(clientDataDelta());
        }
        return parts;
    }

    /** The cumulative, one-entry-per-line description of every armed REGISTRATION edit (CREATE status area). */
    private List<String> regEditLines() {
        List<String> parts = new ArrayList<>();
        if (regPlantSigner != null) {
            String attSuffix = selectedAttestation() == PlantAttestation.PACKED_SELF
                    ? ", packed self-attestation" : "";
            parts.add("planted our " + regPlantAlgLabel + " key" + attSuffix);
        }
        if (regCredId != null) {
            parts.add("credentialId = " + HexFormat.of().formatHex(regCredId));
        }
        if (regFlags != null) {
            parts.add(flagsLabel(regFlags));
        }
        return parts;
    }

    /** Render an edited flags byte as its set names plus the bits cleared vs the captured original. */
    private String flagsLabel(int flags) {
        StringBuilder set = new StringBuilder();
        if ((flags & AuthenticatorData.FLAG_UP) != 0) set.append("UP ");
        if ((flags & AuthenticatorData.FLAG_UV) != 0) set.append("UV ");
        if ((flags & AuthenticatorData.FLAG_BE) != 0) set.append("BE ");
        if ((flags & AuthenticatorData.FLAG_BS) != 0) set.append("BS ");
        String label = "flags = [" + set.toString().trim() + "]";
        int orig = model.authenticatorData() != null ? model.authenticatorData().flags() : flags;
        List<String> cleared = new ArrayList<>();
        if ((orig & AuthenticatorData.FLAG_UP) != 0 && (flags & AuthenticatorData.FLAG_UP) == 0) cleared.add("UP=0");
        if ((orig & AuthenticatorData.FLAG_UV) != 0 && (flags & AuthenticatorData.FLAG_UV) == 0) cleared.add("UV=0");
        return cleared.isEmpty() ? label : label + " (" + String.join(",", cleared) + ")";
    }

    /** Name what changed in an edited clientDataJSON (framing / origin / challenge / generic), vs the captured one. */
    private String clientDataDelta() {
        try {
            JsonObject edited = JsonParser.parseString(new String(editClientData, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            ClientData orig = model.clientData();
            // Framing forge (crossOrigin / topOrigin): report the pair when either differs from the captured
            // value. Takes precedence because this edit deliberately leaves origin/challenge untouched.
            List<String> framing = new ArrayList<>();
            if (edited.has("crossOrigin") && edited.get("crossOrigin").isJsonPrimitive()) {
                boolean co = edited.get("crossOrigin").getAsBoolean();
                Boolean origCo = orig != null ? orig.crossOrigin() : null;
                if (origCo == null || origCo.booleanValue() != co) {
                    framing.add("crossOrigin = " + co);
                }
            }
            if (edited.has("topOrigin") && edited.get("topOrigin").isJsonPrimitive()) {
                String to = edited.get("topOrigin").getAsString();
                String origTo = orig != null ? orig.topOrigin() : null;
                if (origTo == null || !origTo.equals(to)) {
                    framing.add("topOrigin = " + to);
                }
            }
            if (!framing.isEmpty()) {
                return String.join(", ", framing);
            }
            String newOrigin = edited.has("origin") && edited.get("origin").isJsonPrimitive()
                    ? edited.get("origin").getAsString() : null;
            if (newOrigin != null && (orig == null || !newOrigin.equals(orig.origin()))) {
                return "origin = " + newOrigin;
            }
            String newChal = edited.has("challenge") && edited.get("challenge").isJsonPrimitive()
                    ? edited.get("challenge").getAsString() : null;
            if (newChal != null && (orig == null || !newChal.equals(orig.challenge()))) {
                return "challenge edited";
            }
        } catch (RuntimeException ignored) {
            // fall through to the generic label
        }
        return "clientDataJSON edited";
    }

    /** Strip (flip) the signature - a no-re-sign probe. Standalone: clears any pending re-sign edits. */
    private void onStripSignature(SigStripAttack.Mode mode) {
        if (model == null || model.type() != CeremonyType.GET || model.signature() == null
                || !spans.containsKey(F_SIGNATURE)) {
            showError("No assertion signature to invalidate.");
            return;
        }
        resetEditState();
        CeremonyModel m = new CeremonyModel(CeremonyType.GET);
        m.setSignature(model.signature());
        m.setSignatureWrap(model.signatureWrap());
        new SigStripAttack(mode).apply(m);
        lastStripMode = mode;
        rewrapInto(F_SIGNATURE, m.signature(), model.signatureWrap());
        // Mark the emission as a strip so a Burp self-echo re-bind does NOT mark this deliberately-invalid,
        // un-re-signed signature as "re-signed (<alg>)" (resetEditState above cleared the flag; set it now).
        lastEmissionWasStrip = true;
        renderJson();    // show the flipped signature highlighted in the JSON
        clearStatus();   // → the short per-mode "signature invalidated" notice (lastEmissionWasStrip path)
    }

    private void onClearEdits() {
        resetEditState();
        substituteBadge.setVisible(false); // CREATE: drop the "key planted" badge too
        clearStatus();
        renderJson(); // overrides cleared → repaint the pristine decode (no diff colouring); re-syncs ticks
    }

    private void resetEditState() {
        overrides.clear();
        editFlags = null;
        editSignCount = null;
        editClientData = null;
        editRpIdHash = null;
        editRpIdLabel = null;
        regPlantSigner = null;
        regPlantAlgLabel = null;
        regCredId = null;
        regFlags = null;
        lastEmittedBody = null;
        lastEmissionWasStrip = false;
    }

    // ---- key resolution ------------------------------------------------------------------------

    /**
     * The signer for the current assertion: exact (rpId,credId) lookup, falling back to the most recent.
     * Reconstructs the signer of whatever algorithm the key was planted with - re-sign follows the held
     * key's algorithm, so a planted EdDSA / RS256 / … credential re-signs correctly with no manual choice.
     */
    private CoseSigner signerForCurrentAssertion() {
        CoseSigner signer = null;
        String credHex = credIdHexFromAssertion();
        if (credHex != null) {
            signer = keyStore.retrieveSigner(new KeyId(rpIdHost(), "", credHex));
        }
        if (signer == null) {
            signer = keyStore.retrieveMostRecentSigner(); // single-account demo fallback
        }
        return signer;
    }

    /**
     * Pre-select the matched profile's default signing algorithm in the chooser (the bridge) -
     * but ONLY when the operator has not manually overridden the algorithm for this binding ({@link
     * #userPickedAlg}), so a deliberate pick is never silently stomped. The listener is suppressed during the
     * programmatic set so the pre-select is not itself mistaken for a manual pick (mirrors the {@code
     * encodingDirty} discipline in the Profile Editor).
     */
    private void applyProfileDefaultAlg(TargetProfile profile) {
        if (userPickedAlg) {
            return; // operator chose an algorithm for this binding - honour it
        }
        try {
            suppressAlgListener = true;
            algCombo.setSelectedItem(SignerAlgorithm.forCoseId(profile.signer().coseAlg()));
        } catch (RuntimeException e) {
            // Unsupported persisted alg id - leave the chooser at its current selection (defaults ES256).
        } finally {
            suppressAlgListener = false;
        }
    }

    /** The short label of a signer's algorithm (e.g. {@code "EdDSA"}), for the status summary. */
    private static String labelFor(CoseSigner signer) {
        try {
            return SignerAlgorithm.forCoseId(signer.coseAlg()).label();
        } catch (RuntimeException e) {
            return "alg" + signer.coseAlg();
        }
    }

    /**
     * Hex of the credentialId used to key the stored signer. Resolves the active profile's
     * {@code CREDENTIAL_ID} locator first (migrated from the old whole-body substring scan, which could
     * mis-key on a body carrying several id-ish members), decoding the located value via its encoding;
     * falls back to the substring scan (first {@code rawId}/{@code id}) for the Default / unprofiled hosts.
     */
    private String credIdHexFromAssertion() {
        if (activeSpec != null) {
            FieldLocator loc = activeSpec.locator(Field.CREDENTIAL_ID);
            if (loc != null) {
                int[] span = loc.locate(originalBody);
                if (span != null) {
                    try {
                        byte[] inner = Encodings.decode(wrapperCodec,
                                Arrays.copyOfRange(originalBody, span[0], span[1]), loc.encoding()).inner();
                        return HexFormat.of().formatHex(inner);
                    } catch (RuntimeException ignored) {
                        // fall back to the substring scan below
                    }
                }
            }
        }
        int[] span = JsonValueEditor.findStringValueSpan(originalBody, "rawId");
        if (span == null) {
            span = JsonValueEditor.findStringValueSpan(originalBody, "id");
        }
        if (span == null) {
            return null;
        }
        String token = new String(originalBody, span[0], span[1] - span[0], StandardCharsets.US_ASCII);
        for (Base64.Decoder dec : new Base64.Decoder[]{Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                return HexFormat.of().formatHex(dec.decode(token));
            } catch (RuntimeException ignored) {
                // try the next flavor
            }
        }
        return null;
    }

    /** Best-effort RP-ID host derived from the parsed clientDataJSON origin (consistent across messages). */
    private String rpIdHost() {
        String origin = model != null && model.clientData() != null ? model.clientData().origin() : null;
        if (origin == null) {
            return "";
        }
        try {
            URI u = new URI(origin);
            return u.getHost() != null ? u.getHost() : origin;
        } catch (Exception e) {
            return origin;
        }
    }

    // ---- decode orchestration ------------------------------------------------------------------

    private void decodeBestEffort() {
        clearStatus();
        String bodyStr = new String(originalBody, StandardCharsets.UTF_8);

        CeremonyType type = detector.detect(bodyStr);
        if (type == null) {
            applyPhaseVisibility(null);
            setJsonPlain("No WebAuthn ceremony detected in this request body.");
            return;
        }

        // Profile-driven extraction: match the request host to a TargetProfile (else the Default, whose
        // candidate paths reproduce the SimpleWebAuthn shape), then locate each field at its declared path
        // and record its splice span. This is what lets the editor adapt to ANY RP's nesting instead of
        // assuming a flat response.<field> shape - RPs are data (profiles), not code.
        // Match an ENABLED profile by host. If its phase pins a verify URL that this request's URL/method
        // does not satisfy, fall back to the Default - this request is a different endpoint than the profile
        // targets. Detection stays structural (the body already decided CREATE/GET); the URL only SCOPES
        // which profile drives extraction.
        TargetProfile profile = registry.match(requestHost());
        Phase phase = type == CeremonyType.CREATE ? Phase.REG_VERIFY : Phase.AUTH_VERIFY;
        PhaseSpec spec = profile.phase(phase);
        // An UNKNOWN url (Burp can't resolve one for this message - see urlOf) is not a mismatch: downgrading
        // to the Default there would decode a profiled RP's nesting with the generic candidates. Same rule as
        // ProfileRegistry.urlScopeAllows, so the visibility gate and this extraction gate can't desync.
        String url = requestUrl();
        if (profile != registry.defaultProfile() && spec != null && spec.url() != null
                && spec.url().isActive() && url != null && !spec.url().matches(url, requestMethod())) {
            profile = registry.defaultProfile();
            spec = null;
        }
        if (spec == null) {
            // The matched profile doesn't define this phase (or was URL-downgraded) - extraction uses the
            // Default's spec, so report the Default as the active profile (keep label + spec consistent).
            profile = registry.defaultProfile();
            spec = profile.phase(phase);
        }
        this.activeSpec = spec;
        applyProfileDefaultAlg(profile);

        CeremonyModel m = new CeremonyModel(type);
        List<String> degraded = new ArrayList<>();

        try {
            byte[] clientDataWire = locateField(spec, Field.CLIENT_DATA_JSON, F_CLIENT_DATA);
            if (clientDataWire != null) {
                WrapperCodec.Unwrapped uw = unwrapField(spec, Field.CLIENT_DATA_JSON, clientDataWire);
                ClientData cd = new ClientData(uw.inner());
                parseClientDataForDisplay(cd);
                m.setClientData(cd);
                m.setClientDataWrap(uw.spec());
            }
        } catch (RuntimeException e) {
            degraded.add(F_CLIENT_DATA);
            logField(F_CLIENT_DATA, e);
        }

        if (type == CeremonyType.CREATE) {
            try {
                byte[] attWire = locateField(spec, Field.ATTESTATION_OBJECT, F_ATTESTATION);
                if (attWire != null) {
                    WrapperCodec.Unwrapped uw = unwrapField(spec, Field.ATTESTATION_OBJECT, attWire);
                    AttestationObject att = cborCodec.decodeAttestationObject(uw.inner());
                    m.setAttestationObject(att);
                    m.setAttestationObjectWrap(uw.spec());
                    if (att.authData() != null) {
                        m.setAuthenticatorData(att.authData());
                    } else {
                        degraded.add(F_ATTESTATION);
                    }
                }
            } catch (RuntimeException e) {
                degraded.add(F_ATTESTATION);
                logField(F_ATTESTATION, e);
            }
        } else { // GET
            try {
                byte[] adWire = locateField(spec, Field.AUTHENTICATOR_DATA, F_AUTH_DATA);
                if (adWire != null) {
                    WrapperCodec.Unwrapped uw = unwrapField(spec, Field.AUTHENTICATOR_DATA, adWire);
                    AuthenticatorData ad = cborCodec.decodeAuthData(uw.inner());
                    m.setAuthenticatorData(ad);
                    m.setAuthenticatorDataWrap(uw.spec());
                    if (ad.rpIdHash() == null) {
                        degraded.add(F_AUTH_DATA);
                    }
                }
            } catch (RuntimeException e) {
                degraded.add(F_AUTH_DATA);
                logField(F_AUTH_DATA, e);
            }
            try {
                byte[] sigWire = locateField(spec, Field.SIGNATURE, F_SIGNATURE);
                if (sigWire != null) {
                    WrapperCodec.Unwrapped uw = unwrapField(spec, Field.SIGNATURE, sigWire);
                    m.setSignature(uw.inner());
                    m.setSignatureWrap(uw.spec());
                }
            } catch (RuntimeException e) {
                degraded.add(F_SIGNATURE);
                logField(F_SIGNATURE, e);
            }
        }

        this.model = m;
        // GET (assertion) is editable + re-signable: show the flag ticks + the bottom button row. CREATE
        // (registration) is a read-only coloured display whose move is the plant button + the algorithm
        // chooser (a registration has no assertion signature to re-sign).
        applyPhaseVisibility(type);
        jsonPane.setEditable(editable());
        renderJson();

        if (!degraded.isEmpty()) {
            showError("could not fully decode " + String.join(", ", degraded) + ": showing partial/raw");
        }
    }

    /**
     * Locate {@code field}'s value via the active profile's {@link PhaseSpec}, record its splice span under
     * {@code spanKey} (the wire JSON member name shared by {@link #spans}/{@link #overrides}), and return
     * the field's wire bytes - or {@code null} if the profile does not resolve it on this body. This single
     * call replaces the old "Gson member lookup for the value + first-substring scan for the span" pair,
     * which both assumed one {@code response} layer; the span and the bytes now come from the same
     * profile-declared path, so a deeply-nested / array-wrapped / envelope-keyed field is found correctly.
     */
    private byte[] locateField(PhaseSpec spec, Field field, String spanKey) {
        if (spec == null) {
            return null;
        }
        int[] span = spec.locate(field, originalBody);
        if (span == null) {
            return null;
        }
        spans.put(spanKey, span);
        return Arrays.copyOfRange(originalBody, span[0], span[1]);
    }

    /**
     * Unwrap a located field's wire bytes using the active profile field's encoding - AUTO (self-detect) by
     * default, or the operator's pinned {@link com.anvil.passkeyeditor.profile.EncodingSpec}. Returning the
     * effective {@link WrapSpec} keeps the re-sign re-wrap byte-exact for either. This is what makes a
     * profile validated GREEN in the Check panel extract identically here on live traffic.
     */
    private WrapperCodec.Unwrapped unwrapField(PhaseSpec spec, Field field, byte[] wire) {
        FieldLocator loc = spec != null ? spec.locator(field) : null;
        return Encodings.decode(wrapperCodec, wire, loc != null ? loc.encoding() : null);
    }

    /**
     * Read-only parallel decode of an arbitrary body - the pristine original OR the rebuilt outgoing body -
     * into a fresh {@link CeremonyModel} via the active profile's path locators, for the side-by-side delta
     * ONLY. Unlike {@link #decodeBestEffort()} it touches NO editor state ({@code spans} / {@code overrides})
     * and swallows per-field decode failures (the field is left unset), so
     * rendering the delta can never disturb the live edit/forge path or throw on the EDT. Path locators are
     * offset-independent, so this decodes the spliced outgoing body correctly even though its field offsets
     * have shifted from the original's.
     */
    private CeremonyModel decodeModelFrom(byte[] body, PhaseSpec spec, CeremonyType type) {
        CeremonyModel m = new CeremonyModel(type);
        if (body == null || spec == null) {
            return m;
        }
        try {
            int[] span = spec.locate(Field.CLIENT_DATA_JSON, body);
            if (span != null) {
                ClientData cd = new ClientData(unwrapField(spec, Field.CLIENT_DATA_JSON,
                        Arrays.copyOfRange(body, span[0], span[1])).inner());
                parseClientDataForDisplay(cd);
                m.setClientData(cd);
            }
        } catch (RuntimeException ignored) {
            // display-only: leave clientData unset
        }
        if (type == CeremonyType.CREATE) {
            try {
                int[] span = spec.locate(Field.ATTESTATION_OBJECT, body);
                if (span != null) {
                    AttestationObject att = cborCodec.decodeAttestationObject(unwrapField(spec,
                            Field.ATTESTATION_OBJECT, Arrays.copyOfRange(body, span[0], span[1])).inner());
                    m.setAttestationObject(att);
                    if (att.authData() != null) {
                        m.setAuthenticatorData(att.authData());
                    }
                }
            } catch (RuntimeException ignored) {
                // leave attestation unset
            }
        } else {
            try {
                int[] span = spec.locate(Field.AUTHENTICATOR_DATA, body);
                if (span != null) {
                    m.setAuthenticatorData(cborCodec.decodeAuthData(unwrapField(spec,
                            Field.AUTHENTICATOR_DATA, Arrays.copyOfRange(body, span[0], span[1])).inner()));
                }
            } catch (RuntimeException ignored) {
                // leave authenticatorData unset
            }
            try {
                int[] span = spec.locate(Field.SIGNATURE, body);
                if (span != null) {
                    m.setSignature(unwrapField(spec, Field.SIGNATURE,
                            Arrays.copyOfRange(body, span[0], span[1])).inner());
                }
            } catch (RuntimeException ignored) {
                // leave signature unset
            }
        }
        return m;
    }

    private String requestHost() {
        return hostOf(requestResponse != null ? requestResponse.request() : null);
    }

    private String requestUrl() {
        return urlOf(requestResponse != null ? requestResponse.request() : null);
    }

    private String requestMethod() {
        return methodOf(requestResponse != null ? requestResponse.request() : null);
    }

    /** The host of {@code req}, or {@code ""} (→ Default profile) if unavailable. */
    private static String hostOf(HttpRequest req) {
        try {
            if (req != null && req.httpService() != null && req.httpService().host() != null) {
                return req.httpService().host();
            }
        } catch (RuntimeException e) {
            // fall through to the Default profile
        }
        return "";
    }

    /**
     * The full URL of {@code req} (for a profile's per-phase URL scope), or {@code null} if unavailable.
     *
     * {@code null} is a routine outcome, not an edge case: {@code HttpRequest.url()} throws
     * {@code MalformedRequestException} for any message Burp cannot derive a URL for (no {@code HttpService} -
     * e.g. a message the editor pane re-binds from raw bytes). Callers must read it as "URL unknown", never as
     * "URL doesn't match" - see {@link com.anvil.passkeyeditor.profile.ProfileRegistry#urlScopeAllows}.
     */
    private static String urlOf(HttpRequest req) {
        try {
            return req != null ? req.url() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The HTTP method of {@code req} (for a URL scope's optional method gate), or {@code null} if unavailable. */
    private static String methodOf(HttpRequest req) {
        try {
            return req != null ? req.method() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void parseClientDataForDisplay(ClientData cd) {
        if (cd.raw() == null) {
            return;
        }
        try {
            JsonElement el = JsonParser.parseString(new String(cd.raw(), StandardCharsets.UTF_8));
            if (!el.isJsonObject()) {
                return;
            }
            JsonObject o = el.getAsJsonObject();
            if (o.has("type") && o.get("type").isJsonPrimitive()) {
                cd.setType(o.get("type").getAsString());
            }
            if (o.has("challenge") && o.get("challenge").isJsonPrimitive()) {
                cd.setChallenge(o.get("challenge").getAsString());
            }
            if (o.has("origin") && o.get("origin").isJsonPrimitive()) {
                cd.setOrigin(o.get("origin").getAsString());
            }
            if (o.has("crossOrigin") && o.get("crossOrigin").isJsonPrimitive()) {
                cd.setCrossOrigin(o.get("crossOrigin").getAsBoolean());
            }
            if (o.has("topOrigin") && o.get("topOrigin").isJsonPrimitive()) {
                cd.setTopOrigin(o.get("topOrigin").getAsString());
            }
        } catch (RuntimeException ignored) {
            // Display-only: a parse miss leaves fields null; raw stays authoritative.
        }
    }


    // ---- flag ticks (GET) ----------------------------------------------------------------------

    /**
     * A flag tick was toggled: recompute the UP/UV/BE/BS bits (preserving the original AT/ED bits) and
     * re-sign the assertion immediately. If the forge is refused (e.g. no stored key yet) the ticks snap
     * back to the live flags so the controls never claim a change the wire does not carry.
     */
    private void onFlagTick() {
        if (suppressFlagListeners || model == null || model.authenticatorData() == null) {
            return;
        }
        int orig = model.authenticatorData().flags();
        int bits = (upBox.isSelected() ? AuthenticatorData.FLAG_UP : 0)
                | (uvBox.isSelected() ? AuthenticatorData.FLAG_UV : 0)
                | (beBox.isSelected() ? AuthenticatorData.FLAG_BE : 0)
                | (bsBox.isSelected() ? AuthenticatorData.FLAG_BS : 0);
        // Preserve the captured AT/ED bits (only UP/UV/BE/BS are ticks) - for a registration AT MUST stay set.
        int newFlags = (orig & ~(AuthenticatorData.FLAG_UP | AuthenticatorData.FLAG_UV
                | AuthenticatorData.FLAG_BE | AuthenticatorData.FLAG_BS)) | bits;
        if (model.type() == CeremonyType.GET) {
            // Assertion: flipping a flag re-signs immediately over the new authData (existing path).
            if (!forgeWith(newFlags, null, null, null)) {
                syncFlagTicks(); // refused - revert the ticks to the (unchanged) live flags
            }
        } else if (model.type() == CeremonyType.CREATE) {
            // Registration: flipping a flag re-encodes the attestationObject (no signature to re-sign at
            // fmt=none). Toggling every bit back to the captured value clears the flag edit (idempotent).
            regFlags = (newFlags == orig) ? null : newFlags;
            if (!applyRegistrationEdits()) {
                regFlags = null;
                syncFlagTicks(); // refused - revert the ticks
            }
        }
    }

    /** Mirror the flag ticks onto the current effective flags (edited if armed, else the captured ones) -
     * GET uses {@link #editFlags}, CREATE uses {@link #regFlags}. */
    private void syncFlagTicks() {
        if (model == null || model.authenticatorData() == null) {
            return;
        }
        int captured = model.authenticatorData().flags();
        int eff;
        if (model.type() == CeremonyType.GET) {
            eff = editFlags != null ? editFlags : captured;
        } else if (model.type() == CeremonyType.CREATE) {
            eff = regFlags != null ? regFlags : captured;
        } else {
            return;
        }
        suppressFlagListeners = true;
        try {
            upBox.setSelected((eff & AuthenticatorData.FLAG_UP) != 0);
            uvBox.setSelected((eff & AuthenticatorData.FLAG_UV) != 0);
            beBox.setSelected((eff & AuthenticatorData.FLAG_BE) != 0);
            bsBox.setSelected((eff & AuthenticatorData.FLAG_BS) != 0);
        } finally {
            suppressFlagListeners = false;
        }
    }

    /**
     * Editable contexts only: Attacks row + alg chooser (CREATE), flag ticks + bottom buttons (BOTH phases,
     * ). The bottom row shows Register (CREATE) / Re-sign + Apply (GET) + Clear (both). In a read-only
     * (Proxy-history) view every action control is hidden - the tab is a pure decoded view with the
     * persistent amber diff ({@code null} type ⇒ hide all).
     */
    private void applyPhaseVisibility(CeremonyType type) {
        boolean act = !readOnly && type != null; // action controls live only in an editable context with a ceremony
        boolean create = type == CeremonyType.CREATE;
        boolean getEdit = act && type == CeremonyType.GET;
        boolean createEdit = act && create && createEditable(); // registration must actually be re-encodable
        // The attacksRow carries BOTH the Attacks button and the Wrap toggle. Keep the row visible always so
        // the Wrap checkbox is available even in a read-only Proxy-history view; gate only the Attacks button
        // (its menu items are all edit actions, useless read-only). This mirrors the response tab, where Wrap
        // is always shown.
        attacksButton.setVisible(act);
        algRow.setVisible(act && create);
        flagsRow.setVisible(getEdit || createEdit);
        buttonRow.setVisible(getEdit || createEdit);
        registerButton.setVisible(createEdit);
        resignButton.setVisible(getEdit);
        applyButton.setVisible(getEdit);
        clearButton.setVisible(getEdit || createEdit);
        if (readOnly || !create) {
            substituteBadge.setVisible(false);
        }
    }

    /** "Clear edits" is enabled only when something is armed. */
    private void updateButtons() {
        clearButton.setEnabled(!overrides.isEmpty());
    }

    /** The JSON is editable only in an editable context (not read-only) and only on an assertion (GET). */
    private boolean editable() {
        return !readOnly && model != null && model.type() == CeremonyType.GET;
    }

    /**
     * True on a CREATE message whose attestationObject + authData decoded and whose attestationObject splice
     * span was recorded - i.e. the registration can actually be re-encoded + spliced back. Guards
     * the Register button, the credentialId-swap item, and the registration flag ticks.
     */
    private boolean createEditable() {
        return model != null && model.type() == CeremonyType.CREATE
                && model.attestationObject() != null && model.attestationObject().authData() != null
                && spans.containsKey(F_ATTESTATION);
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // ---- status area ---------------------------------------------------------------------------

    // Status tones come from Palette so they hold up on both Burp themes.

    /** Show a red error line in the status area below the JSON (takes precedence over the re-sign summary). */
    private void showError(String text) {
        statusError = text;
        renderStatus();
    }

    /** Drop the error; the re-sign summary (if anything is armed) or nothing is shown instead. */
    private void clearStatus() {
        statusError = null;
        renderStatus();
    }

    /**
     * Repaint the status area below the JSON. Precedence: a red error if one is set; else, on an editable
     * assertion, the strip notice / the cumulative "re-signed (alg)" summary (each armed edit on its own
     * line) + an optional caveat; else hidden. A read-only (Proxy-history) view shows nothing here - just
     * the JSON + amber diff. Registration surfaces only errors (its plant confirmation sits by the chooser).
     */
    private void renderStatus() {
        Color color;
        String text;
        if (statusError != null) {
            color = Palette.error();
            text = statusError;
        } else if (readOnly || model == null) {
            statusArea.setVisible(false);
            return;
        } else if (model.type() == CeremonyType.CREATE) {
            // CREATE summary: each armed registration edit on its own line, plus the conformance
            // framing - registration tampering probes the RP's validation policy, it is not a 2nd ATO primitive.
            List<String> lines = regEditLines();
            if (lines.isEmpty()) {
                statusArea.setVisible(false);
                return;
            }
            color = Palette.ok();
            // A packed self-attestation plant emits fmt="packed" with a real signature; a fmt="none" plant or
            // a field-only edit emits fmt="none". Reflect what is actually on the wire (must match the emitted
            // bytes + the "key planted" badge), not a fixed string.
            boolean packedSelf = regPlantSigner != null
                    && selectedAttestation() == PlantAttestation.PACKED_SELF;
            StringBuilder sb = new StringBuilder(packedSelf
                    ? "registration re-encoded (fmt=packed, self-attestation)"
                    : "registration re-encoded (fmt=none)");
            for (String line : lines) {
                sb.append("\n    • ").append(line);
            }
            // Deliberately no trailing explainer. The status area reports what was done to the request; what
            // the result means for a given RP is the tester's read, and belongs in the Guide, not on screen
            // after every plant.
            text = sb.toString();
        } else if (model.type() != CeremonyType.GET) {
            statusArea.setVisible(false);
            return;
        } else if (lastEmissionWasStrip) {
            color = Palette.warn();
            text = "signature invalidated: " + stripModeLabel(lastStripMode);
        } else if (overrides.isEmpty()) {
            statusArea.setVisible(false);
            return;
        } else {
            color = Palette.ok();
            StringBuilder sb = new StringBuilder("re-signed (").append(lastSignerLabel).append(")");
            for (String line : armedEditLines()) {
                sb.append("\n    • ").append(line);
            }
            text = sb.toString();
        }
        statusArea.setForeground(color);
        statusArea.setText(text);
        statusArea.setVisible(true);
    }

    /** Human label for a {@link SigStripAttack.Mode}, so the status says what was actually done. */
    private static String stripModeLabel(SigStripAttack.Mode mode) {
        return switch (mode) {
            case FLIP -> "trailing byte flipped";
            case EMPTY -> "emptied";
            case ZEROED -> "zeroed";
            case GARBAGE -> "random bytes";
        };
    }

    private void logField(String field, RuntimeException e) {
        api.logging().logToError("Passkey Editor: failed to decode " + field, e);
    }

    private Frame suiteFrame() {
        try {
            return api.userInterface().swingUtils().suiteFrame();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
