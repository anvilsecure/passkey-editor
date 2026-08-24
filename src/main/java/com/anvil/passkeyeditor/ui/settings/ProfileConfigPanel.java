package com.anvil.passkeyeditor.ui.settings;

import com.anvil.passkeyeditor.codec.WrapSpec.Padding;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.profile.EncodingSpec;
import com.anvil.passkeyeditor.profile.EncodingSpec.Base64Kind;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.PlantAttestation;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.profile.ProfileValidator.CheckResult;
import com.anvil.passkeyeditor.profile.ProfileValidator.Status;
import com.anvil.passkeyeditor.profile.SignerSpec;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.profile.UrlMatch;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.ui.PlantAttestationRenderer;
import com.anvil.passkeyeditor.ui.SignerAlgorithmRenderer;
import com.anvil.passkeyeditor.ui.Fonts;
import com.anvil.passkeyeditor.ui.ThemedPanel;
import com.anvil.passkeyeditor.ui.editor.CeremonyJson;
import com.anvil.passkeyeditor.util.DecodedDetail;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.Scrollable;
import javax.swing.UIManager;

/**
 * The right-hand config for one selected {@link TargetProfile} - the editable,
 * selection-driven editor. Per phase it exposes the verify-URL scope and
 * a row per WebAuthn field: a PATH/REGEX locator, a per-field encoding (Auto / Raw / Base64 /
 * Base64URL + a URL-encoded tick), and a live per-field Check result.
 * Paste a registration + authentication body, hit Check, and each field shows exactly what the
 * extension would extract + decode; Save writes the rebuilt profile back.
 *
 * Pure Swing over the Burp-free {@link ProfileValidator}; all mutation on the EDT.
 */
public final class ProfileConfigPanel {

    private static final Field[] REG_FIELDS =
            {Field.CLIENT_DATA_JSON, Field.ATTESTATION_OBJECT, Field.AUTHENTICATOR_DATA, Field.CREDENTIAL_ID};
    private static final Field[] AUTH_FIELDS =
            {Field.CLIENT_DATA_JSON, Field.AUTHENTICATOR_DATA, Field.SIGNATURE, Field.USER_HANDLE, Field.CREDENTIAL_ID};

    // The two AUTO warnings are the highest-stakes strings in the panel and were the least readable: a
    // tooltip cannot wrap (see UiStyle.tip), so at 324 and 515 characters they rendered 1923px and 3110px
    // wide - off the side of the screen, with the blast-radius sentence among the parts you could not read.
    // What survives here is only what has to be read BEFORE ticking the box: it changes live traffic, and it
    // does so on every host the profile matches whatever Burp's scope says. The mechanism - key precedence,
    // the most-recent fallback, session-only key storage, which tools it applies in - is unchanged and lives
    // in the Guide tab's "AUTO mode" section, which is a real HTML pane and can afford it.
    private static final String AUTO_PLANT_TIP = "Plants our key into LIVE registrations on every host this "
            + "profile matches, in or out of Burp scope. See the Guide tab.";
    private static final String AUTO_RESIGN_TIP = "Re-signs LIVE authentications on every host this profile "
            + "matches, in or out of Burp scope. See the Guide tab.";
    private static final String DEFAULT_AUTO_TIP = "The Default matches every host, so it "
            + "can't be AUTO-armed. Create a host-specific profile to arm AUTO.";
    /** The host row's counterpart of {@code URL_TIP}, and under the same one-line budget. */
    private static final String HOST_TIP =
            "Matched against the host of the ceremony request, often not the site you are browsing.";

    /** Pretty-printer for the Prettify button - HTML-escaping off so '=', '<', '&' in bodies stay literal. */
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final ProfileValidator validator;
    private final Consumer<TargetProfile> onSave;

    private final ThemedPanel root;
    private final JLabel title = new JLabel("Select or add a profile");
    /** Sample-body box outlines, re-coloured when the theme changes. */
    private final java.util.List<JPanel> boxOutlines = new java.util.ArrayList<>();

    private final JTextField idField = new JTextField(18);
    private final JTextField nameField = new JTextField(22);
    private final JLabel hostLabel = new JLabel("host match:");
    private final JComboBox<HostMatch.Kind> hostKind = new JComboBox<>(HostMatch.Kind.values());
    private final HintField hostPattern = new HintField(20);
    // enabledBox / autoPlantBox / autoResignBox / saveButton are package-private (not private) so the
    // same-package ProfileConfigPanelBug1Test can drive doClick() / setSelected() and assert the captured
    // Save profile - pinning the un-tick-clears-AUTO + authoritative-buildProfile contract headlessly.
    final JCheckBox enabledBox = new JCheckBox("Enabled");
    /** The profile's default signing algorithm - what the manual chooser pre-selects + AUTO uses. */
    private final JComboBox<SignerAlgorithm> algCombo = new JComboBox<>(SignerAlgorithm.values());
    /** The attestation format AUTO plants under - None (fmt="none") or packed self-attestation. */
    final JComboBox<PlantAttestation> attestationCombo = new JComboBox<>(PlantAttestation.values());
    // Per-profile AUTO switches - independent of Enabled (which is the manual tab). Default off.
    final JCheckBox autoPlantBox = new JCheckBox("Auto-plant");
    final JCheckBox autoResignBox = new JCheckBox("Auto re-sign");

    private final PhaseEditor regEditor = new PhaseEditor(Phase.REG_VERIFY, REG_FIELDS);
    private final PhaseEditor authEditor = new PhaseEditor(Phase.AUTH_VERIFY, AUTH_FIELDS);

    // regBody / authBody / checkButton / status are package-private (like saveButton + the AUTO boxes) so the
    // same-package ProfileConfigPanelCheckTest can drive Check headlessly and assert the verdict message.
    final JTextArea regBody = bodyArea();
    final JTextArea authBody = bodyArea();
    final JButton checkButton = new JButton("Check");
    private final JButton prettifyButton = new JButton("Prettify JSON");
    /** Base text for the Save button; {@link #applySaveEmphasis} appends the unsaved marker to it. */
    private static final String SAVE_LABEL = "Save profile";
    final JButton saveButton = new JButton(SAVE_LABEL);
    final JLabel status = new JLabel(" ");
    /** Red warning shown only while an AUTO flag is armed - toggled by {@link #updateAutoCaption()}. */
    private final JLabel autoCaption = new JLabel("AUTO rewrites live traffic");

    /** True when no profile is loaded - guards Check/Save. */
    private boolean empty = true;
    /** True when the loaded profile is the catch-all Default - its AUTO checkboxes are disabled (see setProfile). */
    private boolean isDefaultProfile;
    /** True while {@link #setProfile} is populating the controls - suppresses live re-check on programmatic edits. */
    private boolean loading;
    /**
     * True when the operator has changed a control since the profile was loaded or last saved. Save is the
     * validation gate (blank patterns are rejected there, and the profile drives both detection and live-traffic
     * rewriting), so nothing is written per keystroke - this flag is what lets the list warn before a selection
     * change overwrites the panel.
     */
    private boolean dirty;
    /** Fired whenever {@link #dirty} flips, so the profile list can repaint its unsaved marker. */
    private Runnable onDirtyChanged = () -> { };
    /** Debounce for live re-check: a locator/encoding edit restarts it; on fire it re-runs {@link #onCheck()}. */
    private final javax.swing.Timer liveTimer;

    public ProfileConfigPanel(ProfileValidator validator, Consumer<TargetProfile> onSave) {
        this.validator = validator;
        this.onSave = onSave;

        // Live re-check: 350 ms after the operator stops editing a path/regex/encoding, re-run Check so the
        // per-field verdicts + the summary update without pressing the button. Single-shot (restarts on each
        // edit); the manual Check button still works. EDT-only (Swing Timer fires on the EDT).
        this.liveTimer = new javax.swing.Timer(350, e -> onCheck());
        this.liveTimer.setRepeats(false);
        regEditor.setLiveRecheck(this::scheduleLiveRecheck);
        authEditor.setLiveRecheck(this::scheduleLiveRecheck);
        // Pasting/editing a sample body re-checks too (the locators run against it), so the verdicts appear
        // the moment a body is pasted and update as either the body or a locator changes.
        onDocumentChange(regBody.getDocument(), this::scheduleLiveRecheck);
        onDocumentChange(authBody.getDocument(), this::scheduleLiveRecheck);

        // Unsaved-edit tracking. The locator rows and the sample bodies already route through
        // scheduleLiveRecheck, which marks dirty on the way past; everything else in the panel is wired here
        // so no editable control can change the profile silently. Each hook is suppressed while setProfile is
        // populating (markDirty honours the same `loading` flag the live re-check does), which matters because
        // a JComboBox DOES fire an ActionEvent on setSelectedItem - unlike a JCheckBox's setSelected.
        onDocumentChange(idField.getDocument(), this::markDirty);
        onDocumentChange(nameField.getDocument(), this::markDirty);
        onDocumentChange(hostPattern.getDocument(), this::markDirty);
        hostLabel.setToolTipText(HOST_TIP);
        hostPattern.setToolTipText(HOST_TIP);
        hostKind.addActionListener(e -> {
            applyHostKind();
            markDirty();
        });
        algCombo.addActionListener(e -> markDirty());
        attestationCombo.addActionListener(e -> markDirty());
        regEditor.setOnDirty(this::markDirty);
        authEditor.setOnDirty(this::markDirty);

        title.setFont(Fonts.ui().deriveFont(Font.BOLD, Fonts.ui().getSize() + 2f)); // colour comes from onTheme

        checkButton.addActionListener(e -> onCheck());
        prettifyButton.addActionListener(e -> onPrettify());
        saveButton.addActionListener(e -> onSaveClicked());
        algCombo.setRenderer(new SignerAlgorithmRenderer());
        algCombo.setToolTipText("Default signing algorithm for this target. The ceremony editor's chooser "
                + "pre-selects it, and AUTO mode plants / re-signs under it.");
        attestationCombo.setRenderer(new PlantAttestationRenderer());
        attestationCombo.setToolTipText("Attestation format AUTO plants under: 'None' (fmt=none) for RPs that "
                + "accept it, or 'Packed self-attestation' for RPs that REQUIRE attestation but don't pin roots.");
        autoPlantBox.setToolTipText(AUTO_PLANT_TIP);
        autoResignBox.setToolTipText(AUTO_RESIGN_TIP);
        // Enabled is the master switch (a disabled profile is fully inert - no tab, no colour, no auto):
        //  • arming an AUTO action auto-ticks Enabled;
        //  • un-ticking Enabled clears BOTH AUTO flags, so one click deactivates a fully-armed profile (no
        //    need to untick the AUTO boxes first).
        // setSelected(...) fires no ActionEvent (only doClick/user clicks do), so neither listener re-enters.
        java.awt.event.ActionListener armTicksEnabled = e -> {
            if (autoPlantBox.isSelected() || autoResignBox.isSelected()) {
                enabledBox.setSelected(true);
            }
            updateAutoCaption();
            markDirty();
        };
        autoPlantBox.addActionListener(armTicksEnabled);
        autoResignBox.addActionListener(armTicksEnabled);
        enabledBox.addActionListener(e -> {
            if (!enabledBox.isSelected()) {
                autoPlantBox.setSelected(false);
                autoResignBox.setSelected(false);
            }
            updateAutoCaption();
            markDirty();
        });
        // autoCaption's colour is registered with the root once it exists, at the end of the constructor.

        // Box 1 ("this section"): the orange-underlined title + identity rows. No enclosing rectangle - the
        // orange underline is its only separator - just padding so it lines up with the boxed sections below.
        // Row 1 after the title carries the three switches + the AUTO warning inline (right of "Auto re-sign");
        // id/name/host/alg follow.
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.add(UiStyle.underline(title));
        header.add(leftRow(enabledBox, autoPlantBox, autoResignBox, Box.createHorizontalStrut(12), autoCaption));
        header.add(leftRow(new JLabel("id:"), idField, new JLabel("  name:"), nameField));
        header.add(leftRow(hostLabel, hostKind, hostPattern));
        header.add(leftRow(new JLabel("default signing alg:"), algCombo,
                new JLabel("  plant attestation:"), attestationCombo));
        header.setBorder(BorderFactory.createEmptyBorder(0, 6, 6, 6));

        // Box 4: the two sample bodies, in one titled panel (the Check/Save row that used to close it is now
        // the footer - see below). RigidHeightPanel so the GridBag glue can't flatten the (scroll-pane-backed)
        // body boxes when the pane is short - it scrolls instead.
        JPanel bodies = new RigidHeightPanel();
        bodies.setLayout(new BoxLayout(bodies, BoxLayout.Y_AXIS));
        bodies.add(labeled("Registration body (paste the reg-verify request body):", regBody));
        bodies.add(Box.createVerticalStrut(4));
        bodies.add(labeled("Authentication body (paste the auth-verify request body):", authBody));
        bodies.setBorder(BorderFactory.createTitledBorder("Sample bodies"));

        // The action row is CHROME, not content. As the last child of the "Sample bodies" box it lived inside
        // the scrolled column, so with the two body boxes at their natural height it sat below the fold at any
        // ordinary pane height - Check / Prettify / Save were unreachable exactly when a long profile made them
        // matter, and an edit that was never saved read as the panel losing it. Parking the row in the root's
        // SOUTH pins it under the viewport, a sibling of the scroll pane rather than a passenger in it. Same
        // buttons, same listeners, same status label - only the parent changed.
        // BorderLayout, not one FlowLayout row holding all four. A FlowLayout wraps when the row is wider than
        // the pane, and SOUTH sizes the footer for ONE row - so a long verdict ("saved. auto re-sign: add a
        // CREDENTIAL_ID locator...") wrapped the status label to a second line the band has no height for and
        // it vanished, which is the same disappearing-feedback failure this footer exists to end. It also fed
        // the label's width into root.getMinimumSize(), and JSplitPane honours the right component's minimum,
        // so the divider's travel shrank every time a long message appeared. Buttons WEST at their natural
        // size, status CENTER: a JLabel in CENTER clips with an ellipsis instead of wrapping, and the explicit
        // zero minimum width keeps the message out of the split's arithmetic entirely.
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonRow.add(checkButton);
        buttonRow.add(prettifyButton);
        buttonRow.add(saveButton);
        status.setMinimumSize(new Dimension(0, status.getPreferredSize().height));
        JPanel actions = new JPanel(new BorderLayout());
        actions.add(buttonRow, BorderLayout.WEST);
        actions.add(status, BorderLayout.CENTER);

        // Exactly four aligned boxes - header / Registration / Authentication / bodies. GridBag with
        // weightx=1 + fill=HORIZONTAL stretches each to the full width (so their left/right edges line up);
        // anchor=NORTH + a trailing glue row keep them packed to the top. WidthTrackingPanel makes the boxes
        // fill the scroll viewport - a plain JPanel would size to its preferred width and leave them ragged.
        WidthTrackingPanel center = new WidthTrackingPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.weightx = 1.0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.NORTH;
        gc.gridy = 0;
        gc.insets = new Insets(0, 8, 0, 8); // first box flush to the top so its header aligns with the left pane's
        center.add(header, gc);
        gc.insets = new Insets(6, 8, 0, 8);  // a small gap above each subsequent box
        gc.gridy = 1;
        center.add(regEditor.component(), gc);
        gc.gridy = 2;
        center.add(authEditor.component(), gc);
        gc.gridy = 3;
        center.add(bodies, gc);
        gc.gridy = 4;
        gc.weighty = 1.0;
        gc.fill = GridBagConstraints.BOTH;
        center.add(Box.createGlue(), gc);

        this.root = new ThemedPanel(new BorderLayout());
        JScrollPane scroll = new JScrollPane(center);
        scroll.setBorder(BorderFactory.createEmptyBorder()); // drop the scrollpane outline so only the split divider shows
        this.root.add(scroll, BorderLayout.CENTER);
        // Added AFTER the scroll pane: the layout test reads root.getComponent(0) as the outer scroll pane, and
        // a BorderLayout keeps its children in insertion order regardless of constraint.
        this.root.add(actions, BorderLayout.SOUTH);
        // Re-colour rather than rebuild: this panel holds what the operator typed. Registering the
        // meaning of each colour lets the panel follow a live theme change without losing that state -
        // including whatever the status line and the per-field verdicts are currently showing.
        this.root.tint(title, Palette::accent);
        this.root.tint(autoCaption, Palette::error);
        this.root.onTheme(() -> {
            regEditor.retint();
            authEditor.retint();
            // ThemedPanel also fires this when Burp's font size changes, so the monospaced boxes follow it
            // instead of staying pinned at their construction-time size while their labels grow around them.
            regBody.setFont(Fonts.mono());
            authBody.setFont(Fonts.mono());
            boxOutlines.forEach(b -> b.setBorder(BorderFactory.createLineBorder(Palette.border())));
            title.setFont(Fonts.ui().deriveFont(Font.BOLD, Fonts.ui().getSize() + 2f));
            // A hairline across the top of the footer, so the pinned row reads as chrome under the scrolled
            // column rather than as a detached continuation of the "Sample bodies" box it used to live in.
            // Palette.border() (not muted, which is a TEXT colour and glows white as a border).
            actions.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Palette.border()));
        });
        setProfile(null);
    }

    public Component component() {
        return root;
    }

    /** Load a profile into the editor (or clear it when {@code null}). */
    public void setProfile(TargetProfile p) {
        setProfile(p, false);
    }

    /**
     * Load a profile, flagging whether it is the catch-all Default. The Default can be edited + enabled/
     * disabled like any profile, but its AUTO checkboxes are disabled: it matches every host
     * so arming it would be a foot-gun - arm a specific profile instead.
     */
    public void setProfile(TargetProfile p, boolean isDefault) {
        // Populate under the loading flag so the programmatic setText/setFrom below don't trigger live re-check
        // (an expr.setText fires the row's document listener). Cleared in finally so a mid-load error can't stick.
        loading = true;
        try {
            empty = p == null;
            isDefaultProfile = isDefault;
            title.setText(p == null ? "Select or add a profile" : "Profile: " + p.name());
            idField.setText(p != null ? p.id() : "");
            nameField.setText(p != null ? p.name() : "");
            hostKind.setSelectedItem(p != null ? p.host().kind() : HostMatch.Kind.EXACT);
            hostPattern.setText(p != null ? p.host().pattern() : "");
            enabledBox.setSelected(p == null || p.enabled());
            algCombo.setSelectedItem(safeAlg(p != null ? p.signer().coseAlg() : SignerSpec.ES256.coseAlg()));
            attestationCombo.setSelectedItem(p != null ? p.plantAttestation() : PlantAttestation.NONE);
            autoPlantBox.setSelected(p != null && p.autoPlant());
            autoResignBox.setSelected(p != null && p.autoResign());
            regEditor.setFrom(p != null ? p.phase(Phase.REG_VERIFY) : null);
            authEditor.setFrom(p != null ? p.phase(Phase.AUTH_VERIFY) : null);
            regBody.setText(p != null && p.sampleRegBody() != null ? p.sampleRegBody() : "");
            authBody.setText(p != null && p.sampleAuthBody() != null ? p.sampleAuthBody() : "");
            regBody.setCaretPosition(0);
            authBody.setCaretPosition(0);
            setControlsEnabled(!empty);
            applyDefaultAutoGuard();
            updateAutoCaption();
            status.setText(" ");
        } finally {
            loading = false;
        }
        // Outside the finally: the panel now mirrors the stored profile exactly, so whatever the previous
        // profile had pending is gone with it. Clearing here (rather than inside the try) also means a
        // mid-load failure leaves the flag conservatively set rather than claiming the panel is clean.
        clearDirty();
    }

    /** Whether the panel holds edits that have not been through Save. */
    public boolean isDirty() {
        return dirty;
    }

    /** Register the callback fired when {@link #isDirty()} flips - the profile list's repaint trigger. */
    void setOnDirtyChanged(Runnable r) {
        this.onDirtyChanged = r != null ? r : () -> { };
    }

    /**
     * Run the Save action exactly as the button does, validation gate included. This is the "Save" answer to
     * the confirm-on-switch dialog; a rejected save leaves {@link #isDirty()} true and the reason in the
     * status line, which is how the caller knows not to proceed with the switch.
     */
    void saveNow() {
        onSaveClicked();
    }

    /** Record an operator edit and surface it (bold Save + the list's marker). No-op while loading/empty. */
    private void markDirty() {
        if (loading || empty || dirty) {
            return;
        }
        dirty = true;
        applySaveEmphasis();
        onDirtyChanged.run();
    }

    private void clearDirty() {
        boolean was = dirty;
        dirty = false;
        applySaveEmphasis(); // unconditional: this is also what installs the plain font at construction
        if (was) {
            onDirtyChanged.run();
        }
    }

    /**
     * Mark "Save profile" while there are unsaved edits, using the same glyph the list row uses so the two
     * cues read as one thing. The marker is in the LABEL rather than in the font because bolding is not a cue
     * that survives this host: Burp's own look and feel declares {@code Button.font=bold}, so every button is
     * already bold and a bold-while-dirty state is invisible in the one place it has to work. The gutter of
     * two spaces on the clean label keeps the button's width from jumping as the flag flips.
     */
    private void applySaveEmphasis() {
        saveButton.setText(dirty ? SAVE_LABEL + " \u2022" : SAVE_LABEL + "  ");
    }

    /**
     * The Default is the all-hosts catch-all, so arming it would auto-rewrite every
     * unprofiled host - and {@code ProfileRegistry.matchAuto} structurally never returns it anyway. Disable
     * + clear its AUTO checkboxes (with an explanatory tooltip); restore them for any other profile.
     */
    private void applyDefaultAutoGuard() {
        if (isDefaultProfile) {
            autoPlantBox.setSelected(false);
            autoResignBox.setSelected(false);
            autoPlantBox.setEnabled(false);
            autoResignBox.setEnabled(false);
            autoPlantBox.setToolTipText(DEFAULT_AUTO_TIP);
            autoResignBox.setToolTipText(DEFAULT_AUTO_TIP);
        } else {
            autoPlantBox.setToolTipText(AUTO_PLANT_TIP);
            autoResignBox.setToolTipText(AUTO_RESIGN_TIP);
        }
    }

    /** Show the red AUTO caption only while an AUTO flag is armed; hide it otherwise. */
    private void updateAutoCaption() {
        autoCaption.setVisible(autoPlantBox.isSelected() || autoResignBox.isSelected());
        root.revalidate();
        root.repaint();
    }

    private void setControlsEnabled(boolean enabled) {
        boolean on = enabled;
        for (Component c : new Component[]{idField, nameField, hostKind, enabledBox, algCombo,
                attestationCombo, autoPlantBox, autoResignBox, regBody, authBody, checkButton, prettifyButton,
                saveButton}) {
            c.setEnabled(on);
        }
        applyHostKind(); // hostPattern's enablement is this AND a non-ANY kind
        regEditor.setEnabled(on);
        authEditor.setEnabled(on);
    }

    /**
     * The host-match counterpart of the verify-URL row's {@code applyUrlKind}. The two rows pose the operator
     * the identical question - a combo of match kinds beside a pattern box that states no format - so they
     * answer it identically: an example of the shape each kind expects, and under ANY a disabled box saying
     * what is actually happening, because {@link HostMatch#matches} returns true there without reading the
     * pattern at all. Leaving one row explained and the other bare was worse than leaving both bare: it reads
     * as the hint being broken on the row that has none.
     */
    private void applyHostKind() {
        HostMatch.Kind kind = (HostMatch.Kind) hostKind.getSelectedItem();
        boolean scoped = kind != null && kind != HostMatch.Kind.ANY;
        hostPattern.setEnabled(!empty && scoped);
        if (scoped) {
            hostPattern.setOverlay(null);
            hostPattern.setHint(switch (kind) {
                case EXACT -> "webauthn.io";
                case SUFFIX -> ".hanko.io";
                case REGEX -> ".*\\.example\\.com";
                case ANY -> "";
            });
        } else {
            hostPattern.setOverlay("every host");
        }
    }

    // ---- actions -------------------------------------------------------------------------------

    /** A locator/encoding control was edited: (re)start the debounce so Check re-runs shortly (live feedback). */
    private void scheduleLiveRecheck() {
        if (loading || empty) {
            return; // don't fire during programmatic load, or when no profile is open
        }
        markDirty(); // every caller of this is an operator edit to a locator, an encoding or a sample body
        liveTimer.restart();
    }

    private void onCheck() {
        if (empty) {
            return;
        }
        int reg = regEditor.runCheck(textOrNull(regBody), validator);
        int auth = authEditor.runCheck(textOrNull(authBody), validator);
        if (reg < 0 && auth < 0) {
            showStatus("Paste a registration and/or authentication body, then Check.", Palette::muted);
            return;
        }
        // A body is present. Count fields ACTUALLY configured (non-blank locator) for the phase(s) with a body,
        // so "0 problems" on a profile that configures NOTHING is not reported as success - the panel exists to
        // let the operator be SURE the locators are set, and greenlighting a profile that extracts nothing would
        // say the exact opposite.
        int configured = (reg >= 0 ? regEditor.configuredCount() : 0) + (auth >= 0 ? authEditor.configuredCount() : 0);
        if (configured == 0) {
            showStatus("no fields configured: set a path/regex for at least one field.", Palette::warn);
            return;
        }
        int problems = Math.max(reg, 0) + Math.max(auth, 0);
        showStatus(problems == 0
                ? "all " + configured + " configured field(s) extract cleanly"
                : problems + " field(s) not OK: see rows",
                problems == 0 ? Palette::ok : Palette::warn);
    }

    /**
     * Test seam: type a raw locator expression into a phase's field row, exactly as an operator keystroke
     * would (PATH mode, no validation), so a test can drive the live Check with a half-typed/invalid path.
     * Nestmate access reaches the private row + text field; not used by production code.
     */
    void typeLocatorForTest(Phase phase, Field field, String text) {
        PhaseEditor pe = phase == Phase.REG_VERIFY ? regEditor : authEditor;
        for (FieldRowEditor r : pe.rows) {
            if (r.field == field) {
                r.expr.setText(text);
                return;
            }
        }
        throw new IllegalArgumentException("no row for field " + field);
    }

    private void onSaveClicked() {
        if (empty) {
            return;
        }
        try {
            TargetProfile built = buildProfile();
            // Clear BEFORE handing the profile to the sink. The sink rebuilds the profile list and re-selects
            // the row it just wrote, which routes back through the list's selection handler - and that handler
            // is now the confirm-on-switch guard. Still dirty at that moment, our own save would prompt the
            // operator to rescue the edits it is in the middle of storing. buildProfile() above is the
            // validation gate and throws before reaching here, so a rejected save never clears the flag.
            clearDirty();
            onSave.accept(built);
            String warn = autoWarning(built);
            showStatus(warn == null ? "saved" : "saved. " + warn, warn == null ? Palette::ok : Palette::warn);
        } catch (RuntimeException ex) {
            showStatus(ex.getMessage(), Palette::error);
        }
    }

    /** Pretty-print whichever of the two sample bodies holds valid JSON (object/array); leave the rest as-is. */
    private void onPrettify() {
        if (empty) {
            return;
        }
        int done = prettify(regBody) + prettify(authBody);
        if (done == 0) {
            showStatus("Nothing to prettify. Paste valid JSON in a body first.", Palette::muted);
        } else {
            showStatus("prettified " + done + (done == 1 ? " body" : " bodies"), Palette::ok);
        }
    }

    /** Reformat one body in place if it parses as a JSON object/array; return 1 if reformatted, else 0. */
    private static int prettify(JTextArea area) {
        String text = area.getText();
        if (text == null || text.isBlank()) {
            return 0;
        }
        try {
            JsonElement el = JsonParser.parseString(text);
            if (!el.isJsonObject() && !el.isJsonArray()) {
                return 0; // a bare scalar isn't worth reformatting
            }
            String pretty = PRETTY.toJson(el);
            // Only touch the document if the text actually changes. setText is a remove-all + insert whatever
            // the content, so re-prettifying already-pretty JSON used to be a harmless no-op and is not one
            // any more: it fires the document listeners, marks the profile dirty, and earns the operator a
            // confirm dialog over an edit nobody made. Still counted as done, so the status line does not
            // claim there was nothing to prettify.
            if (!pretty.equals(text)) {
                area.setText(pretty);
                area.setCaretPosition(0);
            }
            return 1;
        } catch (RuntimeException ex) {
            return 0; // not valid JSON → leave it untouched
        }
    }

    /**
     * A non-blocking nudge when an AUTO switch is armed without the locators it needs to act: auto re-sign
     * needs a {@code SIGNATURE} locator on AUTH_VERIFY (and a {@code CREDENTIAL_ID} locator for correct
     * multi-account keying); auto-plant needs an {@code ATTESTATION_OBJECT} locator on REG_VERIFY. Returns
     * {@code null} when nothing is amiss. The profile still saves - this only warns.
     */
    private static String autoWarning(TargetProfile p) {
        if (p.autoResign()) {
            PhaseSpec auth = p.phase(Phase.AUTH_VERIFY);
            if (auth == null || auth.locator(Field.SIGNATURE) == null) {
                return "auto re-sign needs a SIGNATURE locator on AUTH_VERIFY";
            }
            if (auth.locator(Field.CREDENTIAL_ID) == null) {
                return "auto re-sign: add a CREDENTIAL_ID locator for correct multi-account keying";
            }
        }
        if (p.autoPlant()) {
            PhaseSpec reg = p.phase(Phase.REG_VERIFY);
            if (reg == null || reg.locator(Field.ATTESTATION_OBJECT) == null) {
                return "auto-plant needs an ATTESTATION_OBJECT locator on REG_VERIFY";
            }
        }
        return null;
    }

    private TargetProfile buildProfile() {
        String id = idField.getText().trim();
        if (id.isEmpty()) {
            throw new IllegalArgumentException("id is required");
        }
        String name = nameField.getText().trim().isEmpty() ? id : nameField.getText().trim();
        HostMatch.Kind hostAs = (HostMatch.Kind) hostKind.getSelectedItem();
        String hostText = hostPattern.getText().trim();
        // A blank pattern is SILENTLY all-hosts for these two: "x".endsWith("") and Pattern.compile("").find()
        // are both true, so an armed profile would rewrite live traffic everywhere. Blank EXACT is NOT rejected
        // - it matches nothing, and ProfileJson uses it deliberately as the inert default for a malformed
        // stored profile, which must stay re-savable through this panel.
        if ((hostAs == HostMatch.Kind.SUFFIX || hostAs == HostMatch.Kind.REGEX) && hostText.isBlank()) {
            throw new IllegalArgumentException(hostAs + " host match needs a pattern (blank matches EVERY host)");
        }
        HostMatch host = new HostMatch(hostAs, hostText);
        Map<Phase, PhaseSpec> phases = new LinkedHashMap<>();
        PhaseSpec reg = regEditor.toPhaseSpec();
        PhaseSpec auth = authEditor.toPhaseSpec();
        if (reg != null) {
            phases.put(Phase.REG_VERIFY, reg);
        }
        if (auth != null) {
            phases.put(Phase.AUTH_VERIFY, auth);
        }
        if (phases.isEmpty()) {
            throw new IllegalArgumentException("configure at least one field");
        }
        // isBlank (not isEmpty) so a whitespace-only paste stores as "no body" - matching the Check path's
        // textOrNull, so Save / persistence / Check agree on whether a sample body exists.
        String regSample = regBody.getText();
        String authSample = authBody.getText();
        SignerAlgorithm alg = (SignerAlgorithm) algCombo.getSelectedItem();
        SignerSpec signer = new SignerSpec(alg != null ? alg.coseId() : SignerSpec.ES256.coseAlg());
        // Enabled is the master switch - gate the AUTO flags on it HERE so the built profile is
        // authoritative and never depends on the un-tick ActionListener having fired. A programmatic
        // enabledBox.setSelected(false) (or any future ItemListener) leaves the AUTO boxes ticked; without
        // this gate buildProfile would read enabled=false + autoPlant=true and the TargetProfile compact
        // ctor (enabled = enabled||autoPlant||autoResign) would SILENTLY RE-ENABLE the profile the operator
        // just disabled - the Bug-1 failure mode. Gating downward at the build boundary closes that without
        // making the model invariant two-directional (which would wrongly disarm a legitimately-armed store).
        boolean en = enabledBox.isSelected();
        boolean ap = en && autoPlantBox.isSelected();
        boolean ar = en && autoResignBox.isSelected();
        PlantAttestation attestation = attestationCombo.getSelectedItem() instanceof PlantAttestation pa
                ? pa : PlantAttestation.NONE;
        return new TargetProfile(id, name, host, phases, en,
                regSample.isBlank() ? null : regSample, authSample.isBlank() ? null : authSample, signer,
                ap, ar, attestation);
    }

    /** The catalog entry for {@code coseAlg}, or ES256 if the persisted id is not a supported algorithm. */
    private static SignerAlgorithm safeAlg(int coseAlg) {
        return SignerAlgorithm.forCoseIdOrDefault(coseAlg, SignerAlgorithm.ES256);
    }

    // ---- per-phase editor ----------------------------------------------------------------------

    /** The URL scope + the field rows for one phase. */
    private static final class PhaseEditor {
        /**
         * One line, because a tooltip is one line - see {@link UiStyle#tip}. It answers only the question the
         * row cannot: what the pattern is measured against. What a mis-typed pattern actually costs is a
         * paragraph, so it lives in the Guide tab instead of being crammed in here.
         */
        private static final String URL_TIP =
                "Matched against the full request URL, not just the path.";

        private final Phase phase;
        private final JLabel urlLabel = new JLabel("verify URL:");
        private final JComboBox<UrlMatch.Kind> urlKind = new JComboBox<>(UrlMatch.Kind.values());
        private final HintField urlPattern = new HintField(22);
        private final JTextField urlMethod = new JTextField(5);
        private final List<FieldRowEditor> rows = new ArrayList<>();
        private final JPanel panel;
        /** The panel-wide enablement from {@link #setEnabled}; the URL field ANDs it with a non-ANY Kind. */
        private boolean controlsEnabled;
        /** Fired on any operator edit in this phase's URL row - the panel's unsaved-edit trigger. */
        private Runnable onDirty = () -> { };

        /** Re-apply every row's verdict colour after a theme change. */
        void retint() {
            rows.forEach(FieldRowEditor::retint);
        }

        PhaseEditor(Phase phase, Field[] fields) {
            this.phase = phase;
            JPanel rowsPanel = new JPanel();
            rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));
            for (Field f : fields) {
                FieldRowEditor row = new FieldRowEditor(f);
                rows.add(row);
                rowsPanel.add(row.component());
            }
            urlLabel.setToolTipText(URL_TIP);
            // The Kind drives more than the match algorithm: it decides whether the field means anything at
            // all, and what shape a value should take. Everything that depends on it is re-applied in one
            // place so the field can never disagree with the combo beside it.
            urlKind.addActionListener(e -> {
                applyUrlKind();
                onDirty.run();
            });
            // One listener, two jobs (they would otherwise fight over the same component): it keeps the
            // field's own tooltip mirroring what is typed - a 22-column box shows a long URL or regex through
            // a keyhole, and hovering is the cheapest way to read the whole of it - and it reports the edit.
            onDocumentChange(urlPattern.getDocument(), () -> {
                updateUrlTooltip();
                onDirty.run();
            });
            onDocumentChange(urlMethod.getDocument(), () -> onDirty.run());
            updateUrlTooltip();
            applyUrlKind();
            JPanel urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            urlRow.add(urlLabel);
            urlRow.add(urlKind);
            urlRow.add(urlPattern);
            urlRow.add(new JLabel("method:"));
            urlRow.add(urlMethod);

            // The field rows can be wider than the panel when Burp is scaled to a large font - the per-field
            // encoding radios (Auto / Raw / Base64 / Base64URL / URL encoded) run off the right edge and are
            // silently clipped. Wrap the rows in a horizontal-only scroll pane so a scrollbar appears UNDER them
            // to reach the cut-off controls, while they still grow VERTICALLY (decoded-detail expanders) with no
            // vertical scrollbar. getPreferredSize tracks the rows + reserves the scrollbar strip so no row is
            // clipped; isValidateRoot=false lets a row's revalidate (detail expand / live-check) propagate OUT to
            // the surrounding layout - a normal JScrollPane would trap it and the expander would vanish under
            // VERTICAL_NEVER.
            //
            // WheelForwardingScrollPane because that VERTICAL_NEVER is exactly the case Swing gets wrong: the
            // wheel goes to the innermost scrollable under the pointer and stops there, and this pane keeps a
            // vertical gesture it can never act on - so the config panel stopped scrolling the moment the
            // pointer was over a field row. Vertical always forwards here; horizontal stays local, which is
            // the whole point of this pane.
            JScrollPane rowsScroll = new WheelForwardingScrollPane(rowsPanel,
                    JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED) {
                @Override
                public Dimension getPreferredSize() {
                    Dimension d = rowsPanel.getPreferredSize();
                    int sb = getHorizontalScrollBar().getPreferredSize().height;
                    return new Dimension(d.width, d.height + sb);
                }

                @Override
                public boolean isValidateRoot() {
                    return false;
                }
            };
            rowsScroll.setBorder(BorderFactory.createEmptyBorder());
            rowsScroll.getHorizontalScrollBar().setUnitIncrement(16);

            // RigidHeightPanel: min-height = preferred so the GridBag glue can't collapse this box to the
            // rowsScroll's near-zero minimum (which would hide every field row when the pane is short).
            this.panel = new RigidHeightPanel(new BorderLayout());
            this.panel.setBorder(BorderFactory.createTitledBorder(phase.displayName()));
            this.panel.add(urlRow, BorderLayout.NORTH);
            this.panel.add(rowsScroll, BorderLayout.CENTER);
        }

        Component component() {
            return panel;
        }

        void setEnabled(boolean on) {
            controlsEnabled = on;
            urlKind.setEnabled(on);
            urlMethod.setEnabled(on);
            rows.forEach(r -> r.setEnabled(on));
            applyUrlKind(); // the pattern field's own enablement is this AND a non-ANY Kind
        }

        /**
         * Re-apply everything the Kind combo governs. Under {@code ANY} the pattern is inert - {@link UrlMatch}
         * short-circuits before reading it - so the field is disabled and says what is actually happening,
         * rather than sitting there enabled and empty looking like something still to fill in. Under the other
         * three the hint shows the shape that Kind expects, which is the one thing the row never stated: EXACT
         * wants a whole URL, CONTAINS a fragment of one, REGEX an expression over it.
         */
        private void applyUrlKind() {
            UrlMatch.Kind kind = (UrlMatch.Kind) urlKind.getSelectedItem();
            boolean scoped = kind != null && kind != UrlMatch.Kind.ANY;
            urlPattern.setEnabled(controlsEnabled && scoped);
            // A method gate is equally inert under ANY - UrlMatch's compact ctor nulls it - so the two
            // controls say the same thing rather than one looking live while the other is greyed.
            urlMethod.setEnabled(controlsEnabled && scoped);
            if (scoped) {
                urlPattern.setOverlay(null);
                urlPattern.setHint(hintFor(kind));
            } else {
                // Overlay, not hint: a profile loaded under ANY can still carry a pattern from an earlier
                // Kind, and that leftover is inert. Showing it would leave the operator reading a rule that
                // does nothing, so the state of the field is what gets displayed and the value stays on hover.
                urlPattern.setOverlay("any URL on this host");
            }
        }

        private static String hintFor(UrlMatch.Kind kind) {
            return switch (kind) {
                case EXACT -> "https://example.com/webauthn/verify";
                case CONTAINS -> "/webauthn/verify";
                case REGEX -> ".*/webauthn/(verify|complete)";
                case ANY -> "any URL on this host";
            };
        }

        /**
         * Put the value the operator typed at the FRONT of the field's own tooltip, ahead of the format
         * guidance, so hovering reads back a long URL or regex in full - the field is 22 columns and widening
         * it is not free: urlRow is a FlowLayout in the phase box's NORTH slot, so a wider field wraps
         * {@code method:} onto a second line the slot has no height for.
         * One tooltip rather than two: the field can only carry one, and the value is what you hover for -
         * {@link UiStyle#tip} puts it in its own block above the guidance and escapes it, which a pattern
         * containing {@code <} needs.
         */
        private void updateUrlTooltip() {
            String value = urlPattern.getText();
            // The value alone once there is one. Appending the guidance to it was how this tooltip grew past
            // the screen: a tooltip cannot wrap, so the two cannot share it. The guidance is a hover away on
            // the label beside it, and it is the value you hover the FIELD for - the box is 22 columns and a
            // full URL or regex does not fit in it.
            urlPattern.setToolTipText(value == null || value.isBlank() ? URL_TIP : UiStyle.tip(value));
        }

        /** Wire every field row to trigger a debounced live re-check when its locator/encoding is edited. */
        void setLiveRecheck(Runnable r) {
            rows.forEach(row -> row.setOnEdit(r));
        }

        /** Wire this phase's URL row (Kind / pattern / method) to the panel's unsaved-edit tracking. */
        void setOnDirty(Runnable r) {
            this.onDirty = r != null ? r : () -> { };
        }

        /** How many rows have a non-blank locator configured - so Check can tell "all green" from "nothing set". */
        int configuredCount() {
            int n = 0;
            for (FieldRowEditor r : rows) {
                try {
                    if (r.toLocator() != null) {
                        n++;
                    }
                } catch (RuntimeException invalidPath) {
                    // A row with a half-typed/invalid path is "configured but not yet valid": count it (its own
                    // runCheck renders the red error) rather than letting the parse throw out of the live re-check.
                    n++;
                }
            }
            return n;
        }

        void setFrom(PhaseSpec spec) {
            UrlMatch u = spec != null ? spec.url() : null;
            urlKind.setSelectedItem(u != null ? u.kind() : UrlMatch.Kind.ANY);
            urlPattern.setText(u != null ? u.pattern() : "");
            urlMethod.setText(u != null && u.method() != null ? u.method() : "");
            for (FieldRowEditor r : rows) {
                r.setFrom(spec != null ? spec.locator(r.field) : null);
            }
        }

        /** Build a PhaseSpec from the non-empty rows + URL, or {@code null} if no field is configured. */
        PhaseSpec toPhaseSpec() {
            Map<Field, FieldLocator> fields = new LinkedHashMap<>();
            for (FieldRowEditor r : rows) {
                FieldLocator loc = r.toLocator();
                if (loc != null) {
                    fields.put(r.field, loc);
                }
            }
            if (fields.isEmpty()) {
                return null;
            }
            UrlMatch url = new UrlMatch((UrlMatch.Kind) urlKind.getSelectedItem(),
                    urlPattern.getText().trim(), urlMethod.getText().trim());
            return new PhaseSpec(fields, url);
        }

        /** Run Check on each configured row; return the count of non-OK fields, or -1 if no body. */
        int runCheck(byte[] body, ProfileValidator validator) {
            if (body == null) {
                rows.forEach(FieldRowEditor::clearResult);
                return -1;
            }
            int problems = 0;
            for (FieldRowEditor r : rows) {
                Status s = r.runCheck(body, validator);
                if (s != null && s != Status.OK) {
                    problems++;
                }
            }
            return problems;
        }
    }

    // ---- per-field row -------------------------------------------------------------------------

    /** One field: PATH/REGEX locator + encoding controls + a live Check result. */
    private static final class FieldRowEditor {
        /** The verdict currently shown, so a theme change can re-colour it; null when cleared. */
        private Status verdict;

        private final Field field;
        private final JRadioButton pathBtn = new JRadioButton("path", true);
        private final JRadioButton regexBtn = new JRadioButton("regex");
        private final JTextField expr = new JTextField(26);
        private final JRadioButton encAuto = new JRadioButton("Auto", true);
        private final JRadioButton encRaw = new JRadioButton("Raw");
        private final JRadioButton encB64 = new JRadioButton("Base64");
        private final JRadioButton encB64Url = new JRadioButton("Base64URL");
        private final JCheckBox urlEncoded = new JCheckBox("URL encoded");
        private final JLabel result = new JLabel(" ");
        private final JLabel nameLabel;
        private final JPanel panel;          // outer: the controls row + the (hidden) detail expander
        private final JPanel controls;       // the FlowLayout row of locator/encoding controls + result + toggle

        // - per-field decoded-detail expander. The Check row shows a CONCISE verdict; this inline
        // disclosure reveals the FULL decoded value (encoding + byte length + full hex + ASCII when printable +
        // pretty JSON for clientDataJSON) so the operator can confirm a parse is MEANINGFUL, not just well-formed.
        // Rendered by the pure Burp-free DecodedDetail; no re-decode (uses the Check bytes). The panel is
        // RESIZABLE via a drag-grip (like the sample-body boxes) so a large hex/JSON value can be extended.
        private final JButton detailsToggle = new JButton("decoded ▸");
        private final JTextArea detailArea = new JTextArea(6, 72);
        // WheelForwardingScrollPane for the same reason as the body boxes: expanded, this box sits under the
        // pointer and would otherwise eat every wheel gesture, including with no scrollbar of its own. It
        // forwards to rowsScroll, which forwards again to the outer pane.
        private final JScrollPane detailScroll = new WheelForwardingScrollPane(detailArea);
        /**
         * detailScroll + resize grip; toggled visible.
         *
         * Width is clamped to the enclosing viewport. The field rows are deliberately WIDER than the
         * panel at large font sizes (that is what the horizontal scrollbar under them is for), and the
         * decoded box would otherwise inherit that width - pushing its text off the right edge, reachable
         * only by a horizontal scrollbar that an expanded detail has pushed far below the fold. The text
         * area already wraps by character, so bounding it to the visible width makes the decode readable
         * without scrolling sideways at all.
         */
        private final JPanel detailBox = new JPanel(new BorderLayout()) {
            @Override
            public Dimension getPreferredSize() {
                return clampToViewport(super.getPreferredSize());
            }

            /**
             * BoxLayout stretches a child to the container width up to its MAXIMUM size, so clamping the
             * preferred size alone changed nothing - the row is wider than the panel by design and the box
             * was stretched to match it regardless.
             */
            @Override
            public Dimension getMaximumSize() {
                return clampToViewport(super.getMaximumSize());
            }

            private Dimension clampToViewport(Dimension d) {
                JViewport port = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, this);
                if (port != null && port.getWidth() > 0) {
                    Insets in = getInsets();
                    d.width = Math.min(d.width, Math.max(120, port.getWidth() - in.left - in.right));
                }
                return d;
            }
        };
        /** Decoded inner bytes + encoding label from the last Check - what the expander renders. */
        private byte[] lastBytes;
        private String lastEncoding;
        private boolean detailExpanded;
        private boolean rowEnabled = true;
        /** Fired when the operator edits this row's locator/encoding - triggers the panel's debounced live re-check. */
        private Runnable onEdit = () -> { };

        /**
         * The {@link EncodingSpec} loaded via {@link #setFrom} - returned verbatim by {@link #encoding()}
         * until the operator actually edits an encoding control. The 4-way Auto/Raw/Base64/Base64URL radio
         * cannot express every spec (off-diagonal padding, an envelopeKey), so rebuilding it on every
         * load+save would silently corrupt those dimensions; preserving it keeps a round-trip byte-faithful.
         */
        private EncodingSpec loadedEncoding;
        private boolean encodingDirty;

        FieldRowEditor(Field field) {
            this.field = field;
            ButtonGroup kind = new ButtonGroup();
            kind.add(pathBtn);
            kind.add(regexBtn);
            ButtonGroup enc = new ButtonGroup();
            enc.add(encAuto);
            enc.add(encRaw);
            enc.add(encB64);
            enc.add(encB64Url);
            // Encoding edits mark the spec dirty AND trigger a live re-check; path/regex + the expression box
            // trigger it too. All go through onEdit (a no-op until the panel wires setOnEdit), which debounces.
            java.awt.event.ActionListener markDirty = ev -> {
                encodingDirty = true;
                onEdit.run();
            };
            encAuto.addActionListener(markDirty);
            encRaw.addActionListener(markDirty);
            encB64.addActionListener(markDirty);
            encB64Url.addActionListener(markDirty);
            urlEncoded.addActionListener(markDirty);
            pathBtn.addActionListener(ev -> onEdit.run());
            regexBtn.addActionListener(ev -> onEdit.run());
            onDocumentChange(expr.getDocument(), () -> onEdit.run());

            this.nameLabel = new JLabel(field.jsonName());
            nameLabel.setPreferredSize(new Dimension(132, 18));
            // No fixed width on the result: the concise verdict sizes naturally so the "decoded" toggle sits
            // RIGHT AFTER the text, not pushed to the far-right edge by an oversized reserved label.

            // Per-control guidance, so hovering any option explains THAT option (not one shared message).
            pathBtn.setToolTipText("path: address the value by JSON path (object keys, [index], and "
                    + "$base64 envelopes), e.g. response.response.signature.");
            regexBtn.setToolTipText("regex: capture group 1 of a regex run on the raw body "
                    + "(e.g. \"signature\":\"([^\"]+)\"). Reaches layers a structural path cannot.");
            encAuto.setToolTipText("Auto: detect the encoding automatically (Base64, Base64URL, and JSON "
                    + "$base64 envelopes). The default; pick a specific encoding only to override it.");
            encRaw.setToolTipText("Raw: the value is not Base64; use the bytes as-is (no Base64 decode).");
            encB64.setToolTipText("Base64: standard alphabet (+ and /), '=' padded.");
            encB64Url.setToolTipText("Base64URL: URL-safe alphabet (- and _), usually unpadded.");
            urlEncoded.setToolTipText("URL encoded: the value is also percent-encoded (e.g. %2B); decode that "
                    + "layer first. Stacks with the Auto / Raw / Base64 / Base64URL choice.");

            this.controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 1));
            controls.setAlignmentX(Component.LEFT_ALIGNMENT);
            controls.add(nameLabel);
            controls.add(pathBtn);
            controls.add(regexBtn);
            controls.add(expr);
            controls.add(encAuto);
            controls.add(encRaw);
            controls.add(encB64);
            controls.add(encB64Url);
            controls.add(urlEncoded);
            controls.add(result);
            controls.add(detailsToggle);

            // the inline decoded-detail expander, below the controls, hidden until "decoded" is clicked.
            detailsToggle.setEnabled(false);
            detailsToggle.setMargin(new Insets(0, 6, 0, 6));
            detailsToggle.setFocusable(false);
            // One line, like every tooltip here (see UiStyle.tip) - at 242 characters this rendered 1455px
            // wide, and it repeats on all nine field rows. Which fields get structured JSON is answered by
            // expanding it, and the resize hint is carried by the grip's own tooltip, on the grip.
            detailsToggle.setToolTipText("Show the full decoded value: structured JSON for the CBOR fields, "
                    + "otherwise encoding, length, hex and ASCII.");
            detailsToggle.addActionListener(ev -> setDetailExpanded(!detailExpanded));
            detailArea.setEditable(false);
            detailArea.setLineWrap(true);
            detailArea.setWrapStyleWord(false); // hex/base64 have no spaces - wrap by char, not word
            detailArea.setFont(Fonts.mono());
            detailScroll.setBorder(BorderFactory.createEmptyBorder()); // the box outline below wraps scroll + grip as one

            // A full-width drag-bar in its own strip INSIDE the box outline, so the operator can extend the
            // decoded view to fit a large hex / JSON value - the same affordance as the sample-body boxes.
            JPanel gripStrip = gripStrip(detailScroll);
            detailBox.setVisible(false);
            detailBox.setAlignmentX(Component.LEFT_ALIGNMENT);
            detailBox.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createEmptyBorder(0, 24, 4, 4),   // indent under the controls row
                    BorderFactory.createLineBorder(Palette.border())));
            detailBox.add(detailScroll, BorderLayout.CENTER);
            detailBox.add(gripStrip, BorderLayout.SOUTH);

            this.panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            panel.add(controls);
            panel.add(detailBox);
        }

        Component component() {
            return panel;
        }

        /** Set the callback fired when this row's locator/encoding is edited (the panel's live re-check trigger). */
        void setOnEdit(Runnable r) {
            this.onEdit = r != null ? r : () -> { };
        }

        void setEnabled(boolean on) {
            rowEnabled = on;
            for (Component c : controls.getComponents()) {
                c.setEnabled(on);
            }
            // The details toggle is enabled only when there is something to show; a disabled row collapses.
            detailsToggle.setEnabled(on && lastBytes != null);
            if (!on) {
                setDetailExpanded(false);
            }
        }

        /**
         * Colour the verdict and remember which one it is, so {@link #retint} can restore it after a
         * theme change without re-running the check.
         */
        void showVerdict(Status status) {
            this.verdict = status;
            result.setForeground(verdictColor(status));
        }

        /** Re-apply the current verdict's colour under the theme now in force. */
        void retint() {
            if (verdict != null) {
                result.setForeground(verdictColor(verdict));
            }
        }

        private static Color verdictColor(Status status) {
            return switch (status) {
                case OK -> Palette.ok();
                case NOT_FOUND -> Palette.error();
                case ABSENT -> Palette.muted();   // absent-but-optional is not a problem to fix
                case SUSPECT -> Palette.warn();
            };
        }

        void clearResult() {
            result.setText(" ");
            result.setToolTipText(null);
            verdict = null;
            lastBytes = null;
            lastEncoding = null;
            detailArea.setText("");      // drop the prior field's decoded plaintext from the component (no residue across reloads)
            detailsToggle.setEnabled(false);
            setDetailExpanded(false);
        }

        /** Expand/collapse the decoded-detail area, (re)rendering its content from the last Check bytes. */
        private void setDetailExpanded(boolean expanded) {
            detailExpanded = expanded;
            detailsToggle.setText(expanded ? "decoded ▾" : "decoded ▸");
            if (expanded) {
                detailArea.setText(detailText());
                detailArea.setCaretPosition(0);
            }
            detailBox.setVisible(expanded);
            panel.revalidate();
            panel.repaint();
        }

        /**
         * The decoded-detail block for the expander. For the CBOR fields (attestationObject /
         * authenticatorData) it shows the SAME structured JSON the Passkey Editor tab shows, so the two views
         * are coherent (a raw-hex dump of a CBOR blob is useless to a human). Every other field keeps the
         * generic encoding / length / hex / ASCII / JSON block from {@link DecodedDetail}.
         */
        private String detailText() {
            String structured = switch (field) {
                case ATTESTATION_OBJECT -> CeremonyJson.attestationObjectJson(lastBytes);
                case AUTHENTICATOR_DATA -> CeremonyJson.authenticatorDataJson(lastBytes);
                default -> null;
            };
            if (structured == null) {
                return DecodedDetail.render(lastEncoding, lastBytes);
            }
            StringBuilder sb = new StringBuilder();
            if (lastEncoding != null && !lastEncoding.isBlank()) {
                sb.append("encoding : ").append(lastEncoding).append('\n');
            }
            sb.append("length   : ").append(lastBytes.length).append(lastBytes.length == 1 ? " byte" : " bytes");
            sb.append('\n').append("decoded  :").append('\n').append(structured);
            return sb.toString();
        }

        void setFrom(FieldLocator loc) {
            loadedEncoding = loc != null ? loc.encoding() : null;
            encodingDirty = false;
            if (loc == null) {
                pathBtn.setSelected(true);
                expr.setText("");
                encAuto.setSelected(true);
                urlEncoded.setSelected(false);
                setEncodingTooltip(null);
                clearResult();
                return;
            }
            if (loc.kind() == FieldLocator.Kind.REGEX) {
                regexBtn.setSelected(true);
                expr.setText(loc.regex());
            } else {
                pathBtn.setSelected(true);
                List<String> ps = new ArrayList<>();
                loc.candidates().forEach(jp -> ps.add(jp.toString()));
                expr.setText(String.join(" | ", ps));
            }
            EncodingSpec e = loadedEncoding;
            urlEncoded.setSelected(e != null && e.urlEncoded());
            Base64Kind b = e == null ? Base64Kind.AUTO : e.base64();
            switch (b) {
                case AUTO -> encAuto.setSelected(true);
                case NONE -> encRaw.setSelected(true);
                case STANDARD -> encB64.setSelected(true);
                case URL_SAFE -> encB64Url.setSelected(true);
            }
            setEncodingTooltip(e);
            clearResult();
        }

        /** Put the field's loaded encoding (incl. padding / envelope the radios can't show) on the field
         * name's hover, leaving each encoding control's own tooltip free to explain that option. */
        private void setEncodingTooltip(EncodingSpec e) {
            nameLabel.setToolTipText(field.jsonName() + ", loaded encoding: "
                    + (e == null ? "auto-detect" : e.label()) + " (preserved unless you edit a control).");
        }

        /** Build a FieldLocator from the row, or {@code null} if the expression is blank (unconfigured). */
        FieldLocator toLocator() {
            String text = expr.getText().trim();
            if (text.isEmpty()) {
                return null;
            }
            EncodingSpec enc = encoding();
            if (regexBtn.isSelected()) {
                return FieldLocator.regex(text, enc);
            }
            String[] paths = text.split("\\|");
            List<String> cleaned = new ArrayList<>();
            for (String p : paths) {
                if (!p.trim().isEmpty()) {
                    cleaned.add(p.trim());
                }
            }
            return FieldLocator.of(enc, cleaned.toArray(new String[0]));
        }

        /** The encoding from the radios + URL tick, or {@code null} for pure Auto (defer to auto-detect). */
        private EncodingSpec encoding() {
            // Untouched since load → return the loaded spec verbatim, preserving padding + envelopeKey the
            // 4-way radio can't represent (so a load+save never silently rewrites those dimensions).
            if (!encodingDirty) {
                return loadedEncoding;
            }
            boolean url = urlEncoded.isSelected();
            if (encAuto.isSelected()) {
                return url ? EncodingSpec.autoUrlEncoded() : null;
            }
            if (encRaw.isSelected()) {
                return new EncodingSpec(url, Base64Kind.NONE, Padding.UNPADDED, null);
            }
            if (encB64.isSelected()) {
                return new EncodingSpec(url, Base64Kind.STANDARD, Padding.PADDED, null);
            }
            return new EncodingSpec(url, Base64Kind.URL_SAFE, Padding.UNPADDED, null);
        }

        Status runCheck(byte[] body, ProfileValidator validator) {
            FieldLocator loc;
            try {
                loc = toLocator();
            } catch (RuntimeException invalidPath) {
                // A half-typed/invalid path (e.g. an unterminated '[') must NOT throw on the EDT: JsonPath.parse
                // raises IllegalArgumentException on malformed input, and this runs on every keystroke via the
                // debounced live re-check. Degrade to a red verdict, mirroring ProfileValidator.check's
                // never-throw contract; Save keeps using the throwing toLocator() so onSaveClicked surfaces it.
                clearResult();
                result.setText(invalidPath.getMessage() != null ? invalidPath.getMessage() : "invalid path");
                showVerdict(Status.NOT_FOUND);
                result.setToolTipText(UiStyle.tip(result.getText()));
                return Status.NOT_FOUND;
            }
            if (loc == null) {
                clearResult();
                return null;
            }
            CheckResult r = validator.check(body, field, loc);
            // Concise verdict: OK → the short "what it is" summary; otherwise → the note (the problem). No
            // icon - the colour alone carries the verdict (green OK / orange SUSPECT / red NOT_FOUND).
            String detail = r.status() == Status.OK ? r.summary() : r.note();
            if (detail == null) {
                detail = r.decoded(); // defensive fallback (should not happen for OK/NOT_FOUND/SUSPECT)
            }
            result.setText(detail != null ? detail : "");
            showVerdict(r.status());
            // Full context on hover: the problem note (if any) + the located wire value + encoding - so a
            // truncated concise line never hides why a field is SUSPECT/NOT_FOUND or what was located.
            String tip = r.note() != null ? r.note() : "";
            if (r.located() != null) {
                // Abbreviated: this is the value off the wire, so its length is the RP's choice, not ours -
                // a located attestationObject measured 3745px here, the widest tooltip in the extension. The
                // prefix is enough to recognise what was found; the whole value is what "decoded" is for.
                tip = (tip.isEmpty() ? "" : tip + ", ") + "[" + r.encoding() + "] located: "
                        + UiStyle.abbreviate(r.located(), 56);
            }
            result.setToolTipText(UiStyle.tip(tip));
            // stash the decoded bytes for the expander. Enable the toggle only when bytes decoded;
            // if the detail is currently open, refresh it to this new Check result (else leave it collapsed).
            lastBytes = r.decodedBytes();
            lastEncoding = r.encoding();
            boolean hasBytes = lastBytes != null;
            detailsToggle.setEnabled(rowEnabled && hasBytes);
            if (!hasBytes) {
                setDetailExpanded(false);
            } else if (detailExpanded) {
                setDetailExpanded(true);
            }
            return r.status();
        }
    }

    // ---- small helpers -------------------------------------------------------------------------

    // Verdict colours (green OK / amber SUSPECT / red NOT_FOUND) come from Palette, so they stay legible
    // on both Burp themes; the old locals here were mid-tones that faded out against the dark one.

    /**
     * Set the panel status line's text and tone together. The tone is the colour's meaning
     * ({@code Palette::ok}), not a value, so the line still reads correctly after a theme change.
     */
    private void showStatus(String text, Supplier<Color> tone) {
        status.setText(text);
        // The label clips with an ellipsis when the footer is narrow, so the whole message stays reachable on
        // hover. A blank status carries no tooltip rather than an empty one.
        status.setToolTipText(UiStyle.tip(text));
        root.tint(status, tone);
    }

    /** Register a {@link javax.swing.event.DocumentListener} that runs {@code r} on any document change. */
    private static void onDocumentChange(javax.swing.text.Document doc, Runnable r) {
        doc.addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        });
    }

    /** A full-width transparent strip carrying a {@link ResizeGrip} for {@code target} (a drag-to-resize bar). */
    private static JPanel gripStrip(JComponent target) {
        JPanel strip = new JPanel(new BorderLayout());
        strip.setOpaque(false);
        strip.add(new ResizeGrip(target), BorderLayout.CENTER);
        return strip;
    }

    private static byte[] textOrNull(JTextArea a) {
        String t = a.getText();
        return t == null || t.isBlank() ? null : t.getBytes(StandardCharsets.UTF_8);
    }

    private static JTextArea bodyArea() {
        JTextArea a = new JTextArea(10, 80);
        a.setLineWrap(true);
        a.setFont(Fonts.mono());
        return a;
    }

    private JPanel labeled(String label, JTextArea area) {
        // WheelForwardingScrollPane: a body box is a scrollable inside the panel's own scroll pane, so a wheel
        // gesture with the pointer over it stops here. Forwarding once this box is at its own top/bottom keeps
        // the outer column scrolling instead of the wheel appearing to die over a text area.
        JScrollPane scroll = new WheelForwardingScrollPane(area);
        scroll.setBorder(BorderFactory.createEmptyBorder()); // the box outline below wraps scroll + grip as one
        // Grip lives in its own strip INSIDE the box outline (not overlapping the scroll pane) - an overlay
        // would get overpainted whenever the scroll pane repaints (e.g. after Prettify) and vanish. The strip is
        // a FULL-WIDTH drag-bar (not just a corner nub), so it stays an easy target when Burp is scaled up.
        JPanel gripStrip = gripStrip(scroll);
        JPanel box = new JPanel(new BorderLayout());
        // Our OWN border instance per box, not the shared UIManager "ScrollPane.border". That shared
        // instance is built for a JScrollPane and, reused across two plain panels, painted only one of
        // them - the registration box lost its outline entirely at larger font sizes. A line border we
        // construct here is one instance per box and paints predictably; retint() re-colours it on a
        // theme change, which the cached look-and-feel border never did either.
        box.setBorder(BorderFactory.createLineBorder(Palette.border()));
        boxOutlines.add(box);
        box.add(scroll, BorderLayout.CENTER);
        box.add(gripStrip, BorderLayout.SOUTH); // bottom-right grip, inside the outline
        JPanel p = new JPanel(new BorderLayout(0, 2));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(new JLabel(label), BorderLayout.NORTH);
        p.add(box, BorderLayout.CENTER);
        return p;
    }

    private static JPanel leftRow(Component... comps) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (Component c : comps) {
            p.add(c);
        }
        return p;
    }

    /**
     * A scroll pane that hands a wheel gesture up to the enclosing scroll pane once it has no room left in
     * that axis.
     *
     * Swing delivers a wheel event to the innermost wheel-enabled component under the pointer and stops there -
     * a component that has the event but does nothing with it does NOT pass it on. Every scroll pane is
     * wheel-enabled, so an inner one swallows the gesture even in an axis it cannot move: over the field rows
     * (VERTICAL_SCROLLBAR_NEVER) the panel simply stopped scrolling, and over a body box it stopped as soon as
     * that box hit its own end.
     *
     * The decision is taken in {@code processMouseWheelEvent} rather than in a {@code MouseWheelListener}
     * because it has to happen BEFORE the look and feel's own wheel listener, and a listener cannot: they fire
     * in registration order and the L&F's is installed by the constructor, so anything client code adds runs
     * only after the L&F has already consumed the event and scrolled the wrong bar. Getting ahead of it means
     * surgery on the pane's listener list, and an L&F change - which Burp performs live on a theme switch -
     * tears that list down and rebuilds it, taking the removed handler with it. Overriding here is
     * order-independent, and delegating to {@code super} for the local case reuses the L&F's exact scroll
     * arithmetic rather than reimplementing it.
     */
    private static class WheelForwardingScrollPane extends JScrollPane {

        WheelForwardingScrollPane(Component view) {
            super(view);
        }

        WheelForwardingScrollPane(Component view, int verticalPolicy, int horizontalPolicy) {
            super(view, verticalPolicy, horizontalPolicy);
        }

        @Override
        protected void processMouseWheelEvent(MouseWheelEvent e) {
            JScrollPane outer = hasRoomFor(e)
                    ? null
                    : (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, this);
            if (outer == null) {
                super.processMouseWheelEvent(e); // room left here, or nothing to forward to - scroll normally
                return;
            }
            // convertMouseEvent re-sources a MouseWheelEvent as one (preserving scroll type, amount and the
            // precise rotation a trackpad sends), which a hand-built MouseEvent would quietly drop.
            outer.dispatchEvent(SwingUtilities.convertMouseEvent(this, e, outer));
            e.consume();
        }

        /**
         * Whether this pane can still move in the wheel's own axis. A {@code *_SCROLLBAR_NEVER} policy is
         * "never can" regardless of what the model says - the bar exists but is never shown, and the L&F would
         * otherwise answer a vertical gesture by scrolling the HORIZONTAL bar instead.
         *
         * Shift means "horizontal" because that is the convention Swing itself scrolls by: BasicScrollPaneUI's
         * own wheel handler switches to the horizontal bar on {@code isShiftDown()}. Reading the axis the same
         * way keeps this pane's answer and the L&F's answer about the same gesture from disagreeing.
         */
        private boolean hasRoomFor(MouseWheelEvent e) {
            boolean horizontal = e.isShiftDown();
            int policy = horizontal ? getHorizontalScrollBarPolicy() : getVerticalScrollBarPolicy();
            if (policy == (horizontal ? HORIZONTAL_SCROLLBAR_NEVER : VERTICAL_SCROLLBAR_NEVER)) {
                return false;
            }
            JScrollBar bar = horizontal ? getHorizontalScrollBar() : getVerticalScrollBar();
            if (bar == null || !bar.isVisible()) {
                return false; // nothing to scroll in this axis: the content fits
            }
            // getPreciseWheelRotation, not getWheelRotation: the int one stays 0 on a high-resolution device
            // until a whole click has accumulated, so a slow trackpad swipe emits a run of rotation-0 events
            // that would all be read as "downward" and tested against the wrong end of the range. The precise
            // value carries the real direction and equals the int rotation for a classic wheel. It matters
            // here specifically: Burp's look and feel scrolls smoothly off the precise value.
            return e.getPreciseWheelRotation() < 0
                    ? bar.getValue() > bar.getMinimum()
                    : bar.getValue() + bar.getVisibleAmount() < bar.getMaximum();
        }
    }

    /**
     * A single-line field that paints a grey hint over itself while it is empty and unfocused.
     *
     * Used for the verify-URL pattern, which is the one field in this panel with no self-evident format: it
     * sits next to a Kind combo whose four values each expect a different shape of value, and the operator on
     * Burp Community retypes it every session (profiles do not survive a restart there). Painted rather than
     * inserted as placeholder text so the document stays genuinely empty - {@code toPhaseSpec} reads it
     * directly, and a hint that could be saved as a pattern would be worse than no hint at all.
     */
    private static final class HintField extends JTextField {

        private String hint = "";
        /** Painted over the field's own text when set - for a state where the stored value does not apply. */
        private String overlay;

        HintField(int columns) {
            super(columns);
        }

        void setHint(String hint) {
            this.hint = hint != null ? hint : "";
            repaint();
        }

        /** Replace what the field shows with {@code text} (null to go back to showing the document). */
        void setOverlay(String text) {
            this.overlay = text;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            if (overlay != null) {
                // Paint the field empty first, then the overlay, so the inert value underneath does not show
                // through. getText() is deliberately not consulted: the point is that it does not apply.
                paintBlank(g);
                drawGrey(g, overlay);
                return;
            }
            super.paintComponent(g);
            // Shown for as long as the field is empty, focused or not. Hiding it on focus is the common
            // placeholder idiom and it is wrong here: the operator clicks into this field precisely because
            // they do not know what shape of value it wants, and that click is what would take the answer
            // away. Typing removes it, which is the only moment it stops being the thing you need.
            if (hint.isEmpty() || !getText().isEmpty()) {
                return;
            }
            drawGrey(g, hint);
        }

        /**
         * The field's own chrome with no text in it - the ground the overlay is written onto. The colour comes
         * from the look and feel's key for the field's CURRENT state, not from getBackground(): the overlay is
         * only ever shown on a disabled field, and a look and feel that greys a disabled field (Burp's does)
         * would otherwise get the enabled colour painted back over it and the field would look live again.
         */
        private void paintBlank(Graphics g) {
            if (!isOpaque()) {
                return;
            }
            Color bg = UIManager.getColor(isEnabled() ? "TextField.background" : "TextField.disabledBackground");
            g.setColor(bg != null ? bg : getBackground());
            g.fillRect(0, 0, getWidth(), getHeight());
        }

        private void drawGrey(Graphics g, String text) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setColor(Palette.muted()); // muted is the palette's TEXT grey, which is what this is
                g2.setFont(getFont().deriveFont(Font.ITALIC));
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                        RenderingHints.VALUE_TEXT_ANTIALIAS_ON); // else the hint reads rougher than real text
                Insets in = getInsets();
                g2.clipRect(in.left, in.top, Math.max(0, getWidth() - in.left - in.right),
                        Math.max(0, getHeight() - in.top - in.bottom)); // never draw past the field's border
                FontMetrics fm = g2.getFontMetrics();
                int usable = getHeight() - in.top - in.bottom;
                g2.drawString(text, in.left, in.top + (usable - fm.getHeight()) / 2 + fm.getAscent());
            } finally {
                g2.dispose();
            }
        }
    }

    /**
     * A panel whose minimum HEIGHT is pinned to its preferred height. The four boxes live in a GridBag with a
     * trailing weighty=1 glue row (to pack them to the top when the pane is tall); GridBag satisfies every
     * cell's minimum first and hands the surplus to the weighted glue. A box that contains a scroll
     * pane (the field-row horizontal scroller, the sample-body areas) has a near-zero natural minimum height,
     * so without this the glue would collapse the box - hiding the field rows and flattening the body boxes to
     * one line when the pane is short. Pinning min-height = preferred-height stops that collapse; the content
     * keeps its height and the OUTER scroll pane scrolls vertically instead. Width stays free (min width 0) so
     * the width-tracking + inner horizontal scroll are unaffected.
     */
    private static final class RigidHeightPanel extends JPanel {
        RigidHeightPanel() {
            super();
        }

        RigidHeightPanel(LayoutManager layout) {
            super(layout);
        }

        @Override
        public Dimension getMinimumSize() {
            return new Dimension(0, getPreferredSize().height);
        }
    }

    /**
     * A panel that reports it tracks the scroll viewport's width - so the four GridBag boxes stretch to the
     * full pane width and their edges line up - while scrolling vertically as usual.
     */
    private static final class WidthTrackingPanel extends JPanel implements Scrollable {
        WidthTrackingPanel(LayoutManager layout) {
            super(layout);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) {
            return 64;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /**
     * A full-width drag-bar (dotted grip painted at the bottom-right, textarea-style) that resizes the given
     * scroll pane's height on a vertical drag, so the operator can grow / shrink a body box to fit the pasted
     * JSON. The whole bar is the hit target (not just the corner dots) and its height scales with the UI
     * font - so it stays a comfortable, reliable drag target when Burp is scaled up (the 16x12 corner nub it
     * replaced was easy to miss at large font sizes).
     */
    private static final class ResizeGrip extends JPanel {
        private final JComponent target;
        private int startScreenY;
        private int startHeight;

        ResizeGrip(JComponent target) {
            this.target = target;
            setOpaque(false); // only the dots paint; the box background shows through
            setCursor(Cursor.getPredefinedCursor(Cursor.S_RESIZE_CURSOR));
            setToolTipText("Drag to resize this box");
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    startScreenY = e.getYOnScreen();
                    startHeight = target.getPreferredSize().height;
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    int h = Math.max(40, startHeight + (e.getYOnScreen() - startScreenY));
                    Dimension cur = target.getPreferredSize();
                    target.setPreferredSize(new Dimension(cur.width, h));
                    // Revalidate the PARENT, not the scroll pane: a JScrollPane is its own validate root, so
                    // revalidating it would never propagate the new preferred size to the surrounding layout.
                    java.awt.Container parent = target.getParent();
                    if (parent != null) {
                        parent.revalidate();
                        parent.repaint();
                    }
                }
            };
            addMouseListener(ma);
            addMouseMotionListener(ma);
        }

        /** One line tall, scaled to the UI font; width is irrelevant - BorderLayout.CENTER stretches it full. */
        @Override
        public Dimension getPreferredSize() {
            int fs = getFont() != null ? getFont().getSize() : 12;
            int h = Math.max(12, fs);
            return new Dimension(h, h);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            g.setColor(Palette.muted());
            int w = getWidth();
            int h = getHeight();
            for (int row = 0; row < 3; row++) {       // dot grip, bottom-right corner: full bottom row up to one on top
                for (int col = 0; col + row < 3; col++) {
                    g.fillRect(w - 3 - col * 3, h - 3 - row * 3, 2, 2); // ~2px inside the box's bottom-right corner
                }
            }
        }
    }
}
