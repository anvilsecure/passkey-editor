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
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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

    private static final String AUTO_PLANT_TIP = "AUTO substitutes OUR key into matching registrations "
            + "(REG_VERIFY) in-flight, a larger blast radius. Off by default; every action is logged and "
            + "highlighted ORANGE in Proxy history. Arming this auto-ticks Enabled. Acts on EVERY host this "
            + "profile's host-match covers, regardless of Burp target scope. Use a specific host match.";
    private static final String AUTO_RESIGN_TIP = "AUTO re-signs matching authentications (AUTH_VERIFY) with "
            + "the key we hold. It prefers the key stored for that exact credential; holding exactly ONE key "
            + "it uses that key even for an unmatched credential (logged as MOST-RECENT FALLBACK), and with "
            + "two or more keys held an unmatched credential passes through. Off by default; logged and highlighted "
            + "ORANGE in Proxy history. Arming this auto-ticks Enabled. Acts on EVERY host this profile's "
            + "host-match covers, regardless of Burp target scope. Use a specific host match.";
    private static final String DEFAULT_AUTO_TIP = "The Default matches every host, so it "
            + "can't be AUTO-armed. Create a host-specific profile to arm AUTO.";

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
    private final JComboBox<HostMatch.Kind> hostKind = new JComboBox<>(HostMatch.Kind.values());
    private final JTextField hostPattern = new JTextField(20);
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
    final JButton saveButton = new JButton("Save profile");
    final JLabel status = new JLabel(" ");
    /** Red warning shown only while an AUTO flag is armed - toggled by {@link #updateAutoCaption()}. */
    private final JLabel autoCaption = new JLabel("AUTO rewrites live traffic");

    /** True when no profile is loaded - guards Check/Save. */
    private boolean empty = true;
    /** True when the loaded profile is the catch-all Default - its AUTO checkboxes are disabled (see setProfile). */
    private boolean isDefaultProfile;
    /** True while {@link #setProfile} is populating the controls - suppresses live re-check on programmatic edits. */
    private boolean loading;
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
        };
        autoPlantBox.addActionListener(armTicksEnabled);
        autoResignBox.addActionListener(armTicksEnabled);
        enabledBox.addActionListener(e -> {
            if (!enabledBox.isSelected()) {
                autoPlantBox.setSelected(false);
                autoResignBox.setSelected(false);
            }
            updateAutoCaption();
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
        header.add(leftRow(new JLabel("host match:"), hostKind, hostPattern));
        header.add(leftRow(new JLabel("default signing alg:"), algCombo,
                new JLabel("  plant attestation:"), attestationCombo));
        header.setBorder(BorderFactory.createEmptyBorder(0, 6, 6, 6));

        // Box 4: the sample bodies + Check/Save actions, in one titled panel. RigidHeightPanel so the GridBag
        // glue can't flatten the (scroll-pane-backed) body boxes when the pane is short - it scrolls instead.
        JPanel bodies = new RigidHeightPanel();
        bodies.setLayout(new BoxLayout(bodies, BoxLayout.Y_AXIS));
        bodies.add(labeled("Registration body (paste the reg-verify request body):", regBody));
        bodies.add(Box.createVerticalStrut(4));
        bodies.add(labeled("Authentication body (paste the auth-verify request body):", authBody));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.setAlignmentX(Component.LEFT_ALIGNMENT);
        actions.add(checkButton);
        actions.add(prettifyButton);
        actions.add(saveButton);
        actions.add(status);
        bodies.add(actions);
        bodies.setBorder(BorderFactory.createTitledBorder("Sample bodies"));

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
        for (Component c : new Component[]{idField, nameField, hostKind, hostPattern, enabledBox, algCombo,
                attestationCombo, autoPlantBox, autoResignBox, regBody, authBody, checkButton, prettifyButton,
                saveButton}) {
            c.setEnabled(on);
        }
        regEditor.setEnabled(on);
        authEditor.setEnabled(on);
    }

    // ---- actions -------------------------------------------------------------------------------

    /** A locator/encoding control was edited: (re)start the debounce so Check re-runs shortly (live feedback). */
    private void scheduleLiveRecheck() {
        if (loading || empty) {
            return; // don't fire during programmatic load, or when no profile is open
        }
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
            area.setText(PRETTY.toJson(el));
            area.setCaretPosition(0);
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
        private final Phase phase;
        private final JComboBox<UrlMatch.Kind> urlKind = new JComboBox<>(UrlMatch.Kind.values());
        private final JTextField urlPattern = new JTextField(22);
        private final JTextField urlMethod = new JTextField(5);
        private final List<FieldRowEditor> rows = new ArrayList<>();
        private final JPanel panel;

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
            JPanel urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            urlRow.add(new JLabel("verify URL:"));
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
            JScrollPane rowsScroll = new JScrollPane(rowsPanel,
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
            urlKind.setEnabled(on);
            urlPattern.setEnabled(on);
            urlMethod.setEnabled(on);
            rows.forEach(r -> r.setEnabled(on));
        }

        /** Wire every field row to trigger a debounced live re-check when its locator/encoding is edited. */
        void setLiveRecheck(Runnable r) {
            rows.forEach(row -> row.setOnEdit(r));
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
        private final JScrollPane detailScroll = new JScrollPane(detailArea);
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
            detailsToggle.setToolTipText("Show the FULL decoded value: for attestationObject / "
                    + "authenticatorData / clientDataJSON the same structured JSON the Passkey Editor tab shows, "
                    + "otherwise encoding, byte length, full hex and ASCII when printable. Drag the corner grip to resize.");
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
                result.setToolTipText(result.getText());
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
                tip = (tip.isEmpty() ? "" : tip + ", ") + "[" + r.encoding() + "] located: " + r.located();
            }
            result.setToolTipText(tip.isEmpty() ? null : tip);
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
        JScrollPane scroll = new JScrollPane(area);
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
