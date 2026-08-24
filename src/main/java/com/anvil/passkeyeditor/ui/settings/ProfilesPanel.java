package com.anvil.passkeyeditor.ui.settings;

import burp.api.montoya.MontoyaApi;

import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.ProfileStore;
import com.anvil.passkeyeditor.profile.ProfileValidator;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.util.Log;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridLayout;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ListSelectionModel;

/**
 * The "Profiles" tab: a left profile list (Add / Copy / Delete / Reset Default; selecting a profile loads
 * it on the right) and the right {@link ProfileConfigPanel} for editing + the live Check. Each profile row
 * shows its switches at a glance - ☑/☐ enabled, plus {@code auto-plant} / {@code re-sign} tags - so an
 * armed profile is visible without opening it.
 *
 * Mutations update the shared {@link ProfileRegistry} (the editor + the AUTO/colour handlers consult it
 * per request) and persist via {@link ProfileStore}. The Default is pinned as the first row and is a
 * real, editable profile: it can be edited and disabled like any other (disable every profile,
 * including the Default, and the extension matches nothing). It lives in its own registry slot, so it is
 * saved via {@link ProfileRegistry#setDefaultProfile} (not {@link ProfileRegistry#replace}) and cannot be
 * deleted. There is no global "active profile" or master auto toggle - AUTO is armed per profile via the
 * Auto-plant / Auto-re-sign checkboxes in the config panel (arming auto-ticks Enabled).
 */
public final class ProfilesPanel {

    /** Indices into the unsaved-edits dialog's own answer array (showOptionDialog returns a position). */
    private static final int SAVE_ANSWER = 0;
    private static final int DISCARD_ANSWER = 1;

    private final MontoyaApi api;
    private final ProfileRegistry registry;
    private final ProfileStore store;

    private final JPanel root;
    private final DefaultListModel<TargetProfile> listModel = new DefaultListModel<>();
    private final JList<TargetProfile> list = new JList<>(listModel);
    private final ProfileConfigPanel config;

    /** The id of the profile currently loaded in the editor (so Save can replace it even if the id changes). */
    private String editingId;
    /** True when the loaded row is the Default (saved via setDefaultProfile, never deletable). By reference. */
    private boolean editingDefault;
    /** True while the list is being rebuilt - suppresses the synthetic clear()-fired selection event. */
    private boolean rebuilding;

    public ProfilesPanel(MontoyaApi api, ProfileRegistry registry, ProfileStore store) {
        this.api = api;
        this.registry = registry;
        this.store = store;
        this.config = new ProfileConfigPanel(new ProfileValidator(), this::onSaveProfile);

        // Repaint on every dirty flip so the marker appears with the first keystroke rather than at the next
        // selection change - the whole point of it is to be there BEFORE the click that would discard.
        this.config.setOnDirtyChanged(list::repaint);

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer((jlist, value, index, sel, focus) -> {
            JLabel l = new JLabel(renderRow(value, hasUnsavedEdits(value)));
            l.setOpaque(true);
            l.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
            if (sel) {
                l.setBackground(jlist.getSelectionBackground());
                l.setForeground(jlist.getSelectionForeground());
            } else {
                l.setBackground(jlist.getBackground());
                l.setForeground(rowColor(value, jlist.getForeground()));
            }
            return l;
        });
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onSelect();
            }
        });

        JButton add = new JButton("Add");
        add.addActionListener(e -> onAdd());
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> onCopy());
        JButton delete = new JButton("Delete");
        delete.addActionListener(e -> onDelete());
        JButton restore = new JButton("Reset Default");
        restore.setToolTipText("Restore the Default profile to its shipped configuration. "
                + "Your other profiles are not touched.");
        restore.addActionListener(e -> onResetDefault());
        JPanel buttonGrid = new JPanel(new GridLayout(0, 1, 0, 4)); // equal-width, vertically stacked
        buttonGrid.add(add);
        buttonGrid.add(copy);
        buttonGrid.add(delete);
        buttonGrid.add(restore);
        JPanel buttonBar = new JPanel(new BorderLayout());
        buttonBar.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0)); // a little gap above the buttons
        buttonBar.add(buttonGrid, BorderLayout.NORTH); // stacked, sized to content (not stretched tall)
        buttonBar.setAlignmentX(Component.LEFT_ALIGNMENT);

        JScrollPane listScroll = new JScrollPane(list);
        listScroll.setAlignmentX(Component.LEFT_ALIGNMENT);

        // The list box grows with the profile count (refreshList → setVisibleRowCount) instead of greedily
        // filling the pane; the buttons sit right beneath it and the whole stack is packed to the top, so a
        // handful of profiles stays high up with blank space below.
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(UiStyle.heading("Profiles")); // orange-underlined heading + top padding
        top.add(listScroll);
        top.add(buttonBar);

        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(BorderFactory.createEmptyBorder(0, 6, 6, 6));
        left.setMinimumSize(new Dimension(260, 0)); // keep names readable when the divider is dragged in
        left.add(top, BorderLayout.NORTH); // content-sized, top-packed (CENTER left empty → blank space below)

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, config.component());
        split.setResizeWeight(0.30);
        split.setDividerLocation(340); // wider so long profile ids + tags aren't truncated

        this.root = new JPanel(new BorderLayout());
        this.root.add(split, BorderLayout.CENTER);

        refreshList();
    }

    public Component component() {
        return root;
    }

    // ---- list cell rendering -------------------------------------------------------------------

    /** A row label: unsaved marker + enabled mark + name + AUTO tags + a not-active hint. Arm ⟹ enabled, so
     * there is no "auto-only" (armed-but-disabled) state: a disabled profile is fully inactive. */
    private static String renderRow(TargetProfile p, boolean unsaved) {
        // The marker leads the row, over a two-space gutter on every other row so the glyphs stay roughly
        // columnar as a row goes dirty (roughly, not exactly - the label font is proportional). It has to be
        // on the LIST, not on the editor: the moment the edits are at risk is the click on another row, and
        // that is where the eye already is.
        StringBuilder sb = new StringBuilder(unsaved ? "• " : "  ");
        sb.append(p.enabled() ? "☑ " : "☐ ");
        sb.append(p.name());
        if (p.autoPlant()) {
            sb.append("  [auto-plant]");
        }
        if (p.autoResign()) {
            sb.append("  [re-sign]");
        }
        if (!p.enabled()) {
            sb.append("  [not active]"); // disabled ⇒ no tab, no colour, no auto
        }
        return sb.toString();
    }

    /** True for the one row the editor is holding, when that editor has edits Save has not seen. */
    private boolean hasUnsavedEdits(TargetProfile p) {
        return p != null && editingId != null && config.isDirty() && editingId.equals(p.id());
    }

    private static Color rowColor(TargetProfile p, Color normal) {
        if (p.enabled()) {
            return (p.autoPlant() || p.autoResign()) ? Palette.accent() : normal; // armed stands out; plain enabled normal
        }
        return Palette.muted(); // disabled ⇒ inert ⇒ grey
    }

    // ---- profile list actions ------------------------------------------------------------------

    private void onSelect() {
        if (rebuilding) {
            return; // ignore the synthetic null selection a list rebuild fires
        }
        // Read the click before anything can move the selection again: the Save answer below re-selects the
        // row it wrote, so by the time the guard returns the list no longer remembers what was asked for.
        TargetProfile picked = list.getSelectedValue();
        if (!guardUnsavedEdits(picked)) {
            return; // cancelled, or a save the panel rejected - the guard has put the selection back
        }
        // Re-read rather than load `picked`. Answering Save runs a full registry mutation and list rebuild in
        // between, and `picked` is a pre-mutation reference that the save may have EVICTED: renaming a
        // profile's id onto another profile's makes ProfileRegistry.replace drop that other holder to free the
        // id. Loading the stale object then puts a profile the registry no longer has into the editor under an
        // id that now belongs to something else, and the next Save writes the phantom over the profile the
        // operator just chose to save. Whatever the rebuilt list is pointing at is the profile that exists.
        TargetProfile loaded = list.getSelectedValue();
        editingId = loaded != null ? loaded.id() : null;
        editingDefault = loaded != null && loaded == registry.defaultProfile(); // the pinned top row, by reference
        config.setProfile(loaded, editingDefault);
    }

    /**
     * Ask before a selection change overwrites unsaved edits, and answer whether the change may proceed.
     *
     * Selecting a row loads it over every field in the config panel, so a half-typed profile disappears on the
     * click that was only meant to look at another one. Saving per keystroke is NOT the fix: the profile drives
     * both detection and live-traffic rewriting, so it would arm partial state mid-typing - and Save is the
     * validation gate (it is precisely where a blank pattern is rejected). Prompting keeps the gate and still
     * makes the loss impossible to hit by accident.
     */
    private boolean guardUnsavedEdits(TargetProfile picked) {
        if (!config.isDirty()) {
            return true;
        }
        String label = editingId != null ? editingId : "this profile";
        // showOptionDialog, not showConfirmDialog: YES_NO_CANCEL_OPTION renders "Yes / No / Cancel", which
        // leaves the operator to work out that "No" is the button that throws their typing away. Naming the
        // three answers is the whole point of asking.
        Object[] answers = {"Save", "Discard", "Cancel"};
        int choice = JOptionPane.showOptionDialog(frame(),
                "Profile '" + label + "' has unsaved changes. Save them before switching?",
                "Passkey Editor", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null,
                answers, answers[0]);
        if (choice == SAVE_ANSWER) {
            config.saveNow(); // the button's own path, validation gate included
            if (config.isDirty()) {
                // Rejected (a missing id, a blank SUFFIX/REGEX host, no field configured). The panel has
                // written the reason to its status line; keep the operator on the profile that reason is
                // about instead of discarding it behind a dialog they thought had saved.
                restoreSelection();
                return false;
            }
            // A successful save re-selected the row it wrote. Put the operator's actual click back before the
            // caller loads it, or "Save then switch" would silently land on the profile just saved.
            selectQuietly(picked);
            return true;
        }
        if (choice == DISCARD_ANSWER) {
            return true; // discard: the caller is about to load over the edits, which is what was asked
        }
        restoreSelection(); // Cancel, or the dialog dismissed (CLOSED_OPTION)
        return false;
    }

    /** Re-select the row still loaded in the editor, so a cancelled switch leaves the list where it was. */
    private void restoreSelection() {
        selectQuietly(editingId);
    }

    private void selectQuietly(TargetProfile p) {
        selectQuietly(p != null ? p.id() : null);
    }

    /**
     * Drive the list selection without re-entering {@link #onSelect}. Reuses the {@code rebuilding} guard the
     * list rebuild already relies on: this is the same situation - the selection is being set by the panel
     * rather than clicked by the operator, so it must not re-run the guard that brought us here.
     */
    private void selectQuietly(String id) {
        rebuilding = true;
        try {
            if (id == null) {
                list.clearSelection();
            } else {
                selectById(id);
            }
        } finally {
            rebuilding = false;
        }
    }

    private void onAdd() {
        // Ask BEFORE mutating. These handlers end in a selectById that re-enters onSelect and so would hit the
        // guard anyway - but by then the new profile is already in the registry and on disk, so answering
        // Cancel would keep the edits and still leave an unwanted row behind. Settle the panel first, and
        // Cancel means nothing happened at all.
        if (!guardUnsavedEdits(list.getSelectedValue())) {
            return;
        }
        String id = uniqueId("new-profile");
        TargetProfile blank = new TargetProfile(id, "New profile", HostMatch.exact("example.com"), Map.of(), false);
        registry.add(blank);
        persist();
        refreshList();
        selectById(id);
        log("Profile added: '" + id + "'");
    }

    private void onCopy() {
        TargetProfile p = list.getSelectedValue();
        if (p == null) {
            info("Select a profile to copy.");
            return;
        }
        if (!guardUnsavedEdits(p)) { // same reason as onAdd: do not persist a copy the operator then cancels
            return;
        }
        String id = uniqueId(p.id() + "-copy");
        registry.add(duplicateProfile(p, id));
        persist();
        refreshList();
        selectById(id);
        log("Profile copied: '" + p.id() + "' to '" + id + "'");
    }

    /**
     * A staged duplicate of {@code src} under {@code newId}: disabled and AUTO-off (the 8-arg ctor
     * defaults {@code autoPlant}/{@code autoResign} false, and enabled=false) so it never touches traffic
     * until the operator validates + arms it - but it carries the source's configuration: the signer
     * algorithm AND the plant attestation format (both operator-chosen settings, not activation state).
     * Package-private + static so the copy composition is unit-tested without a Swing harness.
     */
    static TargetProfile duplicateProfile(TargetProfile src, String newId) {
        return new TargetProfile(newId, src.name() + " (copy)", src.host(), src.phases(), false,
                src.sampleRegBody(), src.sampleAuthBody(), src.signer())
                .withPlantAttestation(src.plantAttestation());
    }

    private void onDelete() {
        TargetProfile p = list.getSelectedValue();
        if (p == null) {
            info("Select a profile to delete.");
            return;
        }
        if (p == registry.defaultProfile()) {
            info("The Default profile can't be deleted. Disable it (untick Enabled) if you want it inert.");
            return;
        }
        if (confirm("Delete profile '" + p.id() + "'?")) {
            registry.remove(p.id());
            persist();
            refreshList();
            editingId = null;
            config.setProfile(null);
            log("Profile deleted: '" + p.id() + "'");
        }
    }

    /**
     * Restore the Default profile to its shipped configuration. The Default is editable (locators, encodings,
     * enabled switch, signing algorithm), so it can be broken; nothing else offered a way back short of a new
     * Burp project. Scoped strictly to the Default: the operator's own profiles are untouched.
     */
    private void onResetDefault() {
        // This ends in config.setProfile(null), which wipes the editor - so if another profile is loaded with
        // unsaved edits, resetting the Default silently destroys them. That is the exact loss the unsaved-edit
        // guard exists to prevent, and this action's own wording ("Your other profiles are not affected")
        // actively promises it will not happen. Ask first, and before the reset's own confirm, so Cancel here
        // leaves both the Default and the edits untouched.
        if (!guardUnsavedEdits(list.getSelectedValue())) {
            return;
        }
        if (!confirm("Restore the Default profile to its shipped configuration? "
                + "Your other profiles are not affected.")) {
            return;
        }
        registry.setDefaultProfile(BuiltinProfiles.defaultProfile());
        persist();
        refreshList();
        editingId = null;
        editingDefault = false;
        config.setProfile(null);
        log("Default profile restored to its shipped configuration");
    }

    /**
     * ProfileConfigPanel Save callback. The Default lives in its own slot → save it via setDefaultProfile;
     * every other profile is replaced IN PLACE (preserving match precedence). Both persist (the Default to
     * its own key).
     */
    private void onSaveProfile(TargetProfile rebuilt) {
        if (editingDefault) {
            registry.setDefaultProfile(rebuilt);
        } else {
            registry.replace(editingId != null ? editingId : rebuilt.id(), rebuilt);
        }
        editingId = rebuilt.id();
        persist();
        refreshList();
        selectById(rebuilt.id());
        log("Profile saved: " + describeSaved(rebuilt));
    }

    /** {@code 'id'  host=…  [enabled]  plant=on/off  re-sign=on/off} for the save log line. */
    private static String describeSaved(TargetProfile p) {
        return "'" + p.id() + "'"
                + "  [" + (p.enabled() ? "enabled" : "disabled") + "]"
                + "  plant=" + (p.autoPlant() ? "on" : "off")
                + "  re-sign=" + (p.autoResign() ? "on" : "off");
    }

    // ---- helpers -------------------------------------------------------------------------------

    private void refreshList() {
        rebuilding = true;
        try {
            TargetProfile sel = list.getSelectedValue();
            listModel.clear();
            listModel.addElement(registry.defaultProfile()); // the editable Default, pinned on top
            for (TargetProfile p : registry.profiles()) {
                listModel.addElement(p);
            }
            // grow the list box with the row count (capped) so the buttons sit just below a short list
            list.setVisibleRowCount(Math.max(3, Math.min(listModel.size(), 14)));
            if (sel != null) {
                selectById(sel.id());
            }
        } finally {
            rebuilding = false;
        }
    }

    private void selectById(String id) {
        for (int i = 0; i < listModel.size(); i++) {
            if (listModel.get(i).id().equals(id)) {
                list.setSelectedIndex(i);
                return;
            }
        }
    }

    private String uniqueId(String base) {
        Set<String> ids = new HashSet<>();
        registry.profiles().forEach(p -> ids.add(p.id()));
        // The Default is not in profiles() but IS a row, and every id lookup here (selectById, the unsaved
        // marker) resolves first-match over the model with the Default pinned at index 0. A listed profile
        // that took its id would shadow it in all of them.
        ids.add(registry.defaultProfile().id());
        if (!ids.contains(base)) {
            return base;
        }
        int n = 2;
        while (ids.contains(base + "-" + n)) {
            n++;
        }
        return base + "-" + n;
    }

    private void persist() {
        try {
            store.save(registry.profiles());
            store.saveDefault(registry.defaultProfile()); // the Default lives in its own slot
        } catch (RuntimeException e) {
            api.logging().logToError("Passkey Editor: failed to persist profiles", e);
        }
    }

    private void info(String message) {
        JOptionPane.showMessageDialog(frame(), message, "Passkey Editor", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Echo a profile-list change to the Output log. Profiles are per-project persisted state that silently
     * changes what the extension does to live traffic, so every add / copy / delete / save / reset leaves a
     * timestamped trace next to the load-time inventory.
     */
    private void log(String message) {
        try {
            Log.out(api.logging(), message);
        } catch (RuntimeException e) {
            // Logging must never break a UI action.
        }
    }

    private boolean confirm(String message) {
        return JOptionPane.showConfirmDialog(frame(), message, "Passkey Editor",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION;
    }

    private Frame frame() {
        try {
            return api.userInterface().swingUtils().suiteFrame();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
