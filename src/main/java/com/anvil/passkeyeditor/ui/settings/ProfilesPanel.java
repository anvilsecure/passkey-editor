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

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer((jlist, value, index, sel, focus) -> {
            JLabel l = new JLabel(renderRow(value));
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

    /** A row label: enabled mark + name + AUTO tags + a not-active hint. Arm ⟹ enabled, so there is no
     * "auto-only" (armed-but-disabled) state: a disabled profile is fully inactive. */
    private static String renderRow(TargetProfile p) {
        StringBuilder sb = new StringBuilder(p.enabled() ? "☑ " : "☐ ");
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
        TargetProfile p = list.getSelectedValue();
        editingId = p != null ? p.id() : null;
        editingDefault = p != null && p == registry.defaultProfile(); // the pinned top row, by reference
        config.setProfile(p, editingDefault);
    }

    private void onAdd() {
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
