package com.anvil.passkeyeditor.ui.settings;

import burp.api.montoya.MontoyaApi;

import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.ProfileStore;
import com.anvil.passkeyeditor.ui.Palette;
import com.anvil.passkeyeditor.ui.ThemedPanel;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/**
 * The Passkey Editor suite tab: a title plus internal tabs - Profiles (the integrated profile
 * manager + per-field config + live Check), a Guide, and About. The component is built once and registered via
 * {@code registerSuiteTab}.
 */
public final class ProfileEditorTab {

    private final ThemedPanel root;

    public ProfileEditorTab(MontoyaApi api, ProfileRegistry registry, ProfileStore store) {
        JLabel title = new JLabel("Passkey Editor");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        title.setBorder(BorderFactory.createEmptyBorder(8, 12, 4, 12));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Profiles", new ProfilesPanel(api, registry, store).component());
        tabs.addTab("Guide", new GuidePanel().component());
        tabs.addTab("About", new AboutPanel().component());

        this.root = new ThemedPanel(new BorderLayout());
        this.root.add(title, BorderLayout.NORTH);
        this.root.add(tabs, BorderLayout.CENTER);
        this.root.tint(title, Palette::accent);
    }

    /** The component to register as the suite tab. */
    public Component component() {
        return root;
    }
}
