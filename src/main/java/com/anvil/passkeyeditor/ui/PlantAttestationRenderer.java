package com.anvil.passkeyeditor.ui;

import com.anvil.passkeyeditor.profile.PlantAttestation;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

/**
 * Renders a {@link PlantAttestation} combo-box entry as its human label (e.g. {@code "None"}, {@code "Packed
 * self-attestation"}) instead of the raw enum constant. Shared by the Profile-Editor per-profile attestation
 * dropdown and the ceremony editor's manual attestation chooser (mirrors {@link SignerAlgorithmRenderer}).
 */
public final class PlantAttestationRenderer extends DefaultListCellRenderer {

    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                  boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        if (value instanceof PlantAttestation mode) {
            setText(mode.label());
        }
        return this;
    }
}
