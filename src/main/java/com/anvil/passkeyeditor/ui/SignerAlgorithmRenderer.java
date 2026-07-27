package com.anvil.passkeyeditor.ui;

import com.anvil.passkeyeditor.crypto.SignerAlgorithm;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

/**
 * Renders a {@link SignerAlgorithm} combo-box entry as its ctap.dev-style display name (e.g. {@code "ES256
 * (-7)"}, {@code "EdDSA (-8)"}) instead of the raw enum constant. Shared by the Profile-Editor default-alg
 * dropdown and the ceremony editor's manual algorithm chooser.
 */
public final class SignerAlgorithmRenderer extends DefaultListCellRenderer {

    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                  boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        if (value instanceof SignerAlgorithm a) {
            setText(a.displayName());
        }
        return this;
    }
}
