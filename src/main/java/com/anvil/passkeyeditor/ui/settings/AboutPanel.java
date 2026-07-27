package com.anvil.passkeyeditor.ui.settings;

import com.anvil.passkeyeditor.PasskeyEditorExtension;
import com.anvil.passkeyeditor.ui.ThemedPanel;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;

/**
 * The "About" tab: what this is, who made it, and where to file issues, over a scannable feature list.
 * Usage lives in the Guide; the full reference lives in the project README, so entries here stay short.
 *
 * Layout is a single bounded left-aligned column (Swing's HTML renderer ignores {@code max-width},
 * so {@link UiStyle#doc} pins each block's width): a lead line, identity, the link buttons, then the
 * features.
 */
public final class AboutPanel {

    /** Repository behind the buttons and the issue templates; see {@link PasskeyEditorExtension#REPO_URL}. */
    private static final String REPO = PasskeyEditorExtension.REPO_URL;
    private static final String ANVIL = "https://www.anvilsecure.com";

    /**
     * Column widths (px). {@link #TEXT_W} is the content width, matching the length of the Features
     * heading's underline; the two top columns divide it exactly, so the button stack's RIGHT edge
     * finishes flush with the end of that underline.
     */
    private static final int TEXT_W = 720;
    private static final int BUTTONS_W = 210;
    private static final int GAP = 30;
    private static final int LEFT_W = TEXT_W - BUTTONS_W - GAP;

    private static final String LEAD = """
        Extension for testing <b>WebAuthn/FIDO2</b> passkey ceremonies: decode, edit, and attack
        CBOR/COSE payloads.
        """;

    private static final String IDENTITY = """
        <b>Developed by:</b> Matteo Giordano @ %s<br>
        <b>Version:</b> %s
        """;

    /** Formatted at build time, not class-init: the link colour is read from the installed theme. */
    private static String identity() {
        return IDENTITY.formatted(UiStyle.link(ANVIL, "Anvil Secure"), PasskeyEditorExtension.VERSION);
    }

    // Nested one level so the shape reads at a glance. Swing draws list markers OUTSIDE the content
    // box, so every list needs an explicit left margin or the bullets clip against the pane edge.
    private static final String FEATURES = """
        <ul style='margin:0 0 0 16px'>
          <li><b>Decoded ceremony view</b> in Proxy and Repeater
            <ul style='margin:0 0 0 16px'>
              <li>Decodes clientDataJSON, authenticatorData, attestationObject, COSE key, signature</li>
              <li>Base64 (any flavour), double-Base64, JSON envelopes, percent-encoding</li>
              <li>Hand-editable on an authentication: clientDataJSON, plus the authenticatorData
                  flags, signature counter and RP-ID hash. A registration is a read-only decode,
                  edited through the plant, attestation, flag and credentialId controls</li>
              <li>Surgical edits: only the bytes you change are rewritten; everything else passes
                  through untouched</li>
            </ul>
          </li>
          <li><b>Attacks</b>, one click then resend
            <ul style='margin:0 0 0 16px'>
              <li>Forge or re-sign assertions with 11 COSE algorithms</li>
              <li>Registration key-plant for account takeover, None or packed self-attestation</li>
              <li>Clear UV to bypass user verification</li>
              <li>Toggle the UP / UV / BE / BS flags</li>
              <li>Downgrade UV to discouraged on the options response</li>
              <li>Mutate the origin</li>
              <li>Mutate the RP-ID</li>
              <li>Forge a cross-origin (clickjacking) framing</li>
              <li>Swap credentialId for collision or overwrite</li>
              <li>Invalidate the signature (flip a byte, empty, zero or randomize it)</li>
            </ul>
          </li>
          <li><b>Target Profiles</b>: per-host field extraction by JSON path or regex, with a live
              Check validator</li>
          <li><b>AUTO mode</b>: off by default; plant and re-sign matching requests in flight</li>
          <li><b>Proxy highlighting</b>: marks the ceremony rows on hosts you are tracking</li>
        </ul>
        """;

    private final ThemedPanel root;

    public AboutPanel() {
        this.root = new ThemedPanel(new BorderLayout());
        this.root.onTheme(this::build);   // and again whenever Burp's theme flips
    }

    /** Build the tab's contents. Re-run on a theme change: the colours are baked into the HTML. */
    private void build() {
        JPanel col = new JPanel();
        col.setOpaque(false);
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        col.add(topBand());
        col.add(Box.createVerticalStrut(4));
        col.add(UiStyle.heading("Features", TEXT_W));
        col.add(Box.createVerticalStrut(6));
        col.add(UiStyle.doc(FEATURES, TEXT_W));
        col.add(Box.createVerticalGlue());

        root.removeAll();
        root.add(new JScrollPane(col), BorderLayout.CENTER);
        root.revalidate();
        root.repaint();
    }

    /** Prose on the left, GitHub buttons on the right, the pair packed left so neither stretches. */
    private JPanel topBand() {
        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(UiStyle.doc(LEAD, LEFT_W));
        left.add(Box.createVerticalStrut(10));
        left.add(UiStyle.doc(identity(), LEFT_W));
        left.setMaximumSize(new Dimension(LEFT_W, left.getPreferredSize().height));
        left.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel buttons = buttons();
        buttons.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel band = new JPanel();
        band.setOpaque(false);
        band.setLayout(new BoxLayout(band, BoxLayout.X_AXIS));
        band.setAlignmentX(Component.LEFT_ALIGNMENT);
        band.add(left);
        band.add(Box.createHorizontalStrut(GAP));
        band.add(buttons);
        band.add(Box.createHorizontalGlue());
        band.setMaximumSize(new Dimension(Integer.MAX_VALUE, band.getPreferredSize().height));
        return band;
    }

    /** The GitHub buttons, stacked and pinned to the button width so they do not stretch. */
    private JPanel buttons() {
        JPanel buttons = new JPanel(new GridLayout(0, 1, 0, 4));
        buttons.setOpaque(false);
        buttons.add(linkButton("View on GitHub", REPO));
        buttons.add(linkButton("Report a Bug", issueUrl("bug_report.md", "bug",
                "v" + PasskeyEditorExtension.VERSION + " - Bug: YOUR_TITLE_HERE")));
        buttons.add(linkButton("Request a Feature", issueUrl("feature_request.md", "enhancement",
                "Feature: YOUR_TITLE_HERE")));
        Dimension dim = new Dimension(BUTTONS_W, buttons.getPreferredSize().height);
        buttons.setPreferredSize(dim);
        buttons.setMaximumSize(dim);
        buttons.setMinimumSize(dim);
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        return buttons;
    }

    /** A button carrying the GitHub mark after its label, sized to the current font. */
    private static JButton linkButton(String label, String url) {
        JButton b = new JButton(label);
        b.setIcon(new GithubMark(Math.max(14, b.getFont().getSize() + 2)));
        b.setHorizontalTextPosition(SwingConstants.LEADING);
        b.setIconTextGap(6);
        b.addActionListener(e -> UiStyle.browse(url));
        return b;
    }

    /**
     * A "new issue" URL that opens one of the repository's issue templates
     * ({@code .github/ISSUE_TEMPLATE/}) with the title and labels prefilled. The label is passed here as
     * well as declared in the template, so it still lands if the template is missing. No {@code body} is
     * sent: that parameter overrides the template's own body. An unknown template name degrades to
     * GitHub's blank form rather than failing.
     */
    private static String issueUrl(String template, String labels, String title) {
        return REPO + "/issues/new?template=" + enc(template)
                + "&labels=" + enc(labels)
                + "&title=" + enc(title);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public Component component() {
        root.themeChanged();   // second chance if the host changed theme without walking this tree
        return root;
    }
}
