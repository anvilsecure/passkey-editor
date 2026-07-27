package com.anvil.passkeyeditor.ui.settings;

import com.anvil.passkeyeditor.PasskeyEditorExtension;
import com.anvil.passkeyeditor.ui.ThemedPanel;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

/**
 * The "Guide" tab: enough to get from intercepted traffic to a validated, enabled profile without
 * leaving the extension, plus the two things you cannot discover by poking (what the highlights mean,
 * and how far AUTO reaches). Deeper reference lives in the project README.
 *
 * Sections are separate blocks so each gets a real {@link UiStyle} heading; every list carries an
 * explicit left margin because Swing draws list markers outside the content box.
 */
public final class GuidePanel {

    /** Wider than the About column: the steps and warnings read better with fewer wraps. */
    private static final int TEXT_W = 1000;

    /** Colour legend chips. Black text is pinned so a light chip stays readable in a dark theme. */
    private static final String GREEN = chip("#5CB85C", "green");
    private static final String AMBER = chip("#E8A33D", "amber");
    private static final String RED = chip("#E88080", "red");
    private static final String ORANGE = chip("#FFB800", "orange");
    private static final String CHANGED = chip("#FFD54F", "amber");

    private static final String INTRO = """
        A <b>Target Profile</b> tells Passkey Editor where a site keeps its passkey fields and how they
        are encoded. Set one up per site, then test freely.
        """;

    private static final String SETUP = """
        <ol style='margin:0 0 0 20px'>
          <li><b>Capture</b> a registration and an authentication in Burp.</li>
          <li><b>Add</b> a profile; set its <b>host</b> and per-phase <b>verify URL</b>
              (<code>contains /verify-authentication</code>). The boxes below stay disabled until a
              profile is selected, so this comes first.</li>
          <li><b>Copy</b> each verify request body into the <b>Registration body</b> and
              <b>Authentication body</b> boxes on the Profiles tab.</li>
          <li><b>Locate</b> each field by JSON <b>path</b> (<code>response.response.signature</code>) or
              <b>regex</b> (<code>"signature":"([^"]+)"</code>), and set its <b>encoding</b>.</li>
          <li><b>Check</b>, then fix anything that is not green:
            <ul style='margin:0 0 0 16px'>
              <li>%s found and decoded</li>
              <li>%s decoded but suspect</li>
              <li>%s not found</li>
              <li>grey: not present in this ceremony, and optional, so there is nothing to fix
                  (<code>userHandle</code> is only sent for a discoverable credential)</li>
            </ul>
          </li>
          <li><b>Save profile</b>. Nothing you typed takes effect until you do, and selecting another
              profile first discards it.</li>
          <li><b>Enable</b> the profile and <b>Save</b> again. The ceremony tab now extracts exactly
              what Check showed.</li>
        </ol>
        """.formatted(GREEN, AMBER, RED);

    private static final String LOCATING = """
        <ul style='margin:0 0 0 16px'>
          <li><b>Path</b> walks keys, array indices (<code>[2].response.signature</code>) and envelope
              keys (<code>attestation.attestationObject.$base64</code>).</li>
          <li><b>Regex</b> reaches what a path cannot: escaped or stringified layers, unusual
              envelopes.</li>
          <li><b>Auto</b> encoding detects Base64, Base64URL and JSON envelopes; pin Base64 or
              Base64URL only to override it.</li>
        </ul>
        """;

    private static final String PROFILES = """
        <ul style='margin:0 0 0 16px'>
          <li><b>Keep as many profiles enabled as you like.</b> A request uses the first enabled
              profile whose host matches, so every target you have configured can stay on at once. If
              two enabled profiles match the same host, the one higher in the list wins.</li>
          <li><b>Default</b> is the fallback. It handles any host that has no profile of its own, using
              the generic SimpleWebAuthn shape. Edit or disable it like any other profile, but it can
              never be armed for AUTO because it matches every host. Disable every profile, the Default
              included, and the extension touches nothing.</li>
          <li><b>Profiles are saved in the Burp project.</b> Whatever you <b>save</b> comes back when
              you reopen that project; unsaved edits are lost the moment you select another profile.
              A new project starts with the Default alone, so the targets in the list are always the
              ones you put there. Persistence needs a saved project file, so it is a Burp Professional
              feature - Community's temporary projects have nowhere to store it.</li>
        </ul>
        """;

    private static final String COLOURS = """
        <ul style='margin:0 0 0 16px'>
          <li>%s <b>Proxy row</b>: a ceremony on a host you are tracking. The colour marks relevance
              only, so it does not mean the request was modified. The row comment tells you which kind
              of ceremony it is, and which profile matched: <code>Registration</code>,
              <code>Authentication</code> or <code>Options</code>.</li>
          <li>%s <b>value in the editor</b>: every value that differs from the captured original is
              highlighted, so you can see exactly <i>which</i> fields changed rather than just that
              something did. Your own edits and AUTO's rewrites are both marked, and the highlight
              survives reopening the row from Proxy history during the session.</li>
        </ul>
        """.formatted(ORANGE, CHANGED);

    private static final String AUTO = """
        <p style='margin:0 0 6px 0'>Two per-profile switches, both off until you arm them:</p>
        <ul style='margin:0 0 8px 16px'>
          <li><b>Auto-plant (reg)</b> rewrites a registration so the relying party stores a key this
              extension generated and keeps the private half of, in place of the real authenticator's.
              The account's passkey becomes yours.</li>
          <li><b>Auto re-sign (auth)</b> re-signs an authentication with that stored key, so the
              assertion still verifies after it has been tampered with. It prefers the key stored for
              that exact credential. If it holds <b>exactly one</b> key it will use that key even for a
              credential it does not match, logged as <code>MOST-RECENT FALLBACK</code>; with two or
              more keys held, an unmatched credential passes through untouched.</li>
          <li><b>Keys are held in memory for this extension session only.</b> Unloading the extension,
              reloading the jar or restarting Burp destroys them, and a credential you planted can then
              no longer be used by you or by the account's real authenticator. Finish a plant-then-forge
              run in one session, and plant only where you can re-register.</li>
        </ul>
        <p style='margin:0 0 6px 0'>Together they automate an account takeover: plant once, then every
        assertion that follows is forged for you. Arming applies them at send time in <b>Proxy and
        Repeater only</b>. Scanner, Intruder and the recorded-login replayer are deliberately excluded:
        they re-issue a request on their own schedule, and each re-issue would plant another key on the
        account. Each action is confirmed by:</p>
        <ul style='margin:0 0 8px 16px'>
          <li>an <code>[AUTO]</code> row comment;</li>
          <li>a line in <b>Extensions &rarr; Output</b>;</li>
          <li>the <b>Edited</b> flag and <b>Original vs Edited</b> view, on Proxy.</li>
        </ul>
        <p style='margin:0'><b>Scope carefully.</b> Arming is the opt-in, so an armed profile rewrites
        live traffic on <b>every host its host match covers</b>, in or out of Burp's scope. Give it a
        specific host. The <b>Default</b> profile matches every host and can never be armed, and a
        manual edit always wins over AUTO.</p>
        """;

    private final ThemedPanel root;

    public GuidePanel() {
        this.root = new ThemedPanel(new BorderLayout());
        this.root.onTheme(this::build);   // and again whenever Burp's theme flips
    }

    /** Build the tab's contents. Re-run on a theme change: the colours are baked into the HTML. */
    private void build() {
        JPanel col = new JPanel();
        col.setOpaque(false);
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        col.add(UiStyle.doc(INTRO, TEXT_W));
        section(col, "Set up a target", SETUP);
        section(col, "Locating fields", LOCATING);
        section(col, "How profiles work", PROFILES);
        section(col, "What the highlights mean", COLOURS);
        section(col, "AUTO mode", AUTO);
        col.add(Box.createVerticalStrut(10));
        col.add(UiStyle.doc(closingNote(), TEXT_W));
        col.add(Box.createVerticalGlue());

        root.removeAll();
        root.add(new JScrollPane(col), BorderLayout.CENTER);
        root.revalidate();
        root.repaint();
    }

    /** An accent heading plus its body, spaced consistently. */
    private static void section(JPanel col, String title, String bodyHtml) {
        col.add(UiStyle.heading(title, TEXT_W));
        col.add(Box.createVerticalStrut(6));
        col.add(UiStyle.doc(bodyHtml, TEXT_W));
    }

    /** The closing aside, in secondary text taken from the theme, linking out to the full reference. */
    private static String closingNote() {
        return "<span style='color:" + UiStyle.mutedHex() + "'>The full reference, including every "
                + "attack and every supported encoding, is in the README on the project's "
                + UiStyle.link(PasskeyEditorExtension.REPO_URL, "GitHub repository") + ".</span>";
    }

    private static String chip(String background, String label) {
        return "<span style='background:" + background + "; color:#000000'>&nbsp;" + label
                + "&nbsp;</span>";
    }

    public Component component() {
        root.themeChanged();   // second chance if the host changed theme without walking this tree
        return root;
    }
}
