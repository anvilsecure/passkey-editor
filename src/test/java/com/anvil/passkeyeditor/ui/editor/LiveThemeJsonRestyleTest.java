package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.profile.UrlMatch;
import com.anvil.passkeyeditor.ui.Palette;

import java.awt.Color;
import java.awt.Component;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The decoded JSON keeps its syntax colours in the document as character attributes, and a look
 * and feel change does not touch those any more than it touches a {@code setForeground}. On Intercept,
 * where one message stays bound while the operator works on it, nothing forces a re-render - so the
 * decode sat there in the previous theme's palette: dark-blue keys and dark-red strings on a dark
 * background.
 *
 * Re-rendering is not the fix. {@code renderJson()} rebuilds the text from the model and would throw
 * away whatever is part-way typed, which on Intercept is the likeliest thing to be happening. The spans
 * are re-painted onto the existing text instead. These tests pin both halves: the colours follow the
 * theme, and the operator's text, caret and undo history come through untouched.
 */
class LiveThemeJsonRestyleTest {

    private static final Color DARK_BG = new Color(0x3C, 0x3F, 0x41);
    private static final Color LIGHT_BG = new Color(0xF2, 0xF2, 0xF2);

    @AfterEach
    void resetTheme() {
        UIManager.put("Panel.background", null);
        UIManager.put("TextPane.background", null);
        UIManager.put("TextPane.foreground", null);
    }

    private static void theme(Color background) {
        UIManager.put("Panel.background", background);
        UIManager.put("TextPane.background", background);
    }

    @Test
    void jsonSyntaxColoursFollowALiveThemeSwitch() throws Exception {
        theme(LIGHT_BG);
        CeremonyRequestEditor editor = editor();
        editor.setRequestResponse(authRequest());
        JTextPane pane = pane(editor);
        pane.setBackground(LIGHT_BG);          // stand in for the LaF's text-pane background

        Color keyOnLight = firstKeyColour(pane);
        assertEquals(Palette.jsonKey(LIGHT_BG), keyOnLight, "expected the light JSON key colour to start");

        switchThemeTo(DARK_BG, pane, editor.uiComponent());

        Color keyOnDark = firstKeyColour(pane);
        assertNotEquals(keyOnLight, keyOnDark, "the JSON kept the light theme's syntax colours");
        assertEquals(Palette.jsonKey(DARK_BG), keyOnDark, "the JSON is not on the dark palette");
        assertTrue(contrast(keyOnDark, DARK_BG) >= 4.5, "JSON keys are only "
                + String.format("%.2f", contrast(keyOnDark, DARK_BG)) + ":1 after the switch");
    }

    /** The whole point of re-painting instead of re-rendering: an in-flight edit must survive. */
    @Test
    void anInFlightEditSurvivesAThemeSwitch() throws Exception {
        theme(LIGHT_BG);
        CeremonyRequestEditor editor = editor();
        editor.setRequestResponse(authRequest());
        JTextPane pane = pane(editor);
        pane.setBackground(LIGHT_BG);

        // The operator types into the decode, mid-edit, exactly as on Intercept.
        pane.setEditable(true);
        StyledDocument doc = (StyledDocument) pane.getDocument();
        doc.insertString(0, "TYPED-BY-OPERATOR", null);
        String afterTyping = doc.getText(0, doc.getLength());

        switchThemeTo(DARK_BG, pane, editor.uiComponent());

        assertEquals(afterTyping, doc.getText(0, doc.getLength()),
                "the operator's in-flight edit was destroyed by the theme change");
    }

    /**
     * The re-colouring itself must not disturb the caret. Driven through the display-path check rather
     * than a full tree walk on purpose: Swing reinstalls a text component's caret during {@code
     * updateComponentTreeUI} and resets it to 0 on its own, so going through that would measure Swing
     * rather than this code.
     */
    @Test
    void restylingLeavesTheCaretAlone() throws Exception {
        theme(LIGHT_BG);
        CeremonyRequestEditor editor = editor();
        editor.setRequestResponse(authRequest());
        JTextPane pane = pane(editor);
        pane.setBackground(LIGHT_BG);
        Color keyOnLight = firstKeyColour(pane);
        pane.setCaretPosition(42);

        theme(DARK_BG);
        pane.setBackground(DARK_BG);
        editor.uiComponent();                 // the second-chance check on the display path
        for (int i = 0; i < 3; i++) {
            SwingUtilities.invokeAndWait(() -> { });
        }

        assertNotEquals(keyOnLight, firstKeyColour(pane), "the display path did not re-colour the JSON");
        assertEquals(42, pane.getCaretPosition(), "re-colouring moved the operator's caret");
    }

    // ---- harness -----------------------------------------------------------------------------------

    /** What a host does on a theme change: new defaults, then a walk over the component tree. */
    private static void switchThemeTo(Color background, JTextPane pane, Component root) throws Exception {
        theme(background);
        pane.setBackground(background);        // the LaF would repaint the pane itself
        SwingUtilities.updateComponentTreeUI(root);
        for (int i = 0; i < 3; i++) {
            SwingUtilities.invokeAndWait(() -> { });
        }
    }

    /**
     * The colour of the first JSON key: keys are drawn bold with no background of their own, which
     * separates them from the changed-value runs (also bold, but carrying the amber background).
     */
    private static Color firstKeyColour(JTextPane pane) {
        StyledDocument doc = (StyledDocument) pane.getDocument();
        for (int i = 0; i < doc.getLength(); i++) {
            AttributeSet a = doc.getCharacterElement(i).getAttributes();
            if (StyleConstants.isBold(a)
                    && !a.isDefined(StyleConstants.Background)
                    && a.isDefined(StyleConstants.Foreground)) {
                return StyleConstants.getForeground(a);
            }
        }
        throw new AssertionError("no styled JSON key found - the harness is broken");
    }

    private static CeremonyRequestEditor editor() {
        return new CeremonyRequestEditor(montoya(), context(), new Detector(new Config()),
                new KeyStoreService(), registry());
    }

    private static ProfileRegistry registry() {
        PhaseSpec auth = new PhaseSpec(Map.of(
                Field.CLIENT_DATA_JSON, FieldLocator.of("response.response.clientDataJSON"),
                Field.AUTHENTICATOR_DATA, FieldLocator.of("response.response.authenticatorData"),
                Field.SIGNATURE, FieldLocator.of("response.response.signature")),
                new UrlMatch(UrlMatch.Kind.CONTAINS, "/authentication/verification", "POST"));
        TargetProfile rp = new TargetProfile("webauthn.io", "webauthn.io", HostMatch.exact("webauthn.io"),
                Map.of(Phase.AUTH_VERIFY, auth));
        return new ProfileRegistry(BuiltinProfiles.defaultProfile(), List.of(rp));
    }

    private static HttpRequestResponse authRequest() throws Exception {
        byte[] body;
        try (InputStream in = LiveThemeJsonRestyleTest.class
                .getResourceAsStream("/fixtures/webauthn-io-auth.json")) {
            assertNotNull(in, "fixture not on classpath: webauthn-io-auth.json");
            body = in.readAllBytes();
        }
        ByteArray ba = proxy(ByteArray.class, (m, a) -> switch (m.getName()) {
            case "getBytes" -> body;
            case "length" -> body.length;
            default -> null;
        });
        HttpService service = proxy(HttpService.class, (m, a) -> switch (m.getName()) {
            case "host" -> "webauthn.io";
            case "port" -> 443;
            case "secure" -> Boolean.TRUE;
            default -> null;
        });
        HttpRequest req = proxy(HttpRequest.class, (m, a) -> switch (m.getName()) {
            case "body" -> ba;
            case "bodyToString" -> new String(body, StandardCharsets.UTF_8);
            case "httpService" -> service;
            case "method" -> "POST";
            case "path" -> "/authentication/verification";
            case "url" -> "https://webauthn.io/authentication/verification";
            default -> null;
        });
        return proxy(HttpRequestResponse.class, (m, a) -> "request".equals(m.getName()) ? req : null);
    }

    private static MontoyaApi montoya() {
        Logging logging = proxy(Logging.class, (m, a) -> null);
        return proxy(MontoyaApi.class, (m, a) -> "logging".equals(m.getName()) ? logging : null);
    }

    /** DEFAULT is the editable (Repeater/Intercept) context - where an in-flight edit is at stake. */
    private static EditorCreationContext context() {
        return proxy(EditorCreationContext.class,
                (m, a) -> "editorMode".equals(m.getName()) ? EditorMode.DEFAULT : null);
    }

    private static JTextPane pane(CeremonyRequestEditor editor) throws Exception {
        java.lang.reflect.Field f = CeremonyRequestEditor.class.getDeclaredField("jsonPane");
        f.setAccessible(true);
        return (JTextPane) f.get(editor);
    }

    private interface Call {
        Object apply(Method method, Object[] args);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> iface, Call call) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, (p, m, a) -> {
            if (m.getDeclaringClass() == Object.class) {
                return switch (m.getName()) {
                    case "equals" -> p == a[0];
                    case "hashCode" -> System.identityHashCode(p);
                    case "toString" -> iface.getSimpleName() + "Double";
                    default -> null;
                };
            }
            return call.apply(m, a);
        });
    }

    private static double contrast(Color a, Color b) {
        double la = luminance(a);
        double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    private static double luminance(Color c) {
        return 0.2126 * channel(c.getRed()) + 0.7152 * channel(c.getGreen()) + 0.0722 * channel(c.getBlue());
    }

    private static double channel(int v) {
        double s = v / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }
}
