package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;

import javax.swing.AbstractButton;
import javax.swing.text.JTextComponent;

import org.junit.jupiter.api.Test;

/**
 * The options-response tab must honour the editor's {@link EditorMode}. In READ_ONLY (Proxy HTTP history,
 * Scanner) Burp never calls {@code getResponse()}, so a live "Attacks ▾ → Downgrade UV" would silently
 * discard the edit and a stray keystroke could overwrite the read-only diff view; the pane must stay
 * non-editable and the Attacks button disabled — matching {@link CeremonyRequestEditor}'s {@code !readOnly}
 * gate. In DEFAULT (Repeater / Proxy intercept) both are interactive. Runs headless with Montoya doubles,
 * same {@link Proxy} pattern as the AUTO-handler tests.
 */
class ResponseEditorReadOnlyTest {

    static {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void readOnlyModeDisablesEditingAndAttacks() throws Exception {
        CeremonyResponseEditor editor = editorFor(EditorMode.READ_ONLY);
        editor.setRequestResponse(optionsResponse());

        assertFalse(pane(editor).isEditable(), "READ_ONLY options pane must not accept typing");
        assertFalse(attacksButton(editor).isEnabled(), "READ_ONLY must disable the Attacks menu");
    }

    @Test
    void defaultModeKeepsEditingAndAttacksInteractive() throws Exception {
        CeremonyResponseEditor editor = editorFor(EditorMode.DEFAULT);
        editor.setRequestResponse(optionsResponse());

        assertTrue(pane(editor).isEditable(), "an editable (DEFAULT) options pane accepts edits");
        assertTrue(attacksButton(editor).isEnabled(), "DEFAULT mode enables the Attacks menu");
    }

    // ---- harness -------------------------------------------------------------------------------

    private static CeremonyResponseEditor editorFor(EditorMode mode) {
        return new CeremonyResponseEditor(montoya(), context(mode), new Detector(new Config()),
                RpFixtureProfiles.seededRegistry());
    }

    private static HttpRequestResponse optionsResponse() throws Exception {
        byte[] body;
        try (InputStream in = ResponseEditorReadOnlyTest.class
                .getResourceAsStream("/fixtures/auth-options-clean.json")) {
            assertNotNull(in, "fixture not on classpath: auth-options-clean.json");
            body = in.readAllBytes();
        }
        ByteArray ba = proxy(ByteArray.class, (m, a) -> switch (m.getName()) {
            case "getBytes" -> body;
            case "length" -> body.length;
            default -> null;
        });
        HttpResponse resp = proxy(HttpResponse.class, (m, a) -> switch (m.getName()) {
            case "body" -> ba;
            case "bodyToString" -> new String(body, StandardCharsets.UTF_8);
            default -> null;
        });
        return proxy(HttpRequestResponse.class, (m, a) -> switch (m.getName()) {
            case "hasResponse" -> Boolean.TRUE;
            case "response" -> resp;
            default -> null;
        });
    }

    private static MontoyaApi montoya() {
        Logging logging = proxy(Logging.class, (m, a) -> null); // logToOutput/logToError → no-op
        return proxy(MontoyaApi.class, (m, a) -> "logging".equals(m.getName()) ? logging : null);
    }

    private static EditorCreationContext context(EditorMode mode) {
        return proxy(EditorCreationContext.class, (m, a) -> "editorMode".equals(m.getName()) ? mode : null);
    }

    /** Read-only body-agnostic invocation; Object methods handled so the proxy is a valid Object. */
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

    private static JTextComponent pane(CeremonyResponseEditor editor) throws Exception {
        return (JTextComponent) field(editor, "jsonPane");
    }

    private static AbstractButton attacksButton(CeremonyResponseEditor editor) throws Exception {
        return (AbstractButton) field(editor, "attacksButton");
    }

    private static Object field(CeremonyResponseEditor editor, String name) throws Exception {
        Field f = CeremonyResponseEditor.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(editor);
    }
}
