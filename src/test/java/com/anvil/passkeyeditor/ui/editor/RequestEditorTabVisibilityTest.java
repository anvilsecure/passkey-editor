package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import javax.swing.text.JTextComponent;

import org.junit.jupiter.api.Test;

/**
 * The "Passkey Editor" request tab must survive a message whose URL Burp cannot resolve.
 *
 * LIVE BUG (webauthn.io, AUTO armed): selecting the {@code /authentication/verification} row in Proxy
 * history showed no ceremony tab at all; re-selecting the row - or flipping the Original/Edited sub-view -
 * brought it back. Cause: a message editor binds request objects with no {@code HttpService}, for which
 * {@code HttpRequest.url()} throws {@link MalformedRequestException}; the editor mapped that to a {@code null}
 * URL, and the URL-scoped profile read {@code null} as "wrong endpoint" and hid the tab. The host is still
 * resolvable in that state, so the message never fell through to the (permissive) Default.
 *
 * Locks the fix from both ends: an unknowable URL keeps the tab AND keeps the matched profile driving
 * extraction (a Default downgrade would decode the wrong nesting), while a URL that IS known and wrong still
 * hides the tab - the operator's pinned verify URL stays authoritative.
 */
class RequestEditorTabVisibilityTest {

    static {
        System.setProperty("java.awt.headless", "true");
    }

    private static final String VERIFY_URL = "https://webauthn.io/authentication/verification";

    @Test
    void unresolvableUrlKeepsTheTabVisible() throws Exception {
        CeremonyRequestEditor editor = editor();
        assertTrue(editor.isEnabledFor(authRequest(null)),
                "url() throwing MalformedRequestException must not hide a detected ceremony on a tracked host");
    }

    @Test
    void unresolvableUrlStillDecodesWithTheMatchedProfile() throws Exception {
        CeremonyRequestEditor editor = editor();
        editor.setRequestResponse(authRequest(null));
        // The Default's generic candidates cannot reach webauthn.io's response.response.* nesting, so a
        // silent URL-downgrade to the Default would surface a degraded/empty decode instead of the ceremony.
        assertTrue(pane(editor).getText().contains("webauthn.get"),
                "an unknowable URL must keep the matched profile's locators, not downgrade to the Default");
    }

    @Test
    void pinnedVerifyUrlStaysAuthoritativeWhenTheUrlIsKnown() throws Exception {
        CeremonyRequestEditor editor = editor();
        assertTrue(editor.isEnabledFor(authRequest(VERIFY_URL)), "tab shows on the pinned verify URL");
        assertFalse(editor.isEnabledFor(authRequest("https://webauthn.io/profile")),
                "a KNOWN non-verify URL is still excluded");
    }

    // ---- harness -------------------------------------------------------------------------------

    private static CeremonyRequestEditor editor() {
        return new CeremonyRequestEditor(montoya(), context(), new Detector(new Config()),
                new KeyStoreService(), registry());
    }

    /** The operator's live shape: an enabled webauthn.io profile, AUTH_VERIFY pinned to POST the verify URL. */
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

    /** A webauthn.io auth-verify message whose {@code url()} yields {@code url}, or throws when it is null. */
    private static HttpRequestResponse authRequest(String url) throws Exception {
        byte[] body;
        try (InputStream in = RequestEditorTabVisibilityTest.class
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
            // Burp's own behaviour for a message with no service (burp.Zpa4.url()): throw, don't return null.
            case "url" -> {
                if (url == null) {
                    throw new MalformedRequestException("request has no URL");
                }
                yield url;
            }
            default -> null;
        });
        return proxy(HttpRequestResponse.class, (m, a) -> "request".equals(m.getName()) ? req : null);
    }

    private static MontoyaApi montoya() {
        Logging logging = proxy(Logging.class, (m, a) -> null); // logToOutput/logToError → no-op
        return proxy(MontoyaApi.class, (m, a) -> "logging".equals(m.getName()) ? logging : null);
    }

    private static EditorCreationContext context() {
        // READ_ONLY = the Proxy-history pane the bug was seen in.
        return proxy(EditorCreationContext.class,
                (m, a) -> "editorMode".equals(m.getName()) ? EditorMode.READ_ONLY : null);
    }

    private static JTextComponent pane(CeremonyRequestEditor editor) throws Exception {
        java.lang.reflect.Field f = CeremonyRequestEditor.class.getDeclaredField("jsonPane");
        f.setAccessible(true);
        return (JTextComponent) f.get(editor);
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
}
