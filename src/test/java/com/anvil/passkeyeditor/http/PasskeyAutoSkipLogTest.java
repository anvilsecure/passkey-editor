package com.anvil.passkeyeditor.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Observability pin for the AUTO pass-through (the gap the live re-test surfaced: an Enabled-but-not-armed
 * webauthn.io ceremony left NOTHING in the Output tab, so the operator couldn't tell the extension had even
 * seen it). The contract this pins:
 *   - Enabled + tracked + NOT armed ⇒ a byte-for-byte pass-through that ALSO logs one "AUTO skip …
 *       passed through unchanged" line - the operator deliberately tracks this host, so the skip is signal.
 *   - Disabled ⇒ a pass-through that logs NOTHING (a disabled host is fully inert / silent).
 * Both paths still return {@code compute(...) == null} (no rewrite); only the logging differs - the freeze-safe
 * no-op proven by {@link PasskeyAutoComputeInertTest} is untouched.
 */
class PasskeyAutoSkipLogTest {

    private static final String AUTH_FIXTURE = "webauthn-io-auth";
    private static final String VERIFY_URL = "https://webauthn.io/authentication/verification";

    /** Captures every logToOutput(String) the handler emits, so we can assert the skip line (or its absence). */
    private final List<String> output = new ArrayList<>();

    private MontoyaApi capturingApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                Logging.class.getClassLoader(), new Class<?>[]{Logging.class},
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, args);
                    }
                    if ("logToOutput".equals(method.getName()) && args != null && args.length == 1
                            && args[0] instanceof String s) {
                        output.add(s);
                    }
                    return null; // logToOutput / logToError are void
                });
        InvocationHandler h = (proxy, method, args) -> {
            if (method.getDeclaringClass() == Object.class) {
                return objectMethod(proxy, method, args);
            }
            if ("logging".equals(method.getName())) {
                return logging;
            }
            throw new UnsupportedOperationException("compute() must touch only logging(): " + method.getName());
        };
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class}, h);
    }

    private static Object objectMethod(Object proxy, Method method, Object[] args) {
        return switch (method.getName()) {
            case "equals" -> proxy == args[0];
            case "hashCode" -> System.identityHashCode(proxy);
            case "toString" -> "MontoyaApiDouble";
            default -> null;
        };
    }

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = PasskeyAutoSkipLogTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, "fixture not on classpath: " + fixture);
            return in.readAllBytes();
        }
    }

    private PasskeyAutoHandler handler(ProfileRegistry registry) {
        return new PasskeyAutoHandler(capturingApi(), new Detector(new Config()), registry, new KeyStoreService());
    }

    @Test
    void enabledButNotArmedTrackedCeremonyLogsAPassThroughSkip() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);
        ProfileRegistry reg = RpFixtureProfiles.seededRegistry(); // webauthn.io is enabled, AUTO off (not armed)

        PasskeyAutoHandler.Outcome o = handler(reg)
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNull(o, "enabled-but-not-armed ⇒ still a byte-for-byte pass-through (no rewrite)");
        assertEquals(1, output.size(), "exactly one Output line for the tracked-but-not-armed ceremony: " + output);
        String line = output.get(0);
        assertTrue(line.contains("AUTO skip") && line.contains("Authentication") && line.contains("not armed")
                && line.contains("passed through"), "names the skip + reason: " + line);
        assertTrue(line.contains("webauthn.io"), "names the tracked host/profile: " + line);
    }

    @Test
    void disabledProfileStaysSilent() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);
        ProfileRegistry reg = RpFixtureProfiles.seededRegistry();
        TargetProfile io = reg.match("webauthn.io");
        reg.replace("webauthn.io", io.withEnabled(false)); // disabled ⇒ fully inert

        PasskeyAutoHandler.Outcome o = handler(reg)
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNull(o, "disabled ⇒ pass-through");
        assertTrue(output.isEmpty(), "a disabled host is fully inert - nothing logged: " + output);
    }
}
