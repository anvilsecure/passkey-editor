package com.anvil.passkeyeditor.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.logging.Logging;

import com.anvil.passkeyeditor.attacks.ReSignEngine;
import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.crypto.KeyStoreService.KeyId;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.TargetProfile;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Bug 2 - the DECISIVE headless proof that the AUTO core is a byte-for-byte no-op on inert traffic, so
 * the "webauthn.io auth breaks with HTML-where-JSON while the profile is DISABLED" symptom is NOT an extension
 * fail-open (verdict (a): planted-credential residue, server-side). This is the single most valuable gap the
 * audit surfaced: the just-landed dual seam ({@link PasskeyAutoHandler} as both {@code ProxyRequestHandler}
 * and {@code HttpHandler}) shares one Burp-action-free {@code compute()}, and {@code compute(...) == null} is the
 * pass-through contract both seams obey ({@code if (o == null) return continueWith(request)}; {@code withBody} is
 * reached only on a non-null {@code Outcome}). We drive {@code compute()} directly over the REAL webauthn.io auth
 * fixture and assert {@code null} on every inert path.
 *
 * The {@link MontoyaApi} double is a {@link Proxy} whose ONLY working method is {@code logging()} (a no-op
 * {@link Logging}); any other Burp call throws - so the test also proves {@code compute()} reads nothing else off
 * Burp. A positive control shows the same core DOES rewrite (ORANGE, body changed) when a profile is armed and a
 * correctly-keyed signer is held, so the {@code null}s above are meaningful (the harness can see a real rewrite).
 *
 * Note on the seam wrappers: {@code handleRequestToBeSent} / {@code handleHttpRequestToBeSent} call
 * {@code ByteArray.byteArray(...)} and {@code continueWith(...)}, which require Burp's runtime factory and so
 * cannot be exercised headlessly - but they add no decision logic over {@code compute()} (the {@code o == null}
 * branch is a trivial original-pass-through), which is exactly what this test pins.
 */
class PasskeyAutoComputeInertTest {

    private static final String AUTH_FIXTURE = "webauthn-io-auth";
    private static final String VERIFY_URL = "https://webauthn.io/authentication/verification";

    // ---- a MontoyaApi double whose only live method is logging() (no-op); any other call is forbidden -------

    /** Records the MontoyaApi method names compute() invokes, so we can assert it touches ONLY logging(). */
    private final List<String> apiCalls = new ArrayList<>();

    private MontoyaApi montoyaDouble() {
        Logging noopLogging = (Logging) Proxy.newProxyInstance(
                Logging.class.getClassLoader(), new Class<?>[]{Logging.class},
                (proxy, method, args) -> objectOrNull(proxy, method, args)); // logToOutput/logToError → no-op
        InvocationHandler h = (proxy, method, args) -> {
            if (method.getDeclaringClass() == Object.class) {
                return objectMethod(proxy, method, args);
            }
            apiCalls.add(method.getName());
            if ("logging".equals(method.getName())) {
                return noopLogging;
            }
            throw new UnsupportedOperationException("compute() must not touch MontoyaApi." + method.getName()
                    + "() on any path - only logging() is permitted");
        };
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class}, h);
    }

    /** Object-method handler for a proxy that returns null for every interface method (no-op Logging). */
    private static Object objectOrNull(Object proxy, Method method, Object[] args) {
        return method.getDeclaringClass() == Object.class ? objectMethod(proxy, method, args) : null;
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
        try (InputStream in = PasskeyAutoComputeInertTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, "fixture not on classpath: " + fixture);
            return in.readAllBytes();
        }
    }

    private PasskeyAutoHandler handler(ProfileRegistry registry, KeyStoreService keyStore) {
        return new PasskeyAutoHandler(montoyaDouble(), new Detector(new Config()), registry, keyStore);
    }

    private void assertOnlyLoggingTouched() {
        for (String call : apiCalls) {
            assertEquals("logging", call, "compute() touched a forbidden MontoyaApi method: " + call);
        }
    }

    // ---- negative scenarios: every inert path is a byte-for-byte pass-through (compute() == null) -----------

    @Test
    void disabledProfileIsPassThrough() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);

        // Prove the body IS a detected GET ceremony, so the null below is the matchAuto GATE's doing - NOT a
        // detector miss (a right answer for the wrong reason).
        assertEquals(CeremonyType.GET, new Detector(new Config()).detect(bodyString),
                "webauthn-io-auth is a detected GET ceremony");

        ProfileRegistry reg = RpFixtureProfiles.seededRegistry();
        TargetProfile io = reg.match("webauthn.io");
        reg.replace("webauthn.io", io.withEnabled(false)); // disabled ⇒ compact ctor also forces AUTO off

        PasskeyAutoHandler.Outcome o = handler(reg, new KeyStoreService())
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNull(o, "a DISABLED webauthn.io profile ⇒ AUTO is inert ⇒ byte-for-byte pass-through");
        assertOnlyLoggingTouched();
    }

    @Test
    void unmatchedHostIsPassThrough() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);
        ProfileRegistry reg = RpFixtureProfiles.seededRegistry(); // webauthn.io enabled, but the host below is unprofiled

        PasskeyAutoHandler.Outcome o = handler(reg, new KeyStoreService())
                .compute(body, bodyString, "localhost", "https://localhost/assertion/result", "POST",
                        false, false, true);

        assertNull(o, "an UNPROFILED host falls to the Default, which matchAuto never returns ⇒ pass-through");
        assertOnlyLoggingTouched();
    }

    @Test
    void everyProfileDisabledIsPassThrough() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);

        // Belt-and-braces: disable EVERY listed profile AND the Default - nothing matches anywhere.
        List<TargetProfile> allDisabled = new ArrayList<>();
        for (TargetProfile p : RpFixtureProfiles.all()) {
            allDisabled.add(p.withEnabled(false));
        }
        ProfileRegistry reg = new ProfileRegistry(BuiltinProfiles.defaultProfile().withEnabled(false), allDisabled);

        PasskeyAutoHandler.Outcome o = handler(reg, new KeyStoreService())
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNull(o, "all profiles disabled (incl. Default) ⇒ nothing matches ⇒ pass-through");
        assertOnlyLoggingTouched();
    }

    // ---- positive control: the same core DOES rewrite when armed + a correctly-keyed signer is held ---------

    @Test
    void armedProfileWithHeldKeyRewrites() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);

        ProfileRegistry reg = RpFixtureProfiles.seededRegistry();
        TargetProfile armed = reg.match("webauthn.io").withAutoResign(true);
        reg.replace("webauthn.io", armed);

        // Pre-store a held signer under the EXACT KeyId the handler resolves (origin host + located credId), so
        // resolveHeld takes the exact-match path - NOT the size<=1 most-recent fallback - proving a correctly
        // keyed re-sign rather than a coincidence.
        PhaseSpec spec = armed.phase(Phase.AUTH_VERIFY);
        String keyHost = ReSignEngine.originHost(body, spec);
        String credId = ReSignEngine.credIdHex(body, spec);
        assertNotNull(credId, "the webauthn.io profile locates a credId (response.rawId) in the fixture");
        KeyStoreService keyStore = new KeyStoreService();
        CoseSigner held = Es256Signer.generate();
        keyStore.storeSigner(new KeyId(keyHost, "", credId), held);

        PasskeyAutoHandler.Outcome o = handler(reg, keyStore)
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNotNull(o, "armed + held key ⇒ the core DOES rewrite (so the null assertions above are meaningful)");
        assertEquals(HighlightColor.ORANGE, o.color(), "an auto re-sign is annotated ORANGE (one flat passkey-flow colour)");
        assertFalse(Arrays.equals(body, o.body()), "the re-signed body differs from the original");
        assertTrue(o.note().startsWith("[AUTO] Authentication: "),
                "the re-sign note is the shrunk [AUTO] relevance mark: " + o.note());
        assertFalse(o.note().contains("host="),
                "verbose alg / host / credId detail lives in the Output log, not the row note: " + o.note());
        assertOnlyLoggingTouched();
    }
}
