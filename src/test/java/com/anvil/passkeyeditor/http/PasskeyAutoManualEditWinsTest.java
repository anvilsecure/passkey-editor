package com.anvil.passkeyeditor.http;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.anvil.passkeyeditor.attacks.ReSignEngine;
import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.crypto.KeyStoreService.KeyId;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.RpFixtureProfiles;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.util.EditDiffCache;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Pins the "manual edit wins over AUTO" contract: when the operator hand-forges a ceremony in the Passkey
 * Editor tab (which records the forged body to {@link EditDiffCache} at getRequest / render time, BEFORE the
 * AUTO to-be-sent seam runs), AUTO must defer to the operator's edit - never overwrite it with its own
 * plant / re-sign under the profile's default algorithm. The failing symptom this fixes: a profile armed for
 * EdDSA re-signing silently overrode a manual RS256 plant made via Proxy Intercept.
 *
 * Both scenarios use the SAME armed profile + held key (the positive-control recipe from
 * {@link PasskeyAutoComputeInertTest#armedProfileWithHeldKeyRewrites()}); the only difference is whether the
 * body was recorded as a manual forge. {@link EditDiffCache} is process-wide static state, so it is cleared
 * around each test for isolation.
 */
class PasskeyAutoManualEditWinsTest {

    private static final String AUTH_FIXTURE = "webauthn-io-auth";
    private static final String VERIFY_URL = "https://webauthn.io/authentication/verification";

    private final List<String> output = new ArrayList<>();

    @BeforeEach
    @AfterEach
    void clearCache() {
        EditDiffCache.clear(); // isolate: the cache is static/process-wide
    }

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
                    return null;
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
        try (InputStream in = PasskeyAutoManualEditWinsTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, "fixture not on classpath: " + fixture);
            return in.readAllBytes();
        }
    }

    /** An armed (auto-resign) webauthn.io profile + a signer held under the exact located KeyId - so AUTO WOULD
     *  re-sign this fixture. Returns the handler ready to drive. */
    private PasskeyAutoHandler armedHandlerHoldingKey(byte[] body) {
        ProfileRegistry reg = RpFixtureProfiles.seededRegistry();
        TargetProfile armed = reg.match("webauthn.io").withAutoResign(true);
        reg.replace("webauthn.io", armed);
        PhaseSpec spec = armed.phase(Phase.AUTH_VERIFY);
        String keyHost = ReSignEngine.originHost(body, spec);
        String credId = ReSignEngine.credIdHex(body, spec);
        KeyStoreService keyStore = new KeyStoreService();
        CoseSigner held = Es256Signer.generate();
        keyStore.storeSigner(new KeyId(keyHost, "", credId), held);
        return new PasskeyAutoHandler(capturingApi(), new Detector(new Config()), reg, keyStore);
    }

    @Test
    void manuallyForgedBodyIsDeferredToNotRewritten() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);
        // The manual editor records edited→original before this seam runs; simulate that.
        EditDiffCache.record(body, "{\"pristine\":\"original\"}".getBytes(StandardCharsets.UTF_8));

        PasskeyAutoHandler.Outcome o = armedHandlerHoldingKey(body)
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNull(o, "an armed profile must DEFER to a manually-forged body (no AUTO rewrite)");
        assertTrue(output.stream().anyMatch(l -> l.contains("AUTO skip") && l.contains("manually edited")
                && l.contains("deferred")), "the skip names the manual-edit deferral: " + output);
    }

    @Test
    void freshCeremonyIsStillReSigned() throws IOException {
        byte[] body = load(AUTH_FIXTURE);
        String bodyString = new String(body, StandardCharsets.UTF_8);
        // No EditDiffCache record: a live browser ceremony the operator did NOT hand-edit.

        PasskeyAutoHandler.Outcome o = armedHandlerHoldingKey(body)
                .compute(body, bodyString, "webauthn.io", VERIFY_URL, "POST", false, false, true);

        assertNotNull(o, "a fresh (non-manually-edited) ceremony is still auto-re-signed - the deferral is "
                + "specific to a recorded manual forge, so live AUTO is unaffected");
    }
}
