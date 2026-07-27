package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.detect.Detector;

import com.google.gson.JsonElement;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The options-phase gate on real relying-party bytes - the analog of
 * {@link com.anvil.passkeyeditor.codec.RealFixtureByteIdentityTest} for the UV downgrade.
 *
 * {@link OptionsJsonTest} exercises the same operations on hand-modeled JSON; these run on
 * {@code generate-*-options} responses captured verbatim from a controlled relying party
 * (SimpleWebAuthn - zero PII, synthetic challenge and credentials). That is the discipline that caught the
 * original detection bug, where the literal markers turned out to be absent on the wire: prove detection and
 * the downgrade against the exact bytes an RP emits, including its real key set and the
 * {@code requireResidentKey} / {@code hints} members the synthetic fixtures omit.
 */
class RealOptionsFixtureTest {

    private final Detector detector = new Detector(new Config());

    private static String loadFixture(String name) {
        try (InputStream in = RealOptionsFixtureTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void realAuthOptionsDetectAndDowngrade() {
        assertDetectAndDowngrade("auth-options-clean.json", Detector.OptionsKind.AUTHENTICATION);
    }

    @Test
    void realRegOptionsDetectAndDowngrade() {
        assertDetectAndDowngrade("reg-options-clean.json", Detector.OptionsKind.REGISTRATION);
    }

    private void assertDetectAndDowngrade(String fixture, Detector.OptionsKind expectedKind) {
        String body = loadFixture(fixture);

        // 1) Detection fires correctly on the real bytes.
        assertTrue(detector.isOptions(body), fixture + " must be recognised as options");
        assertEquals(expectedKind, detector.detectOptions(body));

        // 2) The fixture ships userVerification "preferred"; the downgrade lowers exactly that. This is the
        //    path the Attacks menu actually runs - a tree edit, so the response is re-serialised. (An
        //    UNEDITED options response is still forwarded byte-identically; that is pinned elsewhere.)
        JsonElement tree = OptionsJson.parse(body);
        assertNotNull(tree, "real options body must parse");
        assertEquals("preferred", OptionsJson.userVerification(tree));
        assertTrue(OptionsJson.downgradeUv(tree), "a 'preferred' policy must be downgraded");
        assertEquals("discouraged", OptionsJson.userVerification(tree));

        // 3) ONLY userVerification changed: every other leaf - the real challenge, the full credential set,
        //    requireResidentKey, hints, extensions - is untouched.
        JsonElement original = OptionsJson.parse(body);
        assertEquals(java.util.Set.of(uvPath(body)), OptionsJson.changedLeafPaths(original, tree),
                "the downgrade must touch exactly one leaf");

        // 4) The downgraded body still classifies as the same options kind (survives re-binding).
        String out = new String(OptionsJson.toWireBytes(tree), StandardCharsets.UTF_8);
        assertEquals(expectedKind, detector.detectOptions(out));
        assertTrue(out.contains("\"discouraged\""), out);
    }

    /** Where userVerification sits in this fixture: top level, or nested under authenticatorSelection. */
    private static String uvPath(String body) {
        JsonElement root = OptionsJson.parse(body);
        return root != null && root.isJsonObject() && root.getAsJsonObject().has(OptionsJson.UV_KEY)
                ? OptionsJson.UV_KEY
                : "authenticatorSelection." + OptionsJson.UV_KEY;
    }
}
