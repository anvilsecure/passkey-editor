package com.anvil.passkeyeditor.ui.editor;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;

import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The pure generic-JSON renderer / differ / UV-downgrade behind the options-response Passkey Editor tab
 * ({@link OptionsJson}): parse, pretty render with spans (including ARRAYS, which the WebAuthn-specific
 * {@link CeremonyJson} does not expand), leaf diff by path, and the UV-downgrade preset. The editor is a thin
 * renderer over these, so green here == correct tab behaviour.
 */
class OptionsJsonTest {

    private static final String AUTH_OPTS =
            "{\"challenge\":\"abc\",\"rpId\":\"webauthn.io\",\"userVerification\":\"preferred\","
            + "\"allowCredentials\":[{\"id\":\"AA\",\"type\":\"public-key\"}],\"timeout\":60000}";

    private static final String REG_OPTS =
            "{\"challenge\":\"abc\",\"rp\":{\"id\":\"webauthn.io\",\"name\":\"webauthn.io\"},"
            + "\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}],"
            + "\"authenticatorSelection\":{\"residentKey\":\"required\",\"userVerification\":\"required\"}}";

    @Test
    void parseValidAndInvalid() {
        assertNotNull(OptionsJson.parse(AUTH_OPTS));
        assertNull(OptionsJson.parse("{ not valid"));
        assertNull(OptionsJson.parse((String) null));
        assertNull(OptionsJson.parse((byte[]) null));
        assertNull(OptionsJson.parse("   "));
    }

    @Test
    void rendersArraysPrettyNotOneLine() {
        OptionsJson.Rendered r = OptionsJson.render(OptionsJson.parse(REG_OPTS), Set.of());
        assertTrue(r.text().contains("\"pubKeyCredParams\""), r.text());
        assertTrue(r.text().contains("[\n"), "arrays are expanded multi-line, not a single-line toString: " + r.text());
        assertTrue(r.text().contains("\"alg\""), "array element members are rendered");
        assertFalse(r.keys().isEmpty());
        assertFalse(r.strings().isEmpty());
        assertFalse(r.scalars().isEmpty(), "the negative alg numbers are scalar spans");
    }

    @Test
    void changedLeafPathsObjectMember() {
        JsonElement a = OptionsJson.parse(AUTH_OPTS);
        JsonElement b = OptionsJson.parse(AUTH_OPTS);
        b.getAsJsonObject().addProperty("userVerification", "discouraged");
        Set<String> changed = OptionsJson.changedLeafPaths(a, b);
        assertEquals(Set.of("userVerification"), changed);
    }

    @Test
    void changedLeafPathsArrayElementByIndex() {
        Set<String> changed = OptionsJson.changedLeafPaths(
                OptionsJson.parse("{\"a\":[1,2,3]}"), OptionsJson.parse("{\"a\":[1,9,3]}"));
        assertEquals(Set.of("a.1"), changed, "an array element diff is addressed by index");
    }

    @Test
    void userVerificationTopLevelAndNestedAndAbsent() {
        assertEquals("preferred", OptionsJson.userVerification(OptionsJson.parse(AUTH_OPTS)));
        assertEquals("required", OptionsJson.userVerification(OptionsJson.parse(REG_OPTS)));
        assertNull(OptionsJson.userVerification(OptionsJson.parse("{\"challenge\":\"x\"}")));
        assertNull(OptionsJson.userVerification(null));
    }

    @Test
    void downgradeUvTopLevel() {
        JsonElement t = OptionsJson.parse(AUTH_OPTS);
        assertTrue(OptionsJson.downgradeUv(t));
        assertEquals("discouraged", OptionsJson.userVerification(t));
        assertFalse(OptionsJson.downgradeUv(t), "already discouraged -> no change");
    }

    @Test
    void downgradeUvNestedUnderAuthenticatorSelection() {
        JsonElement t = OptionsJson.parse(REG_OPTS);
        assertTrue(OptionsJson.downgradeUv(t));
        assertEquals("discouraged", t.getAsJsonObject().getAsJsonObject("authenticatorSelection")
                .get("userVerification").getAsString());
    }

    @Test
    void downgradeUvAbsentIsNoChange() {
        assertFalse(OptionsJson.downgradeUv(OptionsJson.parse("{\"challenge\":\"x\"}")));
        assertFalse(OptionsJson.downgradeUv(null));
    }

    @Test
    void toWireBytesIsCompactAndRoundTrips() {
        JsonElement t = OptionsJson.parse(AUTH_OPTS);
        byte[] wire = OptionsJson.toWireBytes(t);
        assertFalse(new String(wire, UTF_8).contains("\n"), "wire form is compact");
        assertEquals(t, OptionsJson.parse(wire), "compact bytes round-trip to the same tree");
    }

    @Test
    void renderAmberHighlightsExactlyTheChangedLeaf() {
        JsonElement a = OptionsJson.parse(AUTH_OPTS);
        JsonElement b = OptionsJson.parse(AUTH_OPTS);
        b.getAsJsonObject().addProperty("userVerification", "discouraged");
        Set<String> changed = OptionsJson.changedLeafPaths(a, b);
        OptionsJson.Rendered r = OptionsJson.render(b, changed);
        assertEquals(1, r.changed().size());
        OptionsJson.Span s = r.changed().get(0);
        assertTrue(r.text().substring(s.start(), s.end()).contains("discouraged"),
                "the amber span covers the changed value");
    }
}
