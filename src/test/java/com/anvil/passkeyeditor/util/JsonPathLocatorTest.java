package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.WrapperCodec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * gate: the path-addressed locator ({@link JsonValueEditor#findStringValueSpanAtPath})
 * extracts every WebAuthn field from the real captured wire bytes of five structurally-distinct
 * RPs - the shapes that defeat today's one-{@code response}-layer extraction. For each field this
 * asserts (1) the span is byte-exact (re-splicing the located bytes reproduces the body) and (2) the
 * path points at the right field (the existing {@link WrapperCodec} unwraps it to a sane clientDataJSON
 * / attestationObject / authData / signature). No per-RP code - only per-RP paths as data.
 *
 * Fixtures live in {@code src/test/resources/fixtures}.
 */
class JsonPathLocatorTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = JsonPathLocatorTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, "fixture not on classpath: " + fixture);
            return in.readAllBytes();
        }
    }

    /** Locate {@code path} in {@code fixture}, assert the span is byte-exact, return the unwrapped inner bytes. */
    private static byte[] locateUnwrap(String fixture, String path) throws IOException {
        byte[] body = load(fixture);
        int[] span = JsonValueEditor.findStringValueSpanAtPath(body, JsonPath.parse(path));
        assertNotNull(span, () -> "no value located at " + path + " in " + fixture);
        byte[] value = Arrays.copyOfRange(body, span[0], span[1]);
        // Span exactness: re-splicing the same bytes must reproduce the body byte-for-byte.
        assertArraysEqual(body, JsonValueEditor.splice(body, span, value), fixture + " @ " + path + " splice round-trip");
        return CODEC.unwrap(value).inner();
    }

    private static void assertClientData(String fixture, String path, String type, String origin) throws IOException {
        String cdj = new String(locateUnwrap(fixture, path), StandardCharsets.UTF_8);
        assertTrue(cdj.contains("\"type\":\"" + type + "\""), () -> fixture + " clientData type: " + cdj);
        assertTrue(cdj.contains("\"origin\":\"" + origin + "\""), () -> fixture + " clientData origin: " + cdj);
    }

    private static void assertArraysEqual(byte[] expected, byte[] actual, String msg) {
        assertTrue(Arrays.equals(expected, actual), msg);
    }

    // ---- Registration: clientDataJSON + attestationObject, at each RP's path ---------------------

    @Test
    void registrationFieldsLocateAcrossRps() throws IOException {
        record Rp(String fx, String base, String origin) {}
        Rp[] rps = {
            new Rp("webauthn-io-reg",       "response.response",                    "https://webauthn.io"),
            new Rp("passkeys-debugger-reg", "[2].response.response",                "https://www.passkeys-debugger.io"),
            new Rp("passkeys-io-reg",       "input_data.public_key.response",       "https://www.passkeys.io"),
            new Rp("webauthn-lubu-reg",     "",                                     "https://webauthn.lubu.ch"),
        };
        for (Rp rp : rps) {
            String prefix = rp.base().isEmpty() ? "" : rp.base() + ".";
            assertClientData(rp.fx(), prefix + "clientDataJSON", "webauthn.create", rp.origin());
            byte[] att = locateUnwrap(rp.fx(), prefix + "attestationObject");
            assertEquals((byte) 0xA3, att[0], () -> rp.fx() + " attestationObject should be a CBOR map(3)");
        }
        // Yubico nests each field's value behind a {"$base64":"…"} envelope key - same locator, one more hop.
        assertClientData("yubico-demo-reg", "attestation.clientDataJSON.$base64", "webauthn.create", "https://demo.yubico.com");
        byte[] yubicoAtt = locateUnwrap("yubico-demo-reg", "attestation.attestationObject.$base64");
        assertEquals((byte) 0xA3, yubicoAtt[0], "yubico attestationObject should be a CBOR map(3)");
    }

    // ---- Authentication: clientDataJSON + authenticatorData + signature, at each RP's path --------

    @Test
    void authenticationFieldsLocateAcrossRps() throws IOException {
        record Rp(String fx, String base, String origin, String cdField, String adField, String sigField) {}
        Rp[] rps = {
            new Rp("webauthn-io-auth",       "response.response",              "https://webauthn.io",
                    "clientDataJSON", "authenticatorData", "signature"),
            new Rp("passkeys-debugger-auth", "[2].response.response",          "https://www.passkeys-debugger.io",
                    "clientDataJSON", "authenticatorData", "signature"),
            new Rp("passkeys-io-auth",       "input_data.assertion_response.response", "https://www.passkeys.io",
                    "clientDataJSON", "authenticatorData", "signature"),
            new Rp("webauthn-lubu-auth",     "",                               "https://webauthn.lubu.ch",
                    "clientDataJSON", "authenticatorData", "signature"),
            new Rp("yubico-demo-auth",       "assertion",                      "https://demo.yubico.com",
                    "clientDataJSON.$base64", "authenticatorData.$base64", "signature.$base64"),
        };
        for (Rp rp : rps) {
            String prefix = rp.base().isEmpty() ? "" : rp.base() + ".";
            assertClientData(rp.fx(), prefix + rp.cdField(), "webauthn.get", rp.origin());
            byte[] ad = locateUnwrap(rp.fx(), prefix + rp.adField());
            assertEquals(37, ad.length, () -> rp.fx() + " assertion authData should be 37 bytes (AT=0, no ext)");
            byte[] sig = locateUnwrap(rp.fx(), prefix + rp.sigField());
            // ES256 RPs sign DER ECDSA (0x30, 70-72B); the Chrome virtual authenticator defaults to
            // Ed25519 whenever the RP lists -8 first (webauthn.io / debugger / lubu) -> a raw 64-byte sig.
            boolean der = sig.length >= 8 && sig.length <= 72 && sig[0] == (byte) 0x30;
            boolean eddsa = sig.length == 64;
            assertTrue(der || eddsa,
                    () -> rp.fx() + " signature should be ES256 DER or EdDSA raw-64 (len=" + sig.length + ")");
        }
    }

    // ---- Path discrimination: nesting + array index + duplicate-name siblings --------------------

    @Test
    void pathSelectsTheCorrectNestedField() throws IOException {
        // webauthn.io has 'response' at two depths; the path must reach the inner credential, not the outer.
        byte[] body = load("webauthn-io-reg");
        int[] deep = JsonValueEditor.findStringValueSpanAtPath(body, JsonPath.parse("response.response.attestationObject"));
        assertNotNull(deep, "deep attestationObject");
        // A path that stops one hop short points at the inner credential OBJECT, which is not a string value.
        assertNull(JsonValueEditor.findStringValueSpanAtPath(body, JsonPath.parse("response.response")),
                "an object-valued path resolves to no string span");
        // A wrong array index does not resolve.
        byte[] arr = load("passkeys-debugger-reg");
        assertNull(JsonValueEditor.findStringValueSpanAtPath(arr, JsonPath.parse("[9].response.response.attestationObject")),
                "out-of-range array index yields null");
    }

    // ---- Deferred shapes (a later release) are correctly NOT handled by the plain key/index grammar -----

    @Test
    void deferredShapesReturnNullNotWrongBytes() throws IOException {
        // ctap.dev sends clientDataJSON as raw escaped JSON (not base64) - the value carries '\\"' escapes,
        // so the escape-free locator declines rather than returning a half-span. Deferred (needs a raw frame).
        byte[] ctap = load("ctap-dev-reg");
        assertNull(JsonValueEditor.findStringValueSpanAtPath(ctap, JsonPath.parse("clientDataJSON")),
                "ctap raw-JSON clientDataJSON is out of scope (escape-bearing)");
        // ctap's binary fields ARE plain base64 strings and still locate fine (flat top-level).
        byte[] ctapAtt = locateUnwrap("ctap-dev-reg", "attestationObject");
        assertEquals((byte) 0xA3, ctapAtt[0], "ctap attestationObject still locates (plain base64)");

        // Descope wraps the whole credential as a stringified-JSON value under input.response; a plain
        // key path stops at that string and cannot descend into it (needs a json-string codec frame).
        byte[] descope = load("passkeys-guru-reg");
        assertNull(JsonValueEditor.findStringValueSpanAtPath(descope, JsonPath.parse("input.response.response.attestationObject")),
                "Descope stringified-JSON layer is not a structural hop");
    }
}
