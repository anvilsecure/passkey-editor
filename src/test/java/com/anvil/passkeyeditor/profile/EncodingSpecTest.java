package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.WrapSpec;
import com.anvil.passkeyeditor.codec.WrapSpec.Padding;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec.Unwrapped;
import com.anvil.passkeyeditor.profile.EncodingSpec.Base64Kind;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Gate for {@link EncodingSpec} and {@link WrapSpec}. The contract: a pinned explicit
 * encoding compiles to a {@link WrapSpec} whose {@code rewrap} / {@code unwrapWith} are exact inverses,
 * and — for an unedited field — reproduces what AUTO discovers byte-for-byte (so pinning never changes
 * the wire). Also exercises the new percent-encoding frame end-to-end.
 */
class EncodingSpecTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = EncodingSpecTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    private static byte[] slice(byte[] b, int[] span) {
        return Arrays.copyOfRange(b, span[0], span[1]);
    }

    /** unwrapWith(rewrap(x, spec), spec) == x for every encoding kind (the inverse contract). */
    @Test
    void encodingChainRoundTripsForEveryKind() {
        byte[] inner = "the inner raw bytes ÿ\0\020".getBytes(StandardCharsets.ISO_8859_1);
        EncodingSpec[] specs = {
                EncodingSpec.raw(),
                EncodingSpec.base64Url(),
                EncodingSpec.base64StandardPadded(),
                new EncodingSpec(false, Base64Kind.STANDARD, Padding.UNPADDED, null),
                new EncodingSpec(true, Base64Kind.STANDARD, Padding.PADDED, null),   // url-enc + base64
                new EncodingSpec(true, Base64Kind.URL_SAFE, Padding.UNPADDED, null), // url-enc + base64url
                new EncodingSpec(false, Base64Kind.STANDARD, Padding.PADDED, "$base64"), // envelope + base64
                new EncodingSpec(true, Base64Kind.STANDARD, Padding.PADDED, "$base64"),  // url + envelope + base64
        };
        for (EncodingSpec spec : specs) {
            WrapSpec ws = spec.toWrapSpec();
            byte[] wire = CODEC.rewrap(inner, ws);
            byte[] back = CODEC.unwrapWith(wire, ws);
            assertArrayEquals(inner, back, "round-trip failed for " + spec.label());
        }
    }

    /** Percent-encoding turns the standard-base64 specials +,/,= into %2B,%2F,%3D and back. */
    @Test
    void urlEncodeProducesAndReversesPercentEscapes() {
        // A standard-base64 string carrying all three specials.
        byte[] inner = "ab+/c=".getBytes(StandardCharsets.US_ASCII);
        WrapSpec urlOnly = new EncodingSpec(true, Base64Kind.NONE, Padding.UNPADDED, null).toWrapSpec();
        byte[] wire = CODEC.rewrap(inner, urlOnly);
        assertEquals("ab%2B%2Fc%3D", new String(wire, StandardCharsets.US_ASCII), "specials percent-escaped");
        assertArrayEquals(inner, CODEC.unwrapWith(wire, urlOnly), "percent-decode is exact");
    }

    /** On a REAL base64url field, pinning the AUTO-discovered encoding reproduces the wire byte-for-byte. */
    @Test
    void pinnedEncodingMatchesAutoOnWebauthnIoSignature() throws Exception {
        byte[] body = load("webauthn-io-auth");
        int[] span = FieldLocator.of("response.response.signature").locate(body);
        byte[] wire = slice(body, span);

        WrapperCodec.Unwrapped auto = CODEC.unwrap(wire);
        EncodingSpec pinned = EncodingSpec.fromWrapSpec(auto.spec());
        assertNotNull(pinned, "single base64 layer is expressible as an explicit spec");
        assertEquals(Base64Kind.URL_SAFE, pinned.base64(), "webauthn.io signature is base64url");
        assertEquals(Padding.UNPADDED, pinned.padding(), "…unpadded");

        // Pinned decode == AUTO decode, and pinned re-wrap == the original wire (byte-identical).
        assertArrayEquals(auto.inner(), CODEC.unwrapWith(wire, pinned.toWrapSpec()), "pinned decode == auto");
        assertArrayEquals(wire, CODEC.rewrap(auto.inner(), pinned.toWrapSpec()), "pinned re-wrap == original wire");
    }

    /** AUTO mode is exactly today's null-encoding behaviour (the default). */
    @Test
    void autoModeMatchesNullEncoding() throws Exception {
        byte[] body = load("webauthn-io-auth");
        byte[] wire = slice(body, FieldLocator.of("response.response.signature").locate(body));
        Unwrapped a = Encodings.decode(CODEC, wire, null);
        Unwrapped b = Encodings.decode(CODEC, wire, EncodingSpec.auto());
        assertArrayEquals(a.inner(), b.inner(), "null encoding == EncodingSpec.auto()");
        assertArrayEquals(wire, CODEC.rewrap(a.inner(), a.spec()), "auto effective spec rebuilds the wire");
    }

    /** The URL-encode tick composes with AUTO base64 detection — percent layer outside, base64 discovered. */
    @Test
    void autoWithUrlTickDiscoversAndRoundTrips() {
        byte[] inner = "raw ÿþ bytes, length not a multiple of three!".getBytes(StandardCharsets.ISO_8859_1);
        // Build the wire as url-encoded(standard-base64(inner)) using an explicit spec, then decode with the
        // tick on + AUTO base64 — it must recover inner and rebuild the identical wire.
        WrapSpec explicit = new EncodingSpec(true, Base64Kind.STANDARD, Padding.PADDED, null).toWrapSpec();
        byte[] wire = CODEC.rewrap(inner, explicit);
        assertTrue(new String(wire, StandardCharsets.US_ASCII).contains("%"),
                "the URL layer is actually active (percent-escapes present)");
        Unwrapped dec = Encodings.decode(CODEC, wire, EncodingSpec.autoUrlEncoded());
        assertArrayEquals(inner, dec.inner(), "AUTO + URL tick recovers the inner bytes");
        assertArrayEquals(wire, CODEC.rewrap(dec.inner(), dec.spec()), "AUTO + URL tick effective spec rebuilds the wire");
    }

    /** An AUTO spec has no static WrapSpec — toWrapSpec must refuse (decode goes through Encodings). */
    @Test
    void toWrapSpecRefusesAuto() {
        assertThrows(IllegalStateException.class, () -> EncodingSpec.auto().toWrapSpec());
    }

    /**
     * AUDIT H1 regression: ticking URL-encoded on a value that is NOT actually percent-encoded but DOES
     * carry standard-base64 specials (+,/,=) must NOT corrupt the wire. The self-check in Encodings drops
     * the spurious URL_ENCODE frame, so the effective spec still rebuilds the wire byte-for-byte (before the
     * fix, the strict percentEncode re-escaped +,/,= and produced e.g. "//8=" -> "%2F%2F8%3D").
     */
    @Test
    void urlTickOnNonUrlEncodedValueDoesNotCorrupt() {
        byte[] wire = "//8=".getBytes(StandardCharsets.US_ASCII); // standard base64 of {0xFF,0xFF}, has / and =
        Unwrapped dec = Encodings.decode(CODEC, wire, EncodingSpec.autoUrlEncoded());
        assertArrayEquals(wire, CODEC.rewrap(dec.inner(), dec.spec()),
                "URL tick on a non-url value must rebuild the wire byte-identically (no spurious url frame)");
        assertTrue(dec.spec().frames().stream().noneMatch(f -> f.codec() == WrapSpec.Codec.URL_ENCODE),
                "the ineffective URL frame is dropped by the self-check");
    }

    /** The URL tick toggles independently of (and preserves) the base64 choice — the Check panel's control. */
    @Test
    void withUrlEncodedTogglesTickPreservingBase64() {
        assertTrue(EncodingSpec.auto().withUrlEncoded(true).urlEncoded());
        EncodingSpec b = EncodingSpec.base64Url().withUrlEncoded(true);
        assertTrue(b.urlEncoded());
        assertEquals(Base64Kind.URL_SAFE, b.base64(), "base64 choice preserved through the tick");
        assertTrue(!b.withUrlEncoded(false).urlEncoded(), "tick clears");
    }

    /** Yubico's standard+padded base64 (the $base64 value) likewise pins faithfully. */
    @Test
    void pinnedEncodingMatchesAutoOnYubicoStandardBase64() throws Exception {
        byte[] body = load("yubico-demo-reg");
        int[] span = FieldLocator.of("attestation.attestationObject.$base64").locate(body);
        assertNotNull(span, "yubico attestationObject locates at the $base64 path");
        byte[] wire = slice(body, span);

        WrapperCodec.Unwrapped auto = CODEC.unwrap(wire);
        EncodingSpec pinned = EncodingSpec.fromWrapSpec(auto.spec());
        assertNotNull(pinned);
        assertEquals(Base64Kind.STANDARD, pinned.base64(), "yubico uses standard base64 (+/ alphabet)");
        // Padding is per-value (this attestationObject's length is a multiple of 3 → unpadded); the gate is
        // that the pinned spec reproduces the wire byte-for-byte whatever the padding turns out to be.
        assertArrayEquals(wire, CODEC.rewrap(auto.inner(), pinned.toWrapSpec()), "pinned re-wrap == original wire");
        assertArrayEquals(auto.inner(), CODEC.unwrapWith(wire, pinned.toWrapSpec()), "pinned decode == auto");
        assertTrue(pinned.label().startsWith("base64"), "label: " + pinned.label());
    }
}
