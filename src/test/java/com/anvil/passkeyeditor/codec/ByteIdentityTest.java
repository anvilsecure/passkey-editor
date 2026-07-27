package com.anvil.passkeyeditor.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.WrapSpec.Codec;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * byte-identity.
 *
 * The losslessness contract: {@code decode(fixture) → encode == original bytes}. Two complementary
 * paths are exercised, because the tool's round-trip is wrapper-peel + CBOR-shadow:
 *
 *   - {@link WrapperCodec}: {@code rewrap(unwrap(wire).inner(), unwrap(wire).spec()) == wire} for
 *       every wrapper flavor, including the mixed-flavor double-Base64 (outer standard+padded,
 *       inner base64url-unpadded) and a JSON envelope around that double-Base64 - the synthetic
 *       gnarly fixture. This is the raw-bytes-shadow / splice path.
 *   - {@link CborCodec}: {@code encode(decode(cbor)) == cbor} for a real {@code none}-attestation
 *       registration object and a bare 37-byte assertion authData - the verbatim shadow survives a
 *       foreign producer's CBOR map order / int width byte-identically.
 */
class ByteIdentityTest {

    private final WrapperCodec codec = new WrapperCodec.Default();

    // ---- WrapperCodec round-trips --------------------------------------------------------------

    /**
     * A field already raw on the wire (no wrapper) round-trips with an empty spec. Uses raw CBOR
     * containing control bytes (0x00/0x01) that are outside the Base64 alphabet, so the no-wrapper case
     * is deterministic (not reliant on a random rpIdHash happening to contain a non-Base64 byte).
     */
    @Test
    void rawNoWrapperRoundTrips() {
        byte[] raw = Fixtures.assertionAuthData(); // 37 bytes incl. flags/0x05 + signCount control bytes
        WrapperCodec.Unwrapped uw = codec.unwrap(raw);
        assertTrue(uw.spec().isEmpty(), "raw bytes must not be mis-detected as a wrapper layer");
        assertArrayEquals(raw, codec.rewrap(uw.inner(), uw.spec()));

        // Explicit adversarial control: bytes that contain a non-Base64 char (0x00) are never peeled.
        byte[] withControl = {0x01, 0x02, 0x00, (byte) 0xFF, 0x40, 0x40};
        WrapperCodec.Unwrapped cw = codec.unwrap(withControl);
        assertTrue(cw.spec().isEmpty(), "bytes with a 0x00 cannot be a Base64 layer");
        assertArrayEquals(withControl, codec.rewrap(cw.inner(), cw.spec()));
    }

    /**
     * Adversarial losslessness: raw bytes that happen to be entirely within the Base64 alphabet
     * (so the codec may speculatively peel them) must still round-trip byte-identically - the strict
     * re-encode self-check is what guarantees this, peel or no peel.
     */
    @Test
    void base64LookalikeRawStillRoundTripsLosslessly() {
        // "AAAA...." style: valid Base64 chars, decodes-and-re-encodes cleanly; whether or not the codec
        // records a frame, rewrap(unwrap(x)) must equal x.
        byte[] lookalike = "QUJDREVGR0hJSktMTU4".getBytes(StandardCharsets.US_ASCII); // base64url-ish token
        assertRoundTrip(lookalike);
    }

    /** Single base64url, unpadded - the common WebAuthn wire flavor. */
    @Test
    void singleBase64UrlUnpaddedRoundTrips() {
        byte[] inner = Fixtures.assertionAuthData();
        byte[] wire = Base64.getUrlEncoder().withoutPadding().encode(inner).clone();
        assertRoundTrip(wire);
        // sanity: exactly one base64 frame discovered
        assertEquals(1, codec.unwrap(wire).spec().frames().size());
    }

    /** Single standard base64, padded. */
    @Test
    void singleBase64StandardPaddedRoundTrips() {
        byte[] inner = Fixtures.clientDataJson("webauthn.get");
        byte[] wire = Base64.getEncoder().encode(inner);
        assertRoundTrip(wire);
        WrapSpec spec = codec.unwrap(wire).spec();
        assertEquals(1, spec.frames().size());
        assertEquals(Codec.BASE64, spec.frames().get(0).codec());
    }

    /**
     * A gate: double-Base64 with differing padding per frame - an outer padded layer wrapping
     * an inner base64url-unpadded layer - captured per-frame and replayed byte-identically.
     *
     * The outer is a standard-base64 encoding of a base64url ASCII string, which (as with any base64url
     * field re-wrapped) carries no {@code +}/{@code /}, so it is alphabet-ambiguous and the codec classifies
     * it URL_SAFE - the WebAuthn-correct default that keeps a re-wrapped new value valid base64url;
     * byte-identical here either way. Genuine standard-flavor detection lives in {@link WrapperReWrapFlavorTest}.
     */
    @Test
    void mixedFlavorDoubleBase64RoundTrips() {
        byte[] inner = Fixtures.assertionAuthData();
        byte[] innerB64 = Base64.getUrlEncoder().withoutPadding().encode(inner);       // base64url, unpadded
        byte[] outerB64 = Base64.getEncoder().encode(innerB64);                         // standard encoder, padded
        assertRoundTrip(outerB64);

        WrapSpec spec = codec.unwrap(outerB64).spec();
        assertEquals(2, spec.frames().size(), "expected two Base64 frames (double-Base64)");
        // Frame 0 outermost (PADDED): alphabet-ambiguous ⇒ URL_SAFE default - the regression lock for the
        // base64url re-wrap fix (flipping this back to STANDARD is the "...not a base64url string" bug).
        assertEquals(WrapSpec.Flavor.URL_SAFE, spec.frames().get(0).flavor());
        assertEquals(WrapSpec.Padding.PADDED, spec.frames().get(0).padding());
        // Frame 1 innermost: url-safe, unpadded.
        assertEquals(WrapSpec.Flavor.URL_SAFE, spec.frames().get(1).flavor());
        assertEquals(WrapSpec.Padding.UNPADDED, spec.frames().get(1).padding());
        // The real gate: the peeled inner equals the original raw bytes, byte-identically.
        assertArrayEquals(inner, codec.unwrap(outerB64).inner());
    }

    /** A JSON envelope around a base64url blob (the simple envelope shape). */
    @Test
    void jsonEnvelopeAroundBase64RoundTrips() {
        byte[] inner = Fixtures.clientDataJson("webauthn.create");
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(inner);
        byte[] wire = ("{\"clientDataJSON\":\"" + b64 + "\"}").getBytes(StandardCharsets.UTF_8);
        assertRoundTrip(wire);

        WrapSpec spec = codec.unwrap(wire).spec();
        assertEquals(Codec.JSON_ENVELOPE, spec.frames().get(0).codec(), "outermost frame is the envelope");
        assertEquals("clientDataJSON", spec.frames().get(0).jsonPath());
        assertArrayEquals(inner, codec.unwrap(wire).inner());
    }

    /**
     * The full synthetic gnarly fixture from the plan: a JSON envelope wrapping a mixed-flavor
     * double-Base64 of a real CBOR attestation object. {@code unwrap → rewrap} must be byte-identical and
     * the peeled inner must be the original CBOR.
     */
    @Test
    void jsonEnvelopeAroundMixedDoubleBase64OfCborRoundTrips() {
        KeyPair kp = Fixtures.generateP256();
        byte[] cbor = Fixtures.registrationAttestationObject(kp);     // real attestationObject CBOR
        byte[] innerB64 = Base64.getUrlEncoder().withoutPadding().encode(cbor);   // base64url, unpadded
        byte[] outerB64 = Base64.getEncoder().encode(innerB64);                    // standard, padded
        String envelope = "{\"attestationObject\":\"" + new String(outerB64, StandardCharsets.US_ASCII) + "\"}";
        byte[] wire = envelope.getBytes(StandardCharsets.UTF_8);

        assertRoundTrip(wire);

        WrapSpec spec = codec.unwrap(wire).spec();
        assertEquals(3, spec.frames().size(), "JSON envelope + 2 Base64 layers");
        assertEquals(Codec.JSON_ENVELOPE, spec.frames().get(0).codec());
        assertEquals(Codec.BASE64, spec.frames().get(1).codec());
        assertEquals(Codec.BASE64, spec.frames().get(2).codec());
        assertArrayEquals(cbor, codec.unwrap(wire).inner(), "peeled inner must be the original CBOR");
    }

    /** clientDataJSON raw bytes round-trip untouched (byte-opaque contract). */
    @Test
    void clientDataJsonRawRoundTrips() {
        byte[] raw = Fixtures.clientDataJson("webauthn.get");
        assertRoundTrip(raw);
    }

    // ---- CborCodec shadow round-trips (encode(decode(x)) == x) ----------------------------------

    /** A real {@code none}-attestation registration object decodes and re-encodes byte-identically. */
    @Test
    void attestationObjectCborRoundTrips() {
        KeyPair kp = Fixtures.generateP256();
        byte[] cbor = Fixtures.registrationAttestationObject(kp);

        CborCodec cbor4j = new Webauthn4jCborCodec();
        AttestationObject decoded = cbor4j.decodeAttestationObject(cbor);
        byte[] reencoded = cbor4j.encodeAttestationObject(decoded);
        assertArrayEquals(cbor, reencoded, "attestationObject shadow must round-trip byte-identically");
        // and the embedded credential public key decoded as EC2/ES256
        assertEquals("none", decoded.fmt());
        AuthenticatorData ad = decoded.authData();
        assertTrue(ad != null && ad.hasFlag(AuthenticatorData.FLAG_AT), "AT flag must be set on a registration");
        assertEquals(2, ad.credentialPublicKey().kty(), "EC2 kty");
        assertEquals(-7, ad.credentialPublicKey().alg(), "ES256 alg");
    }

    /** A real 37-byte assertion authData decodes and re-encodes byte-identically (the shadow). */
    @Test
    void assertionAuthDataCborRoundTrips() {
        byte[] authData = Fixtures.assertionAuthData();
        assertEquals(AuthenticatorData.ASSERTION_LENGTH, authData.length, "assertion authData is 37 bytes");

        CborCodec cbor4j = new Webauthn4jCborCodec();
        AuthenticatorData decoded = cbor4j.decodeAuthData(authData);
        assertFalse(decoded.hasFlag(AuthenticatorData.FLAG_AT), "assertion authData has AT=0");
        assertArrayEquals(authData, cbor4j.encodeAuthData(decoded), "authData shadow must round-trip");
    }

    /**
     * Regression guard (review finding): the embedded credential public key's shadow must be the
     * verbatim COSE wire bytes, NOT webauthn4j's canonical re-serialisation. We embed a COSE EC2
     * key in deliberately foreign map order (alg, kty, x, crv, y) inside a registration authData;
     * after decode, {@code credentialPublicKey().raw()} must equal that exact foreign slice. If a future
     * key-splice attack rebuilds authData by re-encoding this raw() for an unedited key, the RP signature
     * must still verify - which only holds if the bytes are preserved, not canonically reordered.
     */
    @Test
    void embeddedCoseKeyShadowIsVerbatimNotCanonical() {
        KeyPair kp = Fixtures.generateP256();
        byte[] foreignCose = Fixtures.foreignOrderEc2CoseKey(kp); // alg,kty,x,crv,y (non-canonical)
        byte[] credId = {0x01, 0x02, 0x03, 0x04};
        byte[] authData = Fixtures.registrationAuthDataWithRawCoseKey(foreignCose, credId);

        CborCodec cbor4j = new Webauthn4jCborCodec();
        AuthenticatorData decoded = cbor4j.decodeAuthData(authData);
        assertTrue(decoded.hasFlag(AuthenticatorData.FLAG_AT), "AT flag must be set");

        byte[] shadow = decoded.credentialPublicKey().raw();
        assertArrayEquals(foreignCose, shadow,
                "embedded COSE key shadow must be the verbatim wire slice, not a canonical re-serialisation");
        // And the whole authData round-trips byte-identically via its own shadow.
        assertArrayEquals(authData, cbor4j.encodeAuthData(decoded), "authData shadow must round-trip");
    }

    // ---- helper --------------------------------------------------------------------------------

    private void assertRoundTrip(byte[] wire) {
        WrapperCodec.Unwrapped uw = codec.unwrap(wire);
        byte[] rebuilt = codec.rewrap(uw.inner(), uw.spec());
        assertArrayEquals(wire, rebuilt,
                "rewrap(unwrap(x)) must equal x - losslessness gate (spec=" + uw.spec().frames() + ")");
    }
}
