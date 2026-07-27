package com.anvil.passkeyeditor.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Byte-identity on REAL relying-party bytes.
 *
 * {@link ByteIdentityTest} proves losslessness on programmatic, webauthn4j-minted fixtures - but
 * those are encoded by the same library that re-encodes them, so a canonicalisation mismatch could hide.
 * These fixtures are genuine ceremony bodies captured from a controlled RP (SimpleWebAuthn + the
 * Chrome DevTools virtual authenticator - zero PII, synthetic challenges/credentials), i.e. bytes a
 * foreign producer emitted. The contract still holds: {@code rewrap(unwrap(x)) == x}, and the CBOR
 * shadow {@code encode(decode(x)) == x} survives the real attestationObject / assertion authData verbatim.
 */
class RealFixtureByteIdentityTest {

    private final WrapperCodec codec = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();

    private static String loadFixture(String name) {
        try (InputStream in = RealFixtureByteIdentityTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The base64url wire bytes (ASCII) of a string member in the captured JSON body. */
    private static byte[] field(String body, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(body);
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + name);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    private void assertWrapperRoundTrips(byte[] wire) {
        WrapperCodec.Unwrapped uw = codec.unwrap(wire);
        assertArrayEquals(wire, codec.rewrap(uw.inner(), uw.spec()),
                "rewrap(unwrap(x)) must equal x on real bytes (spec=" + uw.spec().frames() + ")");
    }

    @Test
    void realRegistrationRoundTrips() {
        String body = loadFixture("reg-clean.json");

        // clientDataJSON + attestationObject wrappers (base64url) round-trip exactly.
        assertWrapperRoundTrips(field(body, "clientDataJSON"));
        byte[] attWire = field(body, "attestationObject");
        assertWrapperRoundTrips(attWire);

        // CBOR shadow on the REAL attestationObject: decode -> encode == original CBOR.
        byte[] attCbor = codec.unwrap(attWire).inner();
        AttestationObject decoded = cbor.decodeAttestationObject(attCbor);
        assertArrayEquals(attCbor, cbor.encodeAttestationObject(decoded),
                "real attestationObject CBOR shadow must round-trip byte-identically");

        // ...and it decoded to the expected shape (none attestation, AT set, EC2/ES256).
        assertEquals("none", decoded.fmt());
        AuthenticatorData ad = decoded.authData();
        assertTrue(ad != null && ad.hasFlag(AuthenticatorData.FLAG_AT), "registration authData has AT set");
        assertEquals(2, ad.credentialPublicKey().kty(), "EC2 kty");
        assertEquals(-7, ad.credentialPublicKey().alg(), "ES256 alg");
    }

    @Test
    void realAuthenticationRoundTrips() {
        String body = loadFixture("auth-clean.json");

        // clientDataJSON + signature wrappers (base64url) round-trip exactly.
        assertWrapperRoundTrips(field(body, "clientDataJSON"));
        assertWrapperRoundTrips(field(body, "signature"));

        // CBOR shadow on the REAL 37-byte assertion authData (AT=0): decode -> encode == original.
        byte[] adWire = field(body, "authenticatorData");
        assertWrapperRoundTrips(adWire);
        byte[] adRaw = codec.unwrap(adWire).inner();
        assertEquals(AuthenticatorData.ASSERTION_LENGTH, adRaw.length, "assertion authData is 37 bytes");
        AuthenticatorData decoded = cbor.decodeAuthData(adRaw);
        assertFalse(decoded.hasFlag(AuthenticatorData.FLAG_AT), "assertion authData has AT=0");
        assertArrayEquals(adRaw, cbor.encodeAuthData(decoded),
                "real assertion authData shadow must round-trip byte-identically");
    }
}
