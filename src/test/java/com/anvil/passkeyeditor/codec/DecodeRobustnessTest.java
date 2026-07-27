package com.anvil.passkeyeditor.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * decode robustness ("the deadliest risk, while there's runway").
 *
 * The baseline RP only ever emits EC2/P-256 keys + {@code fmt="none"} attestation over clean wrappers, so
 * proved the decoder on a narrow slice. Real RPs send RSA and Ed25519 (OKP) credential keys, real
 * attestation formats ({@code packed}, …), unknown vendor formats, and - on a half-captured request -
 * truncated or non-CBOR garbage. The single worst failure for this tool is the decoded tab vanishing or
 * mis-decoding on a target's real traffic; the {@link CborCodec} contract is therefore decode-for-
 * display must never throw on shape and must degrade gracefully (raw preserved), and an unedited
 * structure must still round-trip byte-identically via its shadow.
 */
class DecodeRobustnessTest {

    private final CborCodec cbor = new Webauthn4jCborCodec();

    // ---- valid-but-unusual key types / attestation formats must decode, never throw ------------

    @Test
    void rsaCredentialPublicKeyDecodesAndRoundTrips() {
        byte[] att = Fixtures.rsaRegistrationAttestationObject();
        AttestationObject decoded = assertDoesNotThrow(() -> cbor.decodeAttestationObject(att));

        assertEquals("none", decoded.fmt());
        AuthenticatorData ad = decoded.authData();
        assertNotNull(ad, "registration authData must decode");
        assertTrue(ad.hasFlag(AuthenticatorData.FLAG_AT), "AT flag set");
        assertNotNull(ad.credentialPublicKey(), "credential public key present");
        assertEquals(3, ad.credentialPublicKey().kty(), "RSA COSE kty=3");
        // n/e decode for display, so the editor shows a readable key instead of a hex blob...
        assertNotNull(ad.credentialPublicKey().n(), "RSA modulus decoded for display");
        assertNotNull(ad.credentialPublicKey().e(), "RSA exponent decoded for display");
        // ...and decoding them changes nothing on the wire: the verbatim shadow still governs the re-encode.
        assertArrayEquals(att, cbor.encodeAttestationObject(decoded),
                "RSA-key attestation object must round-trip byte-identically via its shadow");
    }

    @Test
    void ed25519CredentialPublicKeyDecodesAndRoundTrips() {
        byte[] att = Fixtures.ed25519RegistrationAttestationObject();
        AttestationObject decoded = assertDoesNotThrow(() -> cbor.decodeAttestationObject(att));

        AuthenticatorData ad = decoded.authData();
        assertNotNull(ad, "registration authData must decode");
        assertNotNull(ad.credentialPublicKey(), "credential public key present");
        assertEquals(1, ad.credentialPublicKey().kty(), "OKP COSE kty=1");
        assertArrayEquals(att, cbor.encodeAttestationObject(decoded),
                "Ed25519-key attestation object must round-trip byte-identically via its shadow");
    }

    @Test
    void packedAttestationDecodesAndRoundTrips() {
        byte[] att = Fixtures.packedRegistrationAttestationObject();
        AttestationObject decoded = assertDoesNotThrow(() -> cbor.decodeAttestationObject(att));

        assertEquals("packed", decoded.fmt(), "non-none fmt must decode");
        assertNotNull(decoded.attStmtRaw(), "attStmt bytes retained verbatim");
        assertNotNull(decoded.authData(), "authData decodes alongside a non-none attestation");
        assertArrayEquals(att, cbor.encodeAttestationObject(decoded),
                "packed attestation object must round-trip byte-identically via its shadow");
    }

    @Test
    void unknownFmtDegradesToNullFmtWithoutThrowing() {
        byte[] att = Fixtures.unknownFmtAttestationObject();
        AttestationObject decoded = assertDoesNotThrow(() -> cbor.decodeAttestationObject(att));

        assertNull(decoded.fmt(), "an unknown vendor fmt degrades to null, not an exception");
        assertNotNull(decoded.raw(), "raw bytes preserved for display");
        assertArrayEquals(att, cbor.encodeAttestationObject(decoded),
                "unknown-fmt object still round-trips byte-identically via its shadow");
    }

    // ---- truncated / garbage must never throw (tab never vanishes) -----------------------------

    @Test
    void truncatedAttestationObjectNeverThrows() {
        byte[] full = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        byte[] truncated = Arrays.copyOfRange(full, 0, full.length / 2);
        AttestationObject decoded = assertDoesNotThrow(() -> cbor.decodeAttestationObject(truncated));
        assertArrayEquals(truncated, decoded.raw(), "raw bytes preserved even when the structure is broken");
    }

    @Test
    void truncatedAuthDataRecoversHeaderNeverThrows() {
        byte[] assertion = Fixtures.assertionAuthData(); // 37 bytes
        AuthenticatorData full = cbor.decodeAuthData(assertion);

        // Lop the body to 20 bytes - below the 37-byte fixed header, so only raw can be trusted.
        byte[] tiny = Arrays.copyOfRange(assertion, 0, 20);
        AuthenticatorData decodedTiny = assertDoesNotThrow(() -> cbor.decodeAuthData(tiny));
        assertArrayEquals(tiny, decodedTiny.raw(), "raw preserved for a sub-header truncation");

        // A registration authData truncated mid-COSE-key keeps its recoverable 37-byte header.
        byte[] regAuthData = Fixtures.registrationAuthDataWithRawCoseKey(
                Fixtures.foreignOrderEc2CoseKey(Fixtures.generateP256()), new byte[]{1, 2, 3, 4});
        byte[] choppedKey = Arrays.copyOfRange(regAuthData, 0, AuthenticatorData.ASSERTION_LENGTH + 10);
        AuthenticatorData recovered = assertDoesNotThrow(() -> cbor.decodeAuthData(choppedKey));
        assertArrayEquals(choppedKey, recovered.raw());
        assertNotNull(recovered.rpIdHash(), "fixed header recovered from a mid-COSE truncation");
        assertEquals(full.flags() | AuthenticatorData.FLAG_AT,
                recovered.flags() | AuthenticatorData.FLAG_AT, "flags byte recovered");
    }

    @Test
    void garbageAndEmptyNeverThrowOnAnyDecodePath() {
        byte[] garbage = {0x00, 0x01, 0x02, 0x03, (byte) 0xFF, (byte) 0x80, 0x40};
        byte[] empty = new byte[0];
        for (byte[] junk : new byte[][]{garbage, empty}) {
            assertDoesNotThrow(() -> cbor.decodeAttestationObject(junk));
            assertDoesNotThrow(() -> cbor.decodeAuthData(junk));
            assertDoesNotThrow(() -> cbor.decodeCoseKey(junk));
        }
    }
}
