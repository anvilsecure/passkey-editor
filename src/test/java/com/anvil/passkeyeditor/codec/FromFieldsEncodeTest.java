package com.anvil.passkeyeditor.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * from-fields encode, re-gated for byte-identity (insurance for the key-substitution rebuild).
 *
 * When nothing is edited, the codec hands back the verbatim shadow - already proven lossless. But the
 * attack (substitute the registration public key and re-sign) rebuilds the structure from
 * its decoded fields rather than echoing the original. If rebuilding from UNEDITED fields fails to
 * reproduce the original byte-for-byte, then editing one field silently corrupts the others and the RP
 * rejects the forgery for the wrong reason - a brutal thing to debug live. These tests force the
 * from-fields path (by nulling the raw shadow) and assert it reproduces the original byte-identically,
 * including on the real captured registration - the strongest oracle (foreign-produced bytes).
 */
class FromFieldsEncodeTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();

    private static String loadFixture(String name) {
        try (InputStream in = FromFieldsEncodeTest.class.getResourceAsStream("/fixtures/" + name)) {
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

    /** Raw attestationObject CBOR of the real captured registration (wrappers peeled). */
    private byte[] realRegistrationAttestationCbor() {
        String body = loadFixture("reg-clean.json");
        return wrapper.unwrap(field(body, "attestationObject")).inner();
    }

    // ---- registration authData rebuilds from fields, byte-identically --------------------------

    @Test
    void registrationAuthDataRebuildsFromFieldsByteIdentically_realFixture() {
        AttestationObject decoded = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        AuthenticatorData ad = decoded.authData();
        assertNotNull(ad);
        assertTrue(ad.hasFlag(AuthenticatorData.FLAG_AT), "registration authData has AT set");

        byte[] original = ad.raw();
        assertNotNull(original);
        // Force the from-fields concatenation: drop the authData shadow but keep the embedded COSE key
        // verbatim (the unedited-key case - editing a non-key field like signCount must not corrupt it).
        ad.setRaw(null);
        assertArrayEquals(original, cbor.encodeAuthData(ad),
                "registration authData must rebuild from fields byte-identically (COSE key kept verbatim)");
    }

    @Test
    void attestationObjectRebuildsFromFieldsByteIdentically_realFixture() {
        byte[] originalCbor = realRegistrationAttestationCbor();
        AttestationObject decoded = cbor.decodeAttestationObject(originalCbor);
        assertEquals("none", decoded.fmt());

        // Force the from-fields rebuild on BOTH levels (object map + its authData); keep attStmt + the
        // embedded COSE key verbatim. This is the full assembly path with no edits applied.
        decoded.setRaw(null);
        decoded.authData().setRaw(null);
        assertArrayEquals(originalCbor, cbor.encodeAttestationObject(decoded),
                "fmt=none attestation object must rebuild from fields byte-identically");
    }

    @Test
    void assertionAuthDataRebuildsFromFieldsByteIdentically() {
        byte[] authData = Fixtures.assertionAuthData(); // bare 37-byte assertion
        AuthenticatorData ad = cbor.decodeAuthData(authData);
        ad.setRaw(null); // force the from-fields path
        assertArrayEquals(authData, cbor.encodeAuthData(ad),
                "bare assertion authData must rebuild from fields byte-identically");
    }

    // ---- the substitution mechanic produces a valid, re-decodable structure --------------

    @Test
    void substitutedCredentialKeyReEncodesIntoADecodableRegistration() {
        AttestationObject decoded = cbor.decodeAttestationObject(realRegistrationAttestationCbor());
        AuthenticatorData ad = decoded.authData();
        CoseKey key = ad.credentialPublicKey();

        // Simulate a key substitution: drop the COSE key's verbatim shadow so encodeAuthData must
        // re-encode it from its EC2 fields (kty/x/y) - exactly what the key-substitution flow does with our key.
        key.setRaw(null);
        ad.setRaw(null);
        byte[] rebuilt = cbor.encodeAuthData(ad);

        // The re-encoded registration authData must itself decode cleanly back to an EC2/ES256 key.
        AuthenticatorData reDecoded = cbor.decodeAuthData(rebuilt);
        assertTrue(reDecoded.hasFlag(AuthenticatorData.FLAG_AT), "AT flag preserved");
        assertNotNull(reDecoded.credentialPublicKey());
        assertEquals(2, reDecoded.credentialPublicKey().kty(), "re-encoded EC2 kty=2");
        assertEquals(-7, reDecoded.credentialPublicKey().alg(), "re-encoded ES256 alg=-7");
    }

    // ---- recommended-depth scope guard ---------------------------------------------------------

    @Test
    void unsupportedAttestationFromFieldsIsRejected() {
        // From-fields scope is fmt="none" and fmt="packed" (packed self-attestation) only; any OTHER
        // (x5c-bearing / signed) attestation must round-trip via its raw shadow, never be rebuilt from
        // fields - re-encoding such an attStmt from fields would silently corrupt the attestation.
        AttestationObject decoded = cbor.decodeAttestationObject(Fixtures.packedRegistrationAttestationObject());
        assertEquals("packed", decoded.fmt());
        decoded.setFmt("fido-u2f"); // pretend a format the from-fields encoder does not support
        decoded.setRaw(null);       // force the from-fields path
        assertThrows(UnsupportedOperationException.class, () -> cbor.encodeAttestationObject(decoded),
                "from-fields encode must refuse an unsupported (non none/packed) attestation format");
    }

    @Test
    void packedAttestationFromFieldsEmitsProvidedAttStmt() {
        // fmt="packed" IS now rebuildable from fields: the provided attStmtRaw is emitted verbatim as the
        // attStmt value (the self-attestation assembly relies on this). Decodes back to fmt=packed with the
        // same attStmt bytes and the same authData - the round-trip a packed self-attestation plant needs.
        AttestationObject decoded = cbor.decodeAttestationObject(Fixtures.packedRegistrationAttestationObject());
        assertEquals("packed", decoded.fmt());
        byte[] attStmt = decoded.attStmtRaw();
        assertNotNull(attStmt, "packed fixture carries an attStmt");
        byte[] authData = cbor.encodeAuthData(decoded.authData());
        decoded.setRaw(null); // force the from-fields path

        byte[] rebuilt = cbor.encodeAttestationObject(decoded);
        AttestationObject reDecoded = cbor.decodeAttestationObject(rebuilt);
        assertEquals("packed", reDecoded.fmt(), "rebuilt object is still fmt=packed");
        assertArrayEquals(attStmt, reDecoded.attStmtRaw(), "the provided attStmt is emitted verbatim");
        assertArrayEquals(authData, cbor.encodeAuthData(reDecoded.authData()), "authData survives the rebuild");
    }
}
