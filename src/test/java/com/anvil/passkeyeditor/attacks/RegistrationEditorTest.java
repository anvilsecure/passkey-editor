package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.EdDsaSigner;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * - the registration-tab re-encode ({@link RegistrationEditor}). The CREATE tab edits fields INSIDE
 * the attestationObject CBOR, so correctness is byte-level: (a) a plant-only edit must be byte-identical to
 * the proven {@link RegistrationSubstituter#substituteAndEncode} path; (b) an unedited {@code fmt="none"}
 * registration must re-encode byte-identically (no edit ⇒ no drift); (c) a swapped credentialId / edited
 * flags must round-trip while every other field is preserved; (d) the three edits must compose.
 */
class RegistrationEditorTest {

    private final CborCodec cbor = new Webauthn4jCborCodec();
    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final RegistrationEditor editor = new RegistrationEditor(cbor);

    /** Raw attestationObject CBOR of the REAL captured registration (wrappers peeled) - the strongest oracle. */
    private byte[] realRegistrationCbor() {
        String body = loadFixture("reg-clean.json");
        Matcher m = Pattern.compile("\"attestationObject\":\"([^\"]+)\"").matcher(body);
        if (!m.find()) {
            throw new IllegalStateException("attestationObject not found in reg-clean.json");
        }
        return wrapper.unwrap(m.group(1).getBytes(StandardCharsets.US_ASCII)).inner();
    }

    private static String loadFixture(String name) {
        try (InputStream in = RegistrationEditorTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- (a) plant-only is byte-identical to the proven substituteAndEncode --------------------

    @Test
    void plantOnlyEditIsByteIdenticalToSubstituteAndEncode() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        Es256Signer attacker = Es256Signer.generate();

        byte[] viaEditor = editor.edit(cbor.decodeAttestationObject(fixture), attacker, null, null);
        byte[] viaSubstituter = new RegistrationSubstituter(cbor)
                .substituteAndEncode(cbor.decodeAttestationObject(fixture), attacker);

        assertArrayEquals(viaSubstituter, viaEditor,
                "a plant-only registration edit must be byte-identical to the proven substituteAndEncode path");
    }

    // ---- (b) the unedited fmt=none case re-encodes byte-identically ----------------------------

    @Test
    void uneditedNoneRegistrationReEncodesByteIdentically_realFixture() {
        byte[] original = realRegistrationCbor();
        assertEquals("none", cbor.decodeAttestationObject(original).fmt());
        byte[] reEncoded = editor.edit(cbor.decodeAttestationObject(original), null, null, null);
        assertArrayEquals(original, reEncoded,
                "an unedited fmt=none registration must re-encode byte-identically (no edit ⇒ no drift)");
    }

    // ---- (c) a swapped credentialId round-trips; every other field preserved -------------------

    @Test
    void swappedCredentialIdAppearsAndOtherFieldsPreserved() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        AttestationObject src = cbor.decodeAttestationObject(fixture);
        byte[] origAaguid = src.authData().aaguid().clone();
        byte[] origKey = src.authData().credentialPublicKey().raw().clone();
        int origFlags = src.authData().flags();
        long origSignCount = src.authData().signCount();
        byte[] origCredId = src.authData().credentialId().clone();

        // A different-length victim credentialId (the collision/overwrite target).
        byte[] victimCredId = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE};
        byte[] wire = editor.edit(src, null, victimCredId, null);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals("none", out.fmt());
        assertArrayEquals(victimCredId, out.authData().credentialId(), "the swapped credentialId is on the wire");
        assertFalse(java.util.Arrays.equals(origCredId, out.authData().credentialId()), "credId actually changed");
        assertArrayEquals(origAaguid, out.authData().aaguid(), "aaguid preserved");
        assertArrayEquals(origKey, out.authData().credentialPublicKey().raw(), "credential key preserved verbatim");
        assertEquals(origFlags, out.authData().flags(), "flags preserved");
        assertEquals(origSignCount, out.authData().signCount(), "signCount preserved");
    }

    // ---- (c') edited flags round-trip; credId + key preserved ----------------------------------

    @Test
    void editedFlagsRoundTripAndPreserveOtherFields() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        AttestationObject src = cbor.decodeAttestationObject(fixture);
        byte[] origCredId = src.authData().credentialId().clone();
        byte[] origKey = src.authData().credentialPublicKey().raw().clone();
        int origFlags = src.authData().flags();
        // Clear UV (a UV=0 registration-policy conformance probe), preserving AT/ED + every other bit.
        int newFlags = origFlags & ~AuthenticatorData.FLAG_UV;
        assertTrue(newFlags != origFlags, "the fixture had UV set, so clearing it changes the byte");

        byte[] wire = editor.edit(src, null, null, newFlags);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals(newFlags, out.authData().flags(), "edited flags on the wire");
        assertTrue(out.authData().hasFlag(AuthenticatorData.FLAG_AT), "AT still set (still a registration)");
        assertFalse(out.authData().hasFlag(AuthenticatorData.FLAG_UV), "UV cleared");
        assertArrayEquals(origCredId, out.authData().credentialId(), "credentialId preserved");
        assertArrayEquals(origKey, out.authData().credentialPublicKey().raw(), "credential key preserved verbatim");
    }

    // ---- (d) plant + credId swap compose; key becomes ours, credId becomes the victim's --------

    @Test
    void plantPlusCredentialIdSwapComposes() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        Es256Signer attacker = Es256Signer.generate();
        byte[] victimCredId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        byte[] wire = editor.edit(cbor.decodeAttestationObject(fixture), attacker, victimCredId, null);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals("none", out.fmt());
        assertArrayEquals(victimCredId, out.authData().credentialId(), "collided onto the victim credentialId");
        assertArrayEquals(attacker.publicCoseKey().raw(), out.authData().credentialPublicKey().raw(),
                "the embedded key is OUR planted key (ATO-at-registration)");
        assertEquals(2, out.authData().credentialPublicKey().kty(), "EC2 key");
    }

    // ---- a non-none registration can still be edited (attestation dropped to none) --------------

    @Test
    void editingAPackedRegistrationDropsAttestationToNone() {
        AttestationObject src = cbor.decodeAttestationObject(Fixtures.packedRegistrationAttestationObject());
        assertEquals("packed", src.fmt());
        byte[] victimCredId = {0x7a, 0x7b, 0x7c};
        byte[] wire = editor.edit(src, null, victimCredId, null);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals("none", out.fmt(), "a real attestation we cannot re-sign is dropped to fmt=none on edit");
        assertArrayEquals(victimCredId, out.authData().credentialId());
    }

    // ---- guards --------------------------------------------------------------------------------

    @Test
    void editingAnAssertionIsRejected() {
        AttestationObject notARegistration = new AttestationObject();
        notARegistration.setAuthData(cbor.decodeAuthData(Fixtures.assertionAuthData())); // AT=0
        assertThrows(IllegalArgumentException.class,
                () -> editor.edit(notARegistration, Es256Signer.generate(), null, null),
                "editing requires a registration (AT-flagged authData)");
    }

    @Test
    void nullAttestationObjectIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> editor.edit(null, null, null, null));
    }

    // ---- ED (extension data) guard: refuse rather than silently drop extensions -----------------

    @Test
    void registrationCarryingExtensionDataIsRefused() {
        AttestationObject reg = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));
        // A registration whose authData carries extension data (ED bit): the from-fields re-encode cannot
        // reproduce the extension bytes (decode models them only in the raw shadow we must drop), so refuse.
        AuthenticatorData ad = reg.authData();
        ad.setFlags(ad.flags() | AuthenticatorData.FLAG_ED);
        assertTrue(ad.hasFlag(AuthenticatorData.FLAG_AT) && ad.hasFlag(AuthenticatorData.FLAG_ED));
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> editor.edit(reg, null, null, null));
        assertTrue(ex.getMessage().contains("extension data"), ex.getMessage());
    }

    @Test
    void edGuardReadsOriginalFlagsSoAFlagsEditCannotBypassIt() {
        AttestationObject reg = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));
        AuthenticatorData ad = reg.authData();
        ad.setFlags(ad.flags() | AuthenticatorData.FLAG_ED);
        int flagsClearingEd = ad.flags() & ~AuthenticatorData.FLAG_ED; // operator "clears" ED via a flags edit
        // The guard reads the ORIGINAL flags (before applying the edit), so a flags arg that drops ED does NOT
        // sneak past it - the registration's real extension bytes would still be lost.
        assertThrows(IllegalStateException.class, () -> editor.edit(reg, null, null, flagsClearingEd));
    }

    // ---- the alg chooser on CREATE: a non-EC2 (EdDSA) key plants + re-encodes correctly ---------

    @Test
    void plantingAnEdDsaKeyEmbedsOurOkpKeyOnTheWire() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        EdDsaSigner attacker = EdDsaSigner.generate(); // OKP / Ed25519 - what the alg chooser plants for EdDSA
        byte[] wire = editor.edit(cbor.decodeAttestationObject(fixture), attacker, null, null);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals("none", out.fmt());
        assertEquals(1, out.authData().credentialPublicKey().kty(), "OKP kty=1 (the plant is not EC2-only)");
        assertEquals(-8, out.authData().credentialPublicKey().alg(), "EdDSA alg=-8");
        assertArrayEquals(attacker.publicCoseKey().raw(), out.authData().credentialPublicKey().raw(),
                "the emitted registration embeds OUR EdDSA key verbatim (via its raw COSE shadow)");
    }

    // ---- all three edits compose in one re-encode (the offensive plant+collision+policy combo) --

    @Test
    void plantPlusCredentialIdSwapPlusFlagsComposeInOneReEncode() {
        byte[] fixture = Fixtures.registrationAttestationObject(Fixtures.generateP256());
        Es256Signer attacker = Es256Signer.generate();
        byte[] victimCredId = {0x11, 0x22, 0x33, 0x44};
        AttestationObject src = cbor.decodeAttestationObject(fixture);
        int uvCleared = src.authData().flags() & ~AuthenticatorData.FLAG_UV;

        byte[] wire = editor.edit(src, attacker, victimCredId, uvCleared);

        AttestationObject out = cbor.decodeAttestationObject(wire);
        assertEquals("none", out.fmt());
        assertArrayEquals(victimCredId, out.authData().credentialId(), "credentialId swapped");
        assertArrayEquals(attacker.publicCoseKey().raw(), out.authData().credentialPublicKey().raw(),
                "our key planted");
        assertFalse(out.authData().hasFlag(AuthenticatorData.FLAG_UV), "UV cleared");
        assertTrue(out.authData().hasFlag(AuthenticatorData.FLAG_AT), "AT preserved (still a registration)");
    }
}
