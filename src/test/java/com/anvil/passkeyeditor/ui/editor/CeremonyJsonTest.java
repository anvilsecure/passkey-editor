package com.anvil.passkeyeditor.ui.editor;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CeremonyModel;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.model.ClientData;
import com.anvil.passkeyeditor.model.CoseKey;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.util.Arrays;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The decoded-JSON model/diff/edit-back core ({@link CeremonyJson}) behind the Passkey Editor tab: the
 * decoded tree, the leaf diff that drives the Original→Edited colouring, the range-tracking renderer,
 * and reading an operator's edited JSON back into field edits the re-sign path understands.
 */
class CeremonyJsonTest {

    private static byte[] f(int b, int n) {
        byte[] x = new byte[n];
        Arrays.fill(x, (byte) b);
        return x;
    }

    private static CoseKey okp() {
        CoseKey k = new CoseKey();
        k.setKty(1);
        k.setAlg(-8);
        k.setCrv(6);
        k.setX(f(0x16, 32));
        k.setRaw(f(0x16, 42));
        return k;
    }

    private static CoseKey rsa() {
        CoseKey k = new CoseKey();
        k.setKty(3);
        k.setAlg(-257);
        k.setRaw(f(0x22, 270));
        return k;
    }

    private static ClientData cd(String type) {
        return new ClientData(("{\"type\":\"" + type + "\",\"challenge\":\"Y2g\",\"origin\":"
                + "\"https://webauthn.io\",\"crossOrigin\":false}").getBytes(UTF_8));
    }

    private static CeremonyModel create(CoseKey k) {
        CeremonyModel m = new CeremonyModel(CeremonyType.CREATE);
        m.setClientData(cd("webauthn.create"));
        AuthenticatorData a = new AuthenticatorData();
        a.setRpIdHash(f(0x74, 32));
        a.setFlags(0x45); // UP UV AT
        a.setSignCount(1);
        a.setAaguid(f(0x01, 16));
        a.setCredentialId(f(0x93, 16));
        a.setCredentialPublicKey(k);
        m.setAuthenticatorData(a);
        AttestationObject o = new AttestationObject();
        o.setFmt("none");
        o.setAuthData(a);
        m.setAttestationObject(o);
        return m;
    }

    private static CeremonyModel get(byte[] sig) {
        CeremonyModel m = new CeremonyModel(CeremonyType.GET);
        m.setClientData(cd("webauthn.get"));
        AuthenticatorData a = new AuthenticatorData();
        a.setRpIdHash(f(0x74, 32));
        a.setFlags(0x05); // UP UV
        a.setSignCount(2);
        m.setAuthenticatorData(a);
        m.setSignature(sig);
        return m;
    }

    private static String pretty(JsonObject o) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(o);
    }

    @Test
    void treeCreateMirrorsDecodedStructure() {
        JsonObject t = CeremonyJson.tree(create(okp()));
        assertTrue(t.has("clientDataJSON"));
        JsonObject att = t.getAsJsonObject("attestationObject");
        assertEquals("none", att.getAsJsonObject("attestationStatement").get("format").getAsString());
        assertEquals("none", att.get("fmt").getAsString());
        JsonObject ad = att.getAsJsonObject("authenticatorData");
        JsonObject flags = ad.getAsJsonObject("flags");
        assertTrue(flags.get("userPresent").getAsBoolean());
        assertTrue(flags.get("userVerified").getAsBoolean());
        assertTrue(flags.get("attestedCredentialData").getAsBoolean());
        assertFalse(flags.get("extensionDataIncluded").getAsBoolean());
        JsonObject ck = ad.getAsJsonObject("attestedCredentialData").getAsJsonObject("coseKey");
        assertEquals("OKP", ck.get("keyType").getAsString());
        assertEquals("EdDSA", ck.get("algorithm").getAsString());
        assertEquals("Ed25519", ck.get("curve").getAsString());
        assertTrue(ck.has("x"));
        assertTrue(ad.getAsJsonObject("attestedCredentialData").has("credentialId"));
    }

    @Test
    void treeGetHasSignatureAndEmptyAttestedCredentialData() {
        JsonObject t = CeremonyJson.tree(get(f(0xAA, 64)));
        assertTrue(t.has("clientDataJSON"));
        assertFalse(t.has("attestationObject"));
        assertEquals(0, t.getAsJsonObject("authenticatorData").getAsJsonObject("attestedCredentialData").size());
        assertFalse(t.get("signature").getAsString().isEmpty());
    }

    @Test
    void treeRsaCoseKeyShowsModulusAndExponentNotAHexBlob() {
        CoseKey k = rsa();
        k.setN(f(0xAB, 256)); // a 2048-bit modulus
        k.setE(new byte[]{0x01, 0x00, 0x01}); // 65537
        JsonObject ck = CeremonyJson.tree(create(k)).getAsJsonObject("attestationObject")
                .getAsJsonObject("authenticatorData").getAsJsonObject("attestedCredentialData")
                .getAsJsonObject("coseKey");

        assertEquals("RSA", ck.get("keyType").getAsString());
        assertEquals("RS256", ck.get("algorithm").getAsString());
        assertEquals(2048, ck.get("modulusBits").getAsInt(), "the size an operator actually reads off the key");
        assertTrue(ck.get("n").getAsString().startsWith("ABAB"), ck.get("n").getAsString());
        assertEquals("010001", ck.get("e").getAsString().toLowerCase(), "e = 65537");
        assertFalse(ck.has("raw"), "n/e replace the blob rather than sitting beside it");
        assertFalse(ck.has("x"), "no EC2 coordinates on an RSA key");
    }

    /** An RSA key we could not decode still falls back to the verbatim blob rather than rendering empty. */
    @Test
    void treeUndecodableRsaCoseKeyStillShowsRaw() {
        JsonObject ck = CeremonyJson.tree(create(rsa())).getAsJsonObject("attestationObject")
                .getAsJsonObject("authenticatorData").getAsJsonObject("attestedCredentialData")
                .getAsJsonObject("coseKey");
        assertEquals("RSA", ck.get("keyType").getAsString());
        assertTrue(ck.has("raw"), "no n/e decoded → the raw shadow is still shown");
    }

    @Test
    void changedLeafPathsFindsKeyAndSignature() {
        JsonObject a = CeremonyJson.tree(create(okp()));
        CoseKey k2 = okp();
        k2.setX(f(0x99, 32));
        Set<String> keyChange = CeremonyJson.changedLeafPaths(a, CeremonyJson.tree(create(k2)));
        assertTrue(keyChange.contains("attestationObject.authenticatorData.attestedCredentialData.coseKey.x"),
                keyChange.toString());
        assertFalse(keyChange.contains("clientDataJSON.type"));

        Set<String> sigChange = CeremonyJson.changedLeafPaths(
                CeremonyJson.tree(get(f(0xAA, 64))), CeremonyJson.tree(get(f(0xBB, 64))));
        assertEquals(Set.of("signature"), sigChange);

        assertTrue(CeremonyJson.changedLeafPaths(a, a).isEmpty());
    }

    @Test
    void renderMarksOnlyChangedSpans() {
        JsonObject a = CeremonyJson.tree(get(f(0xAA, 64)));
        JsonObject b = CeremonyJson.tree(get(f(0xBB, 64)));
        Set<String> changed = CeremonyJson.changedLeafPaths(a, b);
        CeremonyJson.Rendered r = CeremonyJson.render(b, changed);
        assertEquals(1, r.changed().size());
        CeremonyJson.Span s = r.changed().get(0);
        assertTrue(r.text().substring(s.start(), s.end()).toUpperCase().contains("BB"));
        assertTrue(CeremonyJson.render(a, Set.of()).changed().isEmpty());
    }

    @Test
    void diffEditsReadsBackEveryEditableField() {
        CeremonyModel g = get(f(0xAA, 64));
        JsonObject t = CeremonyJson.tree(g);
        t.getAsJsonObject("authenticatorData").getAsJsonObject("flags").addProperty("backupEligible", true);
        t.getAsJsonObject("authenticatorData").addProperty("signCount", 9);
        t.getAsJsonObject("clientDataJSON").addProperty("origin", "https://evil.example");
        t.getAsJsonObject("authenticatorData").addProperty("rpIdHash", "11".repeat(32));

        CeremonyJson.Edits e = CeremonyJson.diffEdits(pretty(t), g);
        assertFalse(e.parseError());
        assertEquals(Integer.valueOf(0x05 | 0x08), e.flags());
        assertEquals(Long.valueOf(9), e.signCount());
        assertNotNull(e.clientData());
        assertTrue(new String(e.clientData(), UTF_8).contains("evil.example"));
        assertNotNull(e.rpIdHash());
        assertEquals(32, e.rpIdHash().length);
    }

    @Test
    void diffEditsUnchangedYieldsAllNulls() {
        CeremonyModel g = get(f(0xAA, 64));
        CeremonyJson.Edits e = CeremonyJson.diffEdits(pretty(CeremonyJson.tree(g)), g);
        assertFalse(e.parseError());
        assertNull(e.flags());
        assertNull(e.signCount());
        assertNull(e.clientData());
        assertNull(e.rpIdHash());
    }

    @Test
    void diffEditsBadJsonFlagsParseError() {
        assertTrue(CeremonyJson.diffEdits("{ not valid", get(f(0xAA, 64))).parseError());
    }

    @Test
    void renderHighlightsAMemberRetypedFromScalarToObject() {
        // A leaf whose edited value becomes an object/array must still be coloured (regression guard).
        JsonObject orig = CeremonyJson.tree(get(f(0xAA, 64)));
        JsonObject edited = CeremonyJson.tree(get(f(0xAA, 64)));
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "present");
        edited.getAsJsonObject("clientDataJSON").add("origin", obj); // string → object
        Set<String> changed = CeremonyJson.changedLeafPaths(orig, edited);
        assertTrue(changed.contains("clientDataJSON.origin"), changed.toString());
        CeremonyJson.Rendered r = CeremonyJson.render(edited, changed);
        assertFalse(r.changed().isEmpty(), "a retyped member must be highlighted, not silently uncoloured");
        assertTrue(r.changed().stream().anyMatch(s -> r.text().substring(s.start(), s.end()).contains("status")),
                "the changed span should cover the new object value");
    }

    // ---- standalone field decode for the Check panel (real CBOR → editor-tab JSON) -----

    @Test
    void attestationObjectJsonDecodesRealCborLikeTheEditorTab() {
        // Build a real fmt=none attestation (EC2/ES256 key), encode to CBOR via the codec, then confirm the
        // Check panel's standalone decode yields the SAME structured JSON the editor tab shows - not raw hex.
        CoseKey key = new CoseKey();
        key.setKty(2);
        key.setAlg(-7);
        key.setCrv(1);
        key.setX(f(0x11, 32));
        key.setY(f(0x22, 32)); // no raw shadow → encodeCoseKey rebuilds EC2 from fields
        AuthenticatorData a = new AuthenticatorData();
        a.setRpIdHash(f(0x74, 32));
        a.setFlags(0x45); // UP UV AT
        a.setSignCount(1);
        a.setAaguid(f(0x01, 16));
        a.setCredentialId(f(0x93, 16));
        a.setCredentialPublicKey(key);
        AttestationObject o = new AttestationObject();
        o.setFmt("none");
        o.setAuthData(a);
        byte[] cbor = new Webauthn4jCborCodec().encodeAttestationObject(o);

        String json = CeremonyJson.attestationObjectJson(cbor);
        assertNotNull(json);
        assertTrue(json.contains("\"fmt\": \"none\""), json);
        assertTrue(json.contains("\"attestedCredentialData\""), json);
        assertTrue(json.contains("\"keyType\": \"EC2\""), json);
        assertTrue(json.contains("\"algorithm\": \"ES256\""), json);
        assertTrue(json.contains("\"userPresent\": true"), json);
    }

    @Test
    void authenticatorDataJsonDecodesAnAssertionHeader() {
        byte[] authData = new byte[37];
        Arrays.fill(authData, 0, 32, (byte) 0x74); // rpIdHash
        authData[32] = 0x05; // flags: UP (0x01) | UV (0x04)
        authData[36] = 0x02; // signCount = 2 (big-endian)
        String json = CeremonyJson.authenticatorDataJson(authData);
        assertNotNull(json);
        assertTrue(json.contains("\"userPresent\": true"), json);
        assertTrue(json.contains("\"userVerified\": true"), json);
        assertTrue(json.contains("\"signCount\": 2"), json);
    }

    @Test
    void fieldJsonReturnsNullForUndecodableBytesNeverThrows() {
        byte[] garbage = {0x01, 0x02, 0x03};
        assertNull(CeremonyJson.attestationObjectJson(garbage));
        assertNull(CeremonyJson.attestationObjectJson(null));
        assertNull(CeremonyJson.authenticatorDataJson(garbage)); // too short for a 37-byte header
        assertNull(CeremonyJson.authenticatorDataJson(null));
    }

    @Test
    void diffEditsRejectsOutOfRangeOrFractionalSignCount() {
        CeremonyModel g = get(f(0xAA, 64));
        JsonObject over = CeremonyJson.tree(g);
        over.getAsJsonObject("authenticatorData").addProperty("signCount", 4294967301L); // > uint32
        assertTrue(CeremonyJson.diffEdits(pretty(over), g).parseError(), "uint32 overflow must be rejected, not truncated");

        JsonObject frac = CeremonyJson.tree(g);
        frac.getAsJsonObject("authenticatorData").addProperty("signCount", 1.5); // non-integer
        assertTrue(CeremonyJson.diffEdits(pretty(frac), g).parseError(), "fractional signCount must be rejected");

        JsonObject ok = CeremonyJson.tree(g);
        ok.getAsJsonObject("authenticatorData").addProperty("signCount", 4294967295L); // max uint32 - accepted
        CeremonyJson.Edits e = CeremonyJson.diffEdits(pretty(ok), g);
        assertFalse(e.parseError());
        assertEquals(Long.valueOf(4294967295L), e.signCount());
    }

    @Test
    void diffEditsRejectsMalformedRpIdHashWithAReason() {
        CeremonyModel g = get(f(0xAA, 64)); // captured rpIdHash = 0x74 * 32

        // Adding a character (odd length) - was silently dropped before; now a specific, operator-facing error.
        JsonObject odd = CeremonyJson.tree(g);
        odd.getAsJsonObject("authenticatorData").addProperty("rpIdHash", "74".repeat(32) + "A");
        CeremonyJson.Edits e1 = CeremonyJson.diffEdits(pretty(odd), g);
        assertTrue(e1.parseError(), "an odd-length rpIdHash must be rejected, not dropped");
        assertNotNull(e1.error());
        assertTrue(e1.error().toLowerCase().contains("rpidhash"), e1.error());

        // Same character length (64) but a non-hex digit - the "same length, still refused" case.
        JsonObject nonHex = CeremonyJson.tree(g);
        nonHex.getAsJsonObject("authenticatorData").addProperty("rpIdHash", "G" + "1".repeat(63));
        assertTrue(CeremonyJson.diffEdits(pretty(nonHex), g).parseError());

        // Valid hex but the wrong length (66 digits = 33 bytes) - would overflow the fixed 32-byte slot.
        JsonObject longHex = CeremonyJson.tree(g);
        longHex.getAsJsonObject("authenticatorData").addProperty("rpIdHash", "11".repeat(33));
        assertTrue(CeremonyJson.diffEdits(pretty(longHex), g).parseError());
    }

    @Test
    void diffEditsAcceptsHexAndBase64RpIdHashOf32Bytes() {
        CeremonyModel g = get(f(0xAA, 64)); // captured rpIdHash = 0x74 * 32
        byte[] target = f(0x5A, 32);

        // Displayed hex form, changed from the captured value.
        JsonObject hex = CeremonyJson.tree(g);
        hex.getAsJsonObject("authenticatorData").addProperty("rpIdHash", "5A".repeat(32));
        CeremonyJson.Edits eh = CeremonyJson.diffEdits(pretty(hex), g);
        assertFalse(eh.parseError(), eh.error());
        assertArrayEquals(target, eh.rpIdHash());

        // base64url of the same 32 bytes - a paste convenience, accepted because it decodes to exactly 32 bytes.
        JsonObject b64 = CeremonyJson.tree(g);
        b64.getAsJsonObject("authenticatorData")
                .addProperty("rpIdHash", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(target));
        CeremonyJson.Edits eb = CeremonyJson.diffEdits(pretty(b64), g);
        assertFalse(eb.parseError(), eb.error());
        assertArrayEquals(target, eb.rpIdHash());

        // Standard base64 (padded, with '/') of a 32-byte hash - rejected by the url decoder, so it exercises
        // the SECOND decoder in the fallback loop. 0xFF*32 encodes to "////…//8=" ('/' makes getUrlDecoder throw).
        byte[] std = f(0xFF, 32);
        JsonObject stdObj = CeremonyJson.tree(g);
        stdObj.getAsJsonObject("authenticatorData")
                .addProperty("rpIdHash", java.util.Base64.getEncoder().encodeToString(std));
        CeremonyJson.Edits es = CeremonyJson.diffEdits(pretty(stdObj), g);
        assertFalse(es.parseError(), es.error());
        assertArrayEquals(std, es.rpIdHash());
    }

    @Test
    void diffEditsLeavesRpIdHashUnarmedWhenReEncodedToTheSameBytes() {
        // Re-typing the current hash in a different-but-byte-identical form (base64url of the captured
        // rpIdHash) is not a change: it parses and equals the original 32 bytes, so it must NOT arm an edit
        // (no spurious forced re-sign) and must not error - the Arrays.equals skip branch.
        CeremonyModel g = get(f(0xAA, 64)); // captured rpIdHash = 0x74 * 32
        JsonObject t = CeremonyJson.tree(g);
        t.getAsJsonObject("authenticatorData")
                .addProperty("rpIdHash", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(f(0x74, 32)));
        CeremonyJson.Edits e = CeremonyJson.diffEdits(pretty(t), g);
        assertFalse(e.parseError(), e.error());
        assertNull(e.rpIdHash());
    }
}
