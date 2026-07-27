package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.attacks.RegistrationEditor;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * - the registration tab's re-encode → re-wrap → splice wire pipeline, end-to-end and
 * headless (the CREATE counterpart of {@link ForgedRequestWireTest}).
 *
 * {@link com.anvil.passkeyeditor.attacks.RegistrationEditorTest} proves the inner CBOR re-encode; this
 * proves the bytes the product actually puts on the wire: {@code CeremonyRequestEditor.applyRegistrationEdits()}
 * unwraps the {@code attestationObject}, re-encodes it ({@link RegistrationEditor}), re-wraps the new
 * CBOR in the field's captured {@code WrapSpec}, and splices it back into the body via
 * {@link JsonValueEditor#spliceAll}. A regression in the re-wrap, the chosen {@code WrapSpec}, or the
 * span/splice would pass every other test and fail only live in Burp - so this exercises the same recipe on
 * the real captured registration body and re-parses the emitted body.
 */
class ForgedRegistrationWireTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();
    private final RegistrationEditor editor = new RegistrationEditor(cbor);

    private static String loadFixture(String name) {
        try (InputStream in = ForgedRegistrationWireTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The wrapped wire value (base64url token) of a string member in the body, as bytes. */
    private static byte[] wrappedValue(byte[] body, String field) {
        Matcher m = Pattern.compile("\"" + field + "\":\"([^\"]+)\"")
                .matcher(new String(body, StandardCharsets.UTF_8));
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + field);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    /** Decode the attestationObject out of an emitted body (unwrap the field, then CBOR-decode). */
    private AttestationObject attestationOf(byte[] body) {
        return cbor.decodeAttestationObject(wrapper.unwrap(wrappedValue(body, "attestationObject")).inner());
    }

    // ---- credentialId swap: only the attestationObject changes; the swapped id is on the wire ----

    @Test
    void credentialIdSwapReWritesAttestationObjectOnTheWire() {
        byte[] body = loadFixture("reg-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped att = wrapper.unwrap(wrappedValue(body, "attestationObject"));
        int[] attSpan = JsonValueEditor.findStringValueSpan(body, "attestationObject");

        byte[] victimCredId = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 0x01, 0x02};
        AttestationObject decoded = cbor.decodeAttestationObject(att.inner());
        byte[] newCbor = editor.edit(decoded, null, victimCredId, null);
        byte[] attWire = wrapper.rewrap(newCbor, att.spec());
        byte[] outBody = JsonValueEditor.spliceAll(body, List.of(attSpan), List.of(attWire));

        // Re-parse the emitted body: the swapped credentialId is on the wire, fmt forced to none.
        AttestationObject out = attestationOf(outBody);
        assertEquals("none", out.fmt());
        assertArrayEquals(victimCredId, out.authData().credentialId(), "emitted body carries the swapped credId");
        // clientDataJSON is untouched on the wire (only the attestationObject was edited).
        assertArrayEquals(wrappedValue(body, "clientDataJSON"), wrappedValue(outBody, "clientDataJSON"),
                "clientDataJSON unchanged");
        // The re-wrapped attestationObject must be valid base64url (no '+','/','=' - the live #10 finding).
        String attValue = new String(wrappedValue(outBody, "attestationObject"), StandardCharsets.US_ASCII);
        assertFalse(attValue.contains("+") || attValue.contains("/") || attValue.contains("="),
                "emitted attestationObject must be valid base64url; got " + attValue);
    }

    // ---- plant: the emitted body embeds OUR credential key ------------------------------------

    @Test
    void plantReWritesAttestationObjectToOurKeyOnTheWire() {
        byte[] body = loadFixture("reg-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped att = wrapper.unwrap(wrappedValue(body, "attestationObject"));
        int[] attSpan = JsonValueEditor.findStringValueSpan(body, "attestationObject");

        Es256Signer attacker = Es256Signer.generate();
        byte[] newCbor = editor.edit(cbor.decodeAttestationObject(att.inner()), attacker, null, null);
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(attSpan), List.of(wrapper.rewrap(newCbor, att.spec())));

        AttestationObject out = attestationOf(outBody);
        assertEquals("none", out.fmt());
        assertArrayEquals(attacker.publicCoseKey().raw(), out.authData().credentialPublicKey().raw(),
                "the emitted registration embeds our planted key");
    }

    // ---- registration flag edit: UV cleared on the wire, AT preserved -------------------------

    @Test
    void flagEditReWritesAuthDataFlagsOnTheWire() {
        byte[] body = loadFixture("reg-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped att = wrapper.unwrap(wrappedValue(body, "attestationObject"));
        int[] attSpan = JsonValueEditor.findStringValueSpan(body, "attestationObject");

        AttestationObject decoded = cbor.decodeAttestationObject(att.inner());
        int captured = decoded.authData().flags();
        int uvCleared = captured & ~AuthenticatorData.FLAG_UV;
        byte[] newCbor = editor.edit(decoded, null, null, uvCleared);
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(attSpan), List.of(wrapper.rewrap(newCbor, att.spec())));

        AttestationObject out = attestationOf(outBody);
        assertFalse(out.authData().hasFlag(AuthenticatorData.FLAG_UV), "UV cleared on the wire");
        assertTrue(out.authData().hasFlag(AuthenticatorData.FLAG_AT), "AT preserved (still a registration)");
    }

    // ---- the no-op contracts -------------------------------------------------------------------

    @Test
    void emptyOverrideSetForwardsTheByteIdenticalOriginal() {
        // The editor stages NO override when no registration edit is armed (applyRegistrationEdits removes
        // F_ATTESTATION), and getRequest() then short-circuits on the empty override set. This models that
        // forward path: an empty splice returns the original body byte-for-byte. (The inner-CBOR no-op is
        // separately pinned in RegistrationEditorTest.uneditedNoneRegistrationReEncodesByteIdentically.)
        byte[] body = loadFixture("reg-clean.json").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(body, JsonValueEditor.spliceAll(body, List.of(), List.of()),
                "no registration override ⇒ byte-identical original request body");
    }

    @Test
    void noOpEditThroughTheFullRecipeReproducesTheOriginalBody() {
        // Run the EXACT product recipe - unwrap → decode → RegistrationEditor.edit → rewrap in the field's
        // CAPTURED spec → splice - with a no-op edit, and assert the emitted body is byte-identical to the
        // original. This catches a re-encode OR a re-wrap-spec drift that the empty-splice test cannot - the
        // 'passes every test, drifts only live in Burp' freeze-safety class. (reg-clean is fmt=none, so a
        // no-op edit re-encodes byte-identically per RegistrationEditorTest.)
        byte[] body = loadFixture("reg-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped att = wrapper.unwrap(wrappedValue(body, "attestationObject"));
        int[] attSpan = JsonValueEditor.findStringValueSpan(body, "attestationObject");
        byte[] sameCbor = editor.edit(cbor.decodeAttestationObject(att.inner()), null, null, null);
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(attSpan), List.of(wrapper.rewrap(sameCbor, att.spec())));
        assertArrayEquals(body, outBody,
                "a no-op edit through unwrap→edit→rewrap→splice reproduces the original body byte-for-byte");
    }
}
