package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.attacks.AssertionForger;
import com.anvil.passkeyeditor.attacks.CrossOriginForgeAttack;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.webauthn4j.util.SignatureUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * The correctness gate for the framing (clickjacking) forge, end-to-end and headless: apply the
 * {@code crossOrigin=true} + {@code topOrigin} edit to a real captured {@code clientDataJSON}, re-sign, and
 * prove the emitted body's signature verifies under webauthn4j's own ES256 verifier over
 * {@code authenticatorData ‖ SHA-256(edited clientDataJSON wire bytes)}. That is the load-bearing claim:
 * the bytes the RP will verify are exactly the cross-origin {@code clientDataJSON} we forged. Mirrors
 * {@code ForgedRequestWireTest}: it runs the editor's real forge → re-wrap → splice recipe on the wire body.
 */
class CrossOriginForgeWireTest {

    private static final String ATTACKER = "https://attacker.example";

    private final WrapperCodec wrapper = new WrapperCodec.Default();

    private static String loadFixture(String name) {
        try (InputStream in = CrossOriginForgeWireTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test fixture: /fixtures/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The wrapped wire value (the base64url token) of a string member in the body, as bytes. */
    private static byte[] wrappedValue(byte[] body, String field) {
        Matcher m = Pattern.compile("\"" + field + "\":\"([^\"]+)\"")
                .matcher(new String(body, StandardCharsets.UTF_8));
        if (!m.find()) {
            throw new IllegalStateException("field not found: " + field);
        }
        return m.group(1).getBytes(StandardCharsets.US_ASCII);
    }

    /** Verify a wire body's (re-parsed, unwrapped) signature over signedInput(authData, clientData). */
    private boolean bodySignatureVerifies(byte[] body, byte[] innerAuthData, byte[] innerClientData,
                                          PublicKey pub) throws Exception {
        byte[] sig = wrapper.unwrap(wrappedValue(body, "signature")).inner();
        Signature v = SignatureUtil.createES256();
        v.initVerify(pub);
        v.update(AssertionForger.signedInput(innerAuthData, innerClientData));
        return v.verify(sig);
    }

    private static JsonObject parse(byte[] clientDataJson) {
        return JsonParser.parseString(new String(clientDataJson, StandardCharsets.UTF_8)).getAsJsonObject();
    }

    @Test
    void forgedCrossOriginClientDataIsExactlyWhatIsSigned() throws Exception {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);

        // Production-shaped decode: unwrap each field + record the splice spans we will rewrite.
        WrapperCodec.Unwrapped cd = wrapper.unwrap(wrappedValue(body, "clientDataJSON"));
        WrapperCodec.Unwrapped ad = wrapper.unwrap(wrappedValue(body, "authenticatorData"));
        WrapperCodec.Unwrapped sig = wrapper.unwrap(wrappedValue(body, "signature"));
        int[] cdSpan = JsonValueEditor.findStringValueSpan(body, "clientDataJSON");
        int[] sigSpan = JsonValueEditor.findStringValueSpan(body, "signature");

        // The captured ceremony is same-origin: crossOrigin=false, no topOrigin.
        JsonObject before = parse(cd.inner());
        assertEquals("http://localhost:8000", before.get("origin").getAsString());
        assertTrue(!before.get("crossOrigin").getAsBoolean(), "fixture starts same-origin (crossOrigin=false)");

        // Forge cross-origin (leave origin alone), then re-sign over the EDITED clientDataJSON.
        CrossOriginForgeAttack.Result forge = new CrossOriginForgeAttack().forge(cd.inner(), ATTACKER);
        assertTrue(forge.changed());
        byte[] editedCd = forge.clientData();

        Es256Signer signer = Es256Signer.generate();
        byte[] forgedSig = new AssertionForger().sign(ad.inner(), editedCd, signer);

        // The editor's multi-field write-back: rewrap the edited clientDataJSON + the fresh signature, splice both.
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(cdSpan, sigSpan),
                List.of(wrapper.rewrap(editedCd, cd.spec()), wrapper.rewrap(forgedSig, sig.spec())));

        // The emitted clientDataJSON, re-parsed off the wire, is cross-origin - and origin is untouched.
        byte[] reCd = wrapper.unwrap(wrappedValue(outBody, "clientDataJSON")).inner();
        JsonObject after = parse(reCd);
        assertTrue(after.get("crossOrigin").getAsBoolean(), "emitted clientDataJSON is crossOrigin=true");
        assertEquals(ATTACKER, after.get("topOrigin").getAsString(), "emitted clientDataJSON carries topOrigin");
        assertEquals("http://localhost:8000", after.get("origin").getAsString(), "origin left byte-identical");
        assertEquals(before.get("challenge").getAsString(), after.get("challenge").getAsString(),
                "challenge untouched");

        // THE GATE: the signature on the wire verifies over authData ‖ SHA-256(edited clientDataJSON) under
        // webauthn4j's own verifier - i.e. the cross-origin clientDataJSON is exactly what was signed.
        assertTrue(bodySignatureVerifies(outBody, ad.inner(), reCd, signer.keyPair().getPublic()),
                "the re-parsed emitted signature verifies over the forged cross-origin clientDataJSON");

        // authenticatorData is untouched on the wire (only clientDataJSON + signature changed).
        assertArrayEquals(wrappedValue(body, "authenticatorData"), wrappedValue(outBody, "authenticatorData"),
                "authenticatorData unchanged");
    }

    /**
     * The signature must cover the edited clientDataJSON, not the original - a negative control that
     * would catch a bug where the wrong bytes are signed or spliced.
     */
    @Test
    void signatureDoesNotVerifyOverTheOriginalClientData() throws Exception {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped cd = wrapper.unwrap(wrappedValue(body, "clientDataJSON"));
        WrapperCodec.Unwrapped ad = wrapper.unwrap(wrappedValue(body, "authenticatorData"));
        WrapperCodec.Unwrapped sig = wrapper.unwrap(wrappedValue(body, "signature"));
        int[] cdSpan = JsonValueEditor.findStringValueSpan(body, "clientDataJSON");
        int[] sigSpan = JsonValueEditor.findStringValueSpan(body, "signature");

        byte[] editedCd = new CrossOriginForgeAttack().forge(cd.inner(), ATTACKER).clientData();
        Es256Signer signer = Es256Signer.generate();
        byte[] forgedSig = new AssertionForger().sign(ad.inner(), editedCd, signer);
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(cdSpan, sigSpan),
                List.of(wrapper.rewrap(editedCd, cd.spec()), wrapper.rewrap(forgedSig, sig.spec())));

        assertTrue(!bodySignatureVerifies(outBody, ad.inner(), cd.inner(), signer.keyPair().getPublic()),
                "the forged signature must NOT verify over the original (same-origin) clientDataJSON");
    }
}
