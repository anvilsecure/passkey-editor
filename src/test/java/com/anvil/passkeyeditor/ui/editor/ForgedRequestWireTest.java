package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.attacks.AssertionForger;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.util.AuthDataEditor;
import com.anvil.passkeyeditor.util.JsonValueEditor;

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
 * the editor's forge → re-wrap → splice wire pipeline, end-to-end and headless.
 *
 * {@code ForgeryOracleTest} proves the inner-bytes crypto; this proves the bytes the product actually
 * puts on the wire. {@code CeremonyRequestEditor.getRequest()} unwraps each field, re-signs over the
 * inner bytes, re-wraps the fresh DER signature (a variable-length 70/71/72-byte value, unlike the
 * captured fixture's), and splices it back into the body via {@code JsonValueEditor.spliceAll}. A
 * regression in which fields are re-wrapped, the chosen {@code WrapSpec}, or the span/splice merge would
 * pass every other test and fail only live in Burp - so this exercises the same recipe on the real
 * captured authentication body and re-parses the emitted body to confirm its signature verifies.
 */
class ForgedRequestWireTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();
    private final CborCodec cbor = new Webauthn4jCborCodec();

    private static String loadFixture(String name) {
        try (InputStream in = ForgedRequestWireTest.class.getResourceAsStream("/fixtures/" + name)) {
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

    // ---- pure re-sign: only the signature field changes on the wire ----------------------------

    @Test
    void pureReSignEmitsABodyWhoseRepArsedSignatureVerifies() throws Exception {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);

        // Production-shaped decode: unwrap each field + record its splice span in the body.
        WrapperCodec.Unwrapped cd = wrapper.unwrap(wrappedValue(body, "clientDataJSON"));
        WrapperCodec.Unwrapped ad = wrapper.unwrap(wrappedValue(body, "authenticatorData"));
        WrapperCodec.Unwrapped sig = wrapper.unwrap(wrappedValue(body, "signature"));
        int[] sigSpan = JsonValueEditor.findStringValueSpan(body, "signature");

        // Re-sign over the inner bytes (UV preserved), re-wrap the fresh DER, splice back.
        Es256Signer signer = Es256Signer.generate();
        byte[] forged = new AssertionForger().sign(ad.inner(), cd.inner(), signer);
        byte[] sigWire = wrapper.rewrap(forged, sig.spec());
        byte[] outBody = JsonValueEditor.spliceAll(body, List.of(sigSpan), List.of(sigWire));

        assertTrue(bodySignatureVerifies(outBody, ad.inner(), cd.inner(), signer.keyPair().getPublic()),
                "the re-parsed emitted body's signature verifies under the forging key");
        // The other fields are untouched on the wire.
        assertArrayEquals(wrappedValue(body, "clientDataJSON"), wrappedValue(outBody, "clientDataJSON"),
                "clientDataJSON unchanged");
        assertArrayEquals(wrappedValue(body, "authenticatorData"), wrappedValue(outBody, "authenticatorData"),
                "authenticatorData unchanged");
    }

    /**
     * A fresh ES256 DER signature is variable length (70/71/72 bytes) depending on the leading bits of
     * r/s - re-wrapping it produces a different-length token in a different-length body every time. Run
     * many independent signers so short-DER re-wrap + splice is exercised, not just the 72-byte happy case.
     */
    @Test
    void variableLengthDerSignaturesAllReWrapAndVerify() throws Exception {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped cd = wrapper.unwrap(wrappedValue(body, "clientDataJSON"));
        WrapperCodec.Unwrapped ad = wrapper.unwrap(wrappedValue(body, "authenticatorData"));
        WrapperCodec.Unwrapped sig = wrapper.unwrap(wrappedValue(body, "signature"));
        int[] sigSpan = JsonValueEditor.findStringValueSpan(body, "signature");

        for (int i = 0; i < 40; i++) {
            Es256Signer signer = Es256Signer.generate();
            byte[] forged = new AssertionForger().sign(ad.inner(), cd.inner(), signer);
            byte[] outBody = JsonValueEditor.spliceAll(body,
                    List.of(sigSpan), List.of(wrapper.rewrap(forged, sig.spec())));
            assertTrue(bodySignatureVerifies(outBody, ad.inner(), cd.inner(), signer.keyPair().getPublic()),
                    "iteration " + i + " (DER len=" + forged.length + "): emitted body must verify");
            // The re-wrapped signature must be valid base64url - a base64url-strict RP rejects '+','/','='
            // ("...was not a base64url string"). Defends the live #10 finding at the integration level.
            String sigValue = new String(wrappedValue(outBody, "signature"), StandardCharsets.US_ASCII);
            assertFalse(sigValue.contains("+") || sigValue.contains("/") || sigValue.contains("="),
                    "iteration " + i + ": emitted signature must be valid base64url; got " + sigValue);
        }
    }

    // ---- combined edit: authData (UV cleared) + signature both change on the wire ---------------

    @Test
    void uvClearedForgeReWritesBothAuthDataAndSignature() throws Exception {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);
        WrapperCodec.Unwrapped cd = wrapper.unwrap(wrappedValue(body, "clientDataJSON"));
        WrapperCodec.Unwrapped ad = wrapper.unwrap(wrappedValue(body, "authenticatorData"));
        WrapperCodec.Unwrapped sig = wrapper.unwrap(wrappedValue(body, "signature"));
        int[] adSpan = JsonValueEditor.findStringValueSpan(body, "authenticatorData");
        int[] sigSpan = JsonValueEditor.findStringValueSpan(body, "signature");

        byte[] editedAd = AuthDataEditor.withFlags(ad.inner(), AuthenticatorData.FLAG_UP); // clear UV
        Es256Signer signer = Es256Signer.generate();
        byte[] forged = new AssertionForger().sign(editedAd, cd.inner(), signer);

        // Two-field splice (authData precedes signature in the body) - the editor's multi-field write-back.
        byte[] outBody = JsonValueEditor.spliceAll(body,
                List.of(adSpan, sigSpan),
                List.of(wrapper.rewrap(editedAd, ad.spec()), wrapper.rewrap(forged, sig.spec())));

        // Re-parse: the emitted authData decodes to UV=0, and the signature verifies over the EDITED authData.
        byte[] reAuthData = wrapper.unwrap(wrappedValue(outBody, "authenticatorData")).inner();
        assertEquals((byte) 0x01, reAuthData[AuthenticatorData.FLAGS_OFFSET], "emitted authData is UV=0");
        assertTrue(bodySignatureVerifies(outBody, editedAd, cd.inner(), signer.keyPair().getPublic()),
                "signature in the emitted body covers the edited (UV=0) authData");
    }

    // ---- the no-op contract: an unforged build is byte-identical -------------------------------

    @Test
    void unforgedBuildIsByteIdenticalOriginal() {
        byte[] body = loadFixture("auth-clean.json").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(body, JsonValueEditor.spliceAll(body, List.of(), List.of()),
                "no overrides ⇒ byte-identical original request body");
    }
}
