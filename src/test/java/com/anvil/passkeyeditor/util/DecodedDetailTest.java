package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * Pins the pure render-forms behind the Check panel's per-field decoded-detail expander:
 * printable-ASCII detection, full hex, pretty JSON, byte length, and the composed render block. The UI is
 * a thin renderer over these, so green here == correct expander content.
 */
class DecodedDetailTest {

    @Test
    void hexIsFullLowercaseAndUntruncated() {
        byte[] b = {0x00, (byte) 0xff, 0x10, (byte) 0xab};
        assertEquals("00ff10ab", DecodedDetail.hex(b));
        // 40 bytes -> 80 hex chars, no "…" truncation like the one-line Check summary does.
        byte[] big = new byte[40];
        assertEquals(80, DecodedDetail.hex(big).length());
        assertEquals("", DecodedDetail.hex(null));
        assertEquals("", DecodedDetail.hex(new byte[0]));
    }

    @Test
    void printableAsciiDetection() {
        assertTrue(DecodedDetail.isPrintableAscii("webauthnio-2c3f".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(DecodedDetail.isPrintableAscii("{\"type\":\"webauthn.get\"}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(DecodedDetail.isPrintableAscii("line1\nline2\t!".getBytes(StandardCharsets.US_ASCII)));
        // A DER/CBOR-ish blob with high bytes is NOT printable -> no ASCII line.
        assertFalse(DecodedDetail.isPrintableAscii(new byte[]{0x30, 0x45, 0x02, (byte) 0x81, (byte) 0xc0}));
        assertFalse(DecodedDetail.isPrintableAscii(new byte[]{0x00})); // NUL is a control char
        assertFalse(DecodedDetail.isPrintableAscii(null));
        assertFalse(DecodedDetail.isPrintableAscii(new byte[0]));
    }

    @Test
    void prettyJsonOnlyForObjectsAndArrays() {
        String json = DecodedDetail.prettyJson("{\"type\":\"webauthn.get\",\"origin\":\"https://webauthn.io\"}"
                .getBytes(StandardCharsets.UTF_8));
        assertTrue(json.contains("\"type\": \"webauthn.get\""), json);
        assertTrue(json.contains("\n"), "pretty JSON is multi-line");
        assertTrue(DecodedDetail.prettyJson("[1,2,3]".getBytes(StandardCharsets.UTF_8)).contains("\n"));
        // A bare scalar / non-JSON / raw bytes -> no JSON block.
        assertNull(DecodedDetail.prettyJson("webauthnio-2c3f".getBytes(StandardCharsets.US_ASCII)));
        assertNull(DecodedDetail.prettyJson("42".getBytes(StandardCharsets.US_ASCII)));
        assertNull(DecodedDetail.prettyJson(new byte[]{0x30, 0x45, (byte) 0x81}));
        assertNull(DecodedDetail.prettyJson(null));
    }

    @Test
    void prettyJsonLeavesUrlPunctuationLiteral() {
        // disableHtmlEscaping -> '=', '<', '&' inside an origin/challenge are not turned into = etc.
        String json = DecodedDetail.prettyJson("{\"origin\":\"https://x.io?a=1&b=2\"}".getBytes(StandardCharsets.UTF_8));
        assertTrue(json.contains("a=1&b=2"), json);
    }

    @Test
    void renderUserHandleSurfacesTheAsciiHiddenBehindTruncatedHex() {
        // The concrete case from field testing: base64url d2ViYXV0aG5pby0... decodes to ASCII "webauthnio-..." but the
        // one-line Check summary shows only "hex=776562617574686e…". The expander must reveal full hex + ASCII.
        byte[] userHandle = Base64.getUrlDecoder().decode("d2ViYXV0aG5pby0yYzNm"); // "webauthnio-2c3f"
        String out = DecodedDetail.render("auto: base64url", userHandle);
        assertTrue(out.contains("encoding : auto: base64url"), out);
        assertTrue(out.contains("length   : " + userHandle.length + " bytes"), out);
        assertTrue(out.contains("hex      : 776562617574686e696f2d32633366"), out);
        assertTrue(out.contains("ascii    : webauthnio-2c3f"), out);
        assertFalse(out.contains("json"), "a plain handle is not JSON");
    }

    @Test
    void renderClientDataJsonShowsPrettyJsonNotDuplicateAscii() {
        // clientDataJSON is BOTH printable-ASCII and valid JSON; the ASCII line would duplicate the JSON, so
        // only the pretty JSON is shown (the operator's feedback: ascii + json were redundant for clientDataJSON).
        byte[] cdj = "{\"type\":\"webauthn.get\",\"challenge\":\"abc\"}".getBytes(StandardCharsets.UTF_8);
        String out = DecodedDetail.render("auto: base64url", cdj);
        assertFalse(out.contains("ascii    :"), "ASCII duplicates the JSON for clientDataJSON: " + out);
        assertTrue(out.contains("json     :"), out);
        assertTrue(out.contains("\"type\": \"webauthn.get\""), out);
    }

    @Test
    void renderBinaryBlobShowsHexOnly() {
        byte[] der = {0x30, 0x45, 0x02, 0x20, (byte) 0x8c, (byte) 0xff};
        String out = DecodedDetail.render("auto: base64url", der);
        assertTrue(out.contains("length   : 6 bytes"), out);
        assertTrue(out.contains("hex      : 304502208cff"), out);
        assertFalse(out.contains("ascii"), "a DER signature is not printable -> no ASCII line");
        assertFalse(out.contains("json"), "a DER signature is not JSON -> no JSON line");
    }

    @Test
    void renderHandlesNullBytesGracefully() {
        assertEquals("(no decoded bytes for this field)", DecodedDetail.render("auto", null));
    }

    @Test
    void renderOmitsEncodingLineWhenBlank() {
        String out = DecodedDetail.render(null, "hi".getBytes(StandardCharsets.US_ASCII));
        assertFalse(out.contains("encoding"), out);
        assertTrue(out.startsWith("length   : 2 bytes"), out);
        assertTrue(DecodedDetail.render("  ", new byte[]{1}).startsWith("length   : 1 byte"), "singular byte + blank enc");
    }
}
