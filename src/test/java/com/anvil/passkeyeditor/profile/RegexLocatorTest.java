package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import com.anvil.passkeyeditor.attacks.AssertionForger;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Gate for the {@link FieldLocator.Kind#REGEX} locator. The key correctness claim: a
 * regex locator returns the same byte span the proven structural PATH locator does, so the entire
 * write path (unwrap → forge → re-wrap → splice) is identical regardless of how a field was addressed.
 */
class RegexLocatorTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = RegexLocatorTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    private static byte[] slice(byte[] b, int[] span) {
        return Arrays.copyOfRange(b, span[0], span[1]);
    }

    /** A regex locator with a capture group resolves the IDENTICAL span as the equivalent dotted path. */
    @Test
    void regexLocatesSameSpanAsPathOnRealFixture() throws Exception {
        byte[] body = load("webauthn-io-auth");

        int[] pathSpan = FieldLocator.of("response.response.signature").locate(body);
        int[] regexSpan = FieldLocator.regex("\"signature\":\"([^\"]+)\"").locate(body);

        assertNotNull(pathSpan, "path locates the nested signature");
        assertNotNull(regexSpan, "regex locates the signature");
        assertArrayEquals(pathSpan, regexSpan, "regex group-1 span == structural path span");
        // And the value is the real assertion signature (base64url DER), not a neighbouring field.
        byte[] value = slice(body, regexSpan);
        assertTrue(new String(value, StandardCharsets.US_ASCII).startsWith("1C5oxr"),
                "regex captured the signature value");
    }

    /** A regex locator drives a full re-sign round-trip end-to-end, exactly like a path locator would. */
    @Test
    void regexLocatorReSignRoundTrip() throws Exception {
        byte[] body = load("webauthn-io-auth");
        FieldLocator sigLoc = FieldLocator.regex("\"signature\":\"([^\"]+)\"");
        FieldLocator adLoc = FieldLocator.regex("\"authenticatorData\":\"([^\"]+)\"");
        FieldLocator cdLoc = FieldLocator.regex("\"clientDataJSON\":\"([^\"]+)\"");

        byte[] ad = CODEC.unwrap(slice(body, adLoc.locate(body))).inner();
        byte[] cd = CODEC.unwrap(slice(body, cdLoc.locate(body))).inner();
        WrapperCodec.Unwrapped sigUw = CODEC.unwrap(slice(body, sigLoc.locate(body)));

        Es256Signer signer = Es256Signer.generate();
        byte[] forged = new AssertionForger().sign(ad, cd, signer);
        byte[] newBody = JsonValueEditor.splice(body, sigLoc.locate(body), CODEC.rewrap(forged, sigUw.spec()));

        // Re-locate via the SAME regex on the emitted (different-length) body; it must round-trip + verify.
        byte[] relocated = CODEC.unwrap(slice(newBody, sigLoc.locate(newBody))).inner();
        assertArrayEquals(forged, relocated, "forged signature survives regex re-wrap + splice round-trip");
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(signer.keyPair().getPublic());
        verifier.update(AssertionForger.signedInput(ad, cd));
        assertTrue(verifier.verify(relocated), "regex-located forged assertion verifies under our key");
    }

    /** No capture group → the whole match (group 0) is the span. */
    @Test
    void regexWithoutGroupUsesWholeMatch() {
        byte[] body = "{\"a\":1,\"tok\":\"XYZ\"}".getBytes(StandardCharsets.UTF_8);
        int[] span = FieldLocator.regex("XYZ").locate(body);
        assertNotNull(span);
        assertEquals("XYZ", new String(slice(body, span), StandardCharsets.US_ASCII));
    }

    /** Byte offsets stay correct when a multi-byte UTF-8 char precedes the match (ISO-8859-1 scan). */
    @Test
    void regexByteOffsetsSurviveMultibytePrefix() {
        // "café" - the 'é' is two UTF-8 bytes, so a char-index span would be off by one vs the byte span.
        byte[] body = "{\"x\":\"café\",\"signature\":\"ABCD\"}".getBytes(StandardCharsets.UTF_8);
        int[] span = FieldLocator.regex("\"signature\":\"([^\"]+)\"").locate(body);
        assertNotNull(span);
        assertArrayEquals("ABCD".getBytes(StandardCharsets.US_ASCII), slice(body, span),
                "the span addresses the correct BYTES despite the multi-byte prefix");
    }

    /**
     * AUDIT M1 regression: a catastrophic-backtracking profile regex must ABORT (via the step budget) and
     * return null quickly, not hang the per-request UI thread. Without the budget this does not return.
     */
    @Test
    void catastrophicRegexAbortsQuicklyReturningNull() {
        byte[] body = ("a".repeat(40) + "X").getBytes(StandardCharsets.US_ASCII); // no 'b' → forces full backtrack
        FieldLocator evil = FieldLocator.regex("(.*a){20}b");
        assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                assertNull(evil.locate(body), "catastrophic regex trips the step budget → null, no hang"));
    }

    /** A non-matching pattern and an invalid pattern both yield null - never an exception in decode. */
    @Test
    void regexNoMatchAndBadPatternReturnNull() {
        byte[] body = "{\"signature\":\"ABCD\"}".getBytes(StandardCharsets.UTF_8);
        assertNull(FieldLocator.regex("\"nothere\":\"([^\"]+)\"").locate(body), "no match → null");
        assertNull(FieldLocator.regex("([unterminated").locate(body), "invalid regex → null, no throw");
    }

    /** withEncoding preserves the locator's kind + address, swapping only the encoding (Check panel tick). */
    @Test
    void withEncodingPreservesKindAndAddress() {
        FieldLocator path = FieldLocator.of("a.b.c").withEncoding(EncodingSpec.autoUrlEncoded());
        assertEquals(FieldLocator.Kind.PATH, path.kind());
        assertEquals("a.b.c", path.candidates().get(0).toString());
        assertTrue(path.encoding().urlEncoded());

        FieldLocator rx = FieldLocator.regex("x([0-9])").withEncoding(EncodingSpec.raw());
        assertEquals(FieldLocator.Kind.REGEX, rx.kind());
        assertEquals("x([0-9])", rx.regex());
        assertEquals(EncodingSpec.Base64Kind.NONE, rx.encoding().base64());
    }

    /** A regex locator works as a profile field locator through PhaseSpec.locate (end-to-end wiring). */
    @Test
    void regexLocatorWiresThroughPhaseSpec() throws Exception {
        byte[] body = load("webauthn-io-auth");
        PhaseSpec spec = new PhaseSpec(java.util.Map.of(
                Field.SIGNATURE, FieldLocator.regex("\"signature\":\"([^\"]+)\"")));
        int[] span = spec.locate(Field.SIGNATURE, body);
        assertNotNull(span, "PhaseSpec routes through a REGEX FieldLocator");
        assertArrayEquals(FieldLocator.of("response.response.signature").locate(body), span,
                "PhaseSpec regex span == path span");
    }
}
