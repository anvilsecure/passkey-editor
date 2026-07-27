package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The shared byte-surgical JSON value editor: locate a member's string value and replace exactly those
 * bytes. Underpins both the request editor's signature splice and the UV-downgrade attack - so its
 * correctness (especially "change only the target, nothing else") is load-bearing for byte-identity.
 */
class JsonValueEditorTest {

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String str(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    @Test
    void findsSimpleStringValueSpanExclusiveOfQuotes() {
        byte[] body = utf8("{\"userVerification\":\"preferred\"}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "userVerification");
        assertEquals("preferred", str(java.util.Arrays.copyOfRange(body, span[0], span[1])));
    }

    @Test
    void spliceReplacesOnlyTheSpanAndPreservesEverythingElse() {
        byte[] body = utf8("{\"a\":\"x\",\"userVerification\":\"preferred\",\"z\":\"y\"}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "userVerification");
        byte[] out = JsonValueEditor.splice(body, span, utf8("discouraged"));
        assertEquals("{\"a\":\"x\",\"userVerification\":\"discouraged\",\"z\":\"y\"}", str(out));
    }

    @Test
    void toleratesWhitespaceAroundColon() {
        byte[] body = utf8("{ \"userVerification\" :  \"required\" }");
        int[] span = JsonValueEditor.findStringValueSpan(body, "userVerification");
        assertEquals("required", str(java.util.Arrays.copyOfRange(body, span[0], span[1])));
        byte[] out = JsonValueEditor.splice(body, span, utf8("discouraged"));
        assertEquals("{ \"userVerification\" :  \"discouraged\" }", str(out));
    }

    @Test
    void findsNestedKeyAnywhereInBody() {
        // The reg-options shape: userVerification nested under authenticatorSelection.
        byte[] body = utf8("{\"authenticatorSelection\":{\"residentKey\":\"discouraged\","
                + "\"userVerification\":\"preferred\"}}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "userVerification");
        assertEquals("preferred", str(java.util.Arrays.copyOfRange(body, span[0], span[1])));
    }

    @Test
    void doesNotFalseMatchLongerKeyContainingTheNeedle() {
        // "requireUserVerification" must NOT match a search for "userVerification" - the quoted-literal
        // needle has a leading quote, and requireUserVerification has a capital 'U' after 'require'.
        byte[] body = utf8("{\"requireUserVerification\":\"true\"}");
        assertNull(JsonValueEditor.findStringValueSpan(body, "userVerification"));
    }

    @Test
    void returnsNullForAbsentKey() {
        assertNull(JsonValueEditor.findStringValueSpan(utf8("{\"x\":\"y\"}"), "userVerification"));
    }

    @Test
    void returnsNullForNonStringValue() {
        // timeout is a number, not a string - no quote-to-quote span.
        assertNull(JsonValueEditor.findStringValueSpan(utf8("{\"timeout\":60000}"), "timeout"));
    }

    @Test
    void bailsOnEscapeInsideValue() {
        // An escaped quote means the value isn't this tool's simple shape; refuse rather than mis-span.
        byte[] body = utf8("{\"k\":\"a\\\"b\"}");
        assertNull(JsonValueEditor.findStringValueSpan(body, "k"));
    }

    @Test
    void spliceToDifferentLengthShiftsTailCorrectly() {
        byte[] body = utf8("{\"k\":\"preferred\",\"tail\":1}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "k");
        byte[] out = JsonValueEditor.splice(body, span, utf8("discouraged")); // longer than "preferred"
        assertEquals("{\"k\":\"discouraged\",\"tail\":1}", str(out));
    }

    @Test
    void nullInputsReturnNullSpan() {
        assertNull(JsonValueEditor.findStringValueSpan(null, "k"));
        assertNull(JsonValueEditor.findStringValueSpan(utf8("{}"), null));
    }

    // ---- spliceAll: the request editor's multi-field write-back (clientDataJSON + authData + signature) -

    @Test
    void spliceAllReplacesEveryFieldRegardlessOfInputOrder() {
        // The assertion-request shape: three string values, replaced together after a re-sign. The spans
        // are supplied out of body order on purpose - spliceAll must apply them highest-offset-first so the
        // earlier replacements don't shift later spans.
        byte[] body = utf8("{\"clientDataJSON\":\"CDJ\",\"authenticatorData\":\"AD\",\"signature\":\"SIG\"}");
        int[] cdj = JsonValueEditor.findStringValueSpan(body, "clientDataJSON");
        int[] ad = JsonValueEditor.findStringValueSpan(body, "authenticatorData");
        int[] sig = JsonValueEditor.findStringValueSpan(body, "signature");

        // Replacements of differing lengths, listed in a deliberately non-sorted order (sig, cdj, ad).
        byte[] out = JsonValueEditor.spliceAll(body,
                java.util.List.of(sig, cdj, ad),
                java.util.List.of(utf8("S2"), utf8("client-data-edited"), utf8("authdata-edited")));

        assertEquals("{\"clientDataJSON\":\"client-data-edited\",\"authenticatorData\":\"authdata-edited\","
                + "\"signature\":\"S2\"}", str(out));
    }

    @Test
    void spliceAllWithASingleSpanMatchesSplice() {
        byte[] body = utf8("{\"k\":\"preferred\"}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "k");
        assertArrayEquals(JsonValueEditor.splice(body, span, utf8("discouraged")),
                JsonValueEditor.spliceAll(body, java.util.List.of(span), java.util.List.of(utf8("discouraged"))));
    }

    @Test
    void spliceAllRejectsMismatchedListLengths() {
        byte[] body = utf8("{\"k\":\"v\"}");
        int[] span = JsonValueEditor.findStringValueSpan(body, "k");
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> JsonValueEditor.spliceAll(body, java.util.List.of(span), java.util.List.of()));
    }

    // ---- findPrimitiveValueSpan: bare (non-string) values, e.g. clientDataJSON's crossOrigin boolean ----

    @Test
    void findsBareBooleanValueSpan() {
        byte[] body = utf8("{\"crossOrigin\":false}");
        int[] span = JsonValueEditor.findPrimitiveValueSpan(body, "crossOrigin");
        assertEquals("false", str(java.util.Arrays.copyOfRange(body, span[0], span[1])));

        byte[] tru = utf8("{\"crossOrigin\":true}");
        int[] span2 = JsonValueEditor.findPrimitiveValueSpan(tru, "crossOrigin");
        assertEquals("true", str(java.util.Arrays.copyOfRange(tru, span2[0], span2[1])));
    }

    @Test
    void primitiveSpanReplaceFlipsBooleanInPlace() {
        byte[] body = utf8("{\"origin\":\"https://rp\",\"crossOrigin\":false}");
        int[] span = JsonValueEditor.findPrimitiveValueSpan(body, "crossOrigin");
        byte[] out = JsonValueEditor.splice(body, span, utf8("true"));
        assertEquals("{\"origin\":\"https://rp\",\"crossOrigin\":true}", str(out));
    }

    @Test
    void findsBareNumberValueSpanAndToleratesWhitespace() {
        byte[] body = utf8("{ \"timeout\" : 60000 , \"x\":1}");
        int[] span = JsonValueEditor.findPrimitiveValueSpan(body, "timeout");
        assertEquals("60000", str(java.util.Arrays.copyOfRange(body, span[0], span[1])));
    }

    @Test
    void primitiveSpanIsNullForStringObjectOrAbsentValue() {
        assertNull(JsonValueEditor.findPrimitiveValueSpan(utf8("{\"origin\":\"https://rp\"}"), "origin"),
                "a string value is not a bare literal");
        assertNull(JsonValueEditor.findPrimitiveValueSpan(utf8("{\"o\":{\"a\":1}}"), "o"),
                "an object value is not a bare literal");
        assertNull(JsonValueEditor.findPrimitiveValueSpan(utf8("{\"a\":1}"), "crossOrigin"),
                "absent key");
        assertNull(JsonValueEditor.findPrimitiveValueSpan(null, "k"));
        assertNull(JsonValueEditor.findPrimitiveValueSpan(utf8("{}"), null));
    }

    // ---- insertMember: add a member to the root object, comma-correct, everything else byte-preserved ----

    @Test
    void insertsMemberIntoEmptyObjectWithoutComma() {
        byte[] out = JsonValueEditor.insertMember(utf8("{}"), "crossOrigin", utf8("true"));
        assertEquals("{\"crossOrigin\":true}", str(out));
    }

    @Test
    void insertsMemberIntoNonEmptyObjectWithLeadingComma() {
        byte[] body = utf8("{\"type\":\"webauthn.get\",\"origin\":\"https://rp\"}");
        byte[] out = JsonValueEditor.insertMember(body, "crossOrigin", utf8("true"));
        assertEquals("{\"type\":\"webauthn.get\",\"origin\":\"https://rp\",\"crossOrigin\":true}", str(out));
    }

    @Test
    void insertsQuotedStringMemberVerbatim() {
        byte[] body = utf8("{\"crossOrigin\":true}");
        byte[] out = JsonValueEditor.insertMember(body, "topOrigin", utf8("\"https://attacker.example\""));
        assertEquals("{\"crossOrigin\":true,\"topOrigin\":\"https://attacker.example\"}", str(out));
    }

    @Test
    void insertIntoEmptyObjectWithWhitespaceStaysValid() {
        // Insertion goes just before the closing brace; interior whitespace is preserved verbatim.
        byte[] out = JsonValueEditor.insertMember(utf8("{  }"), "k", utf8("1"));
        assertEquals("{  \"k\":1}", str(out));
    }

    @Test
    void insertIntoWhitespacedNonEmptyObjectIsValidJson() {
        byte[] body = utf8("{ \"a\" : 1 }");
        byte[] out = JsonValueEditor.insertMember(body, "k", utf8("2"));
        // The comma lands right before the closing brace; the result parses and preserves "a":1.
        assertEquals("{ \"a\" : 1 ,\"k\":2}", str(out));
    }

    @Test
    void insertMemberReturnsNullForNonObjectOrNullInputs() {
        assertNull(JsonValueEditor.insertMember(utf8("[1,2,3]"), "k", utf8("1")), "array root");
        assertNull(JsonValueEditor.insertMember(utf8("\"str\""), "k", utf8("1")), "string root");
        assertNull(JsonValueEditor.insertMember(utf8("{"), "k", utf8("1")), "unbalanced object");
        assertNull(JsonValueEditor.insertMember(null, "k", utf8("1")));
        assertNull(JsonValueEditor.insertMember(utf8("{}"), null, utf8("1")));
        assertNull(JsonValueEditor.insertMember(utf8("{}"), "k", null));
    }
}
