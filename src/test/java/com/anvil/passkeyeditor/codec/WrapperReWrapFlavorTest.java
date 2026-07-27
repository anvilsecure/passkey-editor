package com.anvil.passkeyeditor.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Regression for the live finding "Credential response signature was not a base64url string" (a re-signed
 * assertion intermittently rejected by the secure RP).
 *
 * A base64 token carrying no flavor-distinguishing char ({@code +/} or {@code -_}) is alphabet-ambiguous.
 * It used to be classified STANDARD, which round-trips byte-identically for the same bytes - but
 * re-wrapping a different value (a freshly re-signed signature) as STANDARD can emit {@code +} / {@code /},
 * which a base64url-strict relying party (SimpleWebAuthn) rejects. WebAuthn wire fields are always base64url,
 * so the codec must default ambiguous tokens to URL_SAFE and keep a re-wrapped new value valid base64url.
 */
class WrapperReWrapFlavorTest {

    private final WrapperCodec wrapper = new WrapperCodec.Default();

    @Test
    void ambiguousBase64UrlTokenIsTreatedUrlSafeSoAReWrappedNewValueStaysUrlSafe() {
        // "AAAA…" is base64url of all-zero bytes - no '-'/'_' and no '+'/'/', i.e. alphabet-ambiguous.
        byte[] seedWire = "AAAAAAAAAAAAAAAA".getBytes(StandardCharsets.US_ASCII);
        WrapperCodec.Unwrapped uw = wrapper.unwrap(seedWire);

        // These bytes encode to "+/+/" under STANDARD base64 and "-_-_" under URL_SAFE.
        byte[] highBits = {(byte) 0xFB, (byte) 0xFF, (byte) 0xBF};
        String out = new String(wrapper.rewrap(highBits, uw.spec()), StandardCharsets.US_ASCII);

        assertFalse(out.contains("+") || out.contains("/") || out.contains("="),
                "re-wrap onto a base64url field must stay url-safe (no +,/,=); got: " + out);
    }

    @Test
    void uneditedRoundTripStillByteIdenticalForAnAmbiguousToken() {
        // The fix must not break byte-identity: re-wrapping the SAME inner bytes reproduces the wire token.
        byte[] seedWire = "QUJDREVG".getBytes(StandardCharsets.US_ASCII); // base64url("ABCDEF"), ambiguous
        WrapperCodec.Unwrapped uw = wrapper.unwrap(seedWire);
        assertArrayEquals(seedWire, wrapper.rewrap(uw.inner(), uw.spec()),
                "an unedited ambiguous token must round-trip byte-identically");
    }

    @Test
    void genuineStandardBase64IsStillDetected() {
        // A token that actually contains '/' is genuine STANDARD and must round-trip as such.
        byte[] standardWire = "//8=".getBytes(StandardCharsets.US_ASCII); // standard base64 of {0xFF,0xFF}
        WrapperCodec.Unwrapped uw = wrapper.unwrap(standardWire);
        assertArrayEquals(standardWire, wrapper.rewrap(uw.inner(), uw.spec()),
                "a genuine standard-base64 token round-trips unchanged");
    }
}
