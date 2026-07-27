package com.anvil.passkeyeditor.codec;

import com.anvil.passkeyeditor.codec.WrapSpec.Codec;
import com.anvil.passkeyeditor.codec.WrapSpec.Flavor;
import com.anvil.passkeyeditor.codec.WrapSpec.Padding;
import com.anvil.passkeyeditor.codec.WrapSpec.WrapFrame;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Per-layer wrapper unwrap / re-wrap.
 *
 * RPs rarely ship clean CBOR over the wire: expect single/double Base64 (URL-safe or standard,
 * padded or unpadded) and JSON envelopes. This codec peels those layers off a field down to its raw
 * CBOR/JSON ({@link #unwrap}) and replays them in reverse to rebuild byte-identical wire bytes from
 * edited inner bytes ({@link #rewrap}). The discovered/applied stack is a {@link WrapSpec}.
 *
 * Losslessness is the gate. {@code rewrap(unwrap(x).inner(), unwrap(x).spec())} must
 * equal {@code x} for every fixture, including a mixed-flavor double-Base64 (outer standard+padded,
 * inner base64url-unpadded). Detection of Base64 layers is best-effort and must be padding/flavor
 * exact; double-Base64 is only descended when the inner layer parses.
 */
public interface WrapperCodec {

    /**
     * The result of unwrapping: the innermost raw bytes plus the layer stack needed to rebuild the
     * original wire bytes.
     *
     * @param inner the innermost raw bytes (raw CBOR for binary fields, raw JSON for clientDataJSON)
     * @param spec  outermost-first wrapper layers that were peeled off
     */
    record Unwrapped(byte[] inner, WrapSpec spec) {
    }

    /**
     * Peel every recognised wrapping layer off {@code wire} down to the innermost raw bytes.
     *
     * @param wire the field bytes exactly as they appear on the wire
     * @return the innermost bytes + the {@link WrapSpec} describing how to rebuild {@code wire}
     */
    Unwrapped unwrap(byte[] wire);

    /**
     * Re-apply {@code spec} (in reverse layer order) to {@code inner}, reconstructing wire bytes.
     * Must be the exact inverse of {@link #unwrap} for an unedited round-trip.
     *
     * @param inner the (possibly edited) innermost raw bytes
     * @param spec  the wrapper layers to re-apply, outermost-first
     * @return the reconstructed wire bytes
     */
    byte[] rewrap(byte[] inner, WrapSpec spec);

    /**
     * Peel a known {@code spec} off {@code wire} - the deterministic inverse of {@link #rewrap}, and
     * the explicit-encoding counterpart of {@link #unwrap} (which discovers the spec). Frames are applied
     * outermost-first; a layer that does not decode under its declared frame throws (the caller - the
     * profile validator / Check panel - renders that as "decoded-but-suspect", which is exactly how a wrong
     * pinned encoding surfaces).
     *
     * @param wire the field bytes exactly as they appear on the wire
     * @param spec the known wrapper layers to peel, outermost-first (e.g. from {@code EncodingSpec.toWrapSpec})
     * @return the innermost raw bytes after peeling every frame
     */
    byte[] unwrapWith(byte[] wire, WrapSpec spec);

    /**
     * The {@link WrapperCodec} implementation.
     *
     * Lives as a nested type to keep the frozen 4-file {@code codec} package intact (the
     * {@link WrapperCodec} interface has no separate impl file, mirroring how {@link CborCodec} pairs
     * with its own impl). The interface stays the seam; {@code Default} is the concrete strategy.
     *
     * Base64 (the byte-identity gate): a layer is recognised only when the bytes are a valid
     * Base64 string in a detected flavor/padding and re-encoding the decoded bytes with that
     * exact flavor/padding reproduces the input verbatim - a strict round-trip self-check, so a frame
     * is recorded only when its replay is provably lossless. Double-Base64 is descended at most once
     * more, and only when the inner layer passes the same self-check. The flavor probe keys on the
     * distinguishing alphabet chars ({@code +/} ⇒ STANDARD; otherwise URL_SAFE - the WebAuthn default, so
     * a re-wrapped new value stays valid base64url) and padding on a trailing {@code =}; the
     * round-trip verify is the actual guarantee for an unedited field.
     *
     * JSON envelope: when the wire is a JSON object carrying a configured key whose value is
     * a string, that string is peeled as the inner blob (then Base64 layers inside it are peeled too).
     * Re-wrap reconstructs the canonical single-member envelope {@code {"<key>":"<value>"}} - the exact
     * shape of the synthetic fixtures this tool emits. (Arbitrary foreign-envelope whitespace/key-order
     * is a later-day concern; the byte-identity gate is asserted on the Base64 stack.) The configured
     * key set defaults to the standard WebAuthn ceremony field names.
     */
    final class Default implements WrapperCodec {

        /** Hard cap on Base64 nesting peeled (single + double). */
        private static final int MAX_BASE64_DEPTH = 2;

        /** Standard JSON envelope keys ceremony fields hide behind (configurable later). */
        private static final String[] ENVELOPE_KEYS = {
                "clientDataJSON", "attestationObject", "authenticatorData", "signature", "data"
        };

        @Override
        public Unwrapped unwrap(byte[] wire) {
            WrapSpec spec = new WrapSpec();
            byte[] current = wire;

            // Outermost layer may be a JSON envelope; peel it first if present.
            byte[] enveloped = peelJsonEnvelope(current, spec);
            if (enveloped != null) {
                current = enveloped;
            }

            // Then peel up to MAX_BASE64_DEPTH Base64 layers, innermost descent gated on a lossless
            // round-trip self-check.
            for (int depth = 0; depth < MAX_BASE64_DEPTH; depth++) {
                byte[] decoded = tryPeelBase64(current, spec);
                if (decoded == null) {
                    break;
                }
                current = decoded;
            }

            return new Unwrapped(current, spec);
        }

        @Override
        public byte[] rewrap(byte[] inner, WrapSpec spec) {
            // Replay frames in reverse (innermost-last in the list ⇒ apply from the tail up so the
            // outermost frame is applied last and ends up on the outside).
            byte[] current = inner;
            var frames = spec.frames();
            for (int i = frames.size() - 1; i >= 0; i--) {
                WrapFrame frame = frames.get(i);
                if (frame.codec() == Codec.BASE64) {
                    current = encodeBase64(current, frame.flavor(), frame.padding());
                } else if (frame.codec() == Codec.JSON_ENVELOPE) {
                    current = wrapJsonEnvelope(current, frame.jsonPath());
                } else if (frame.codec() == Codec.URL_ENCODE) {
                    current = percentEncode(current);
                } else {
                    throw new IllegalArgumentException("Unknown wrap codec: " + frame.codec());
                }
            }
            return current;
        }

        @Override
        public byte[] unwrapWith(byte[] wire, WrapSpec spec) {
            // Peel each declared frame in order (outermost-first) - the exact inverse of rewrap, used to
            // decode a field under a PINNED EncodingSpec. A mismatch (wrong flavor, not-an-envelope, …)
            // throws here; the validator catches it and reports "decoded-but-suspect".
            byte[] current = wire;
            for (WrapFrame frame : spec.frames()) {
                current = switch (frame.codec()) {
                    case BASE64 -> decodeBase64(current, frame.flavor());
                    case JSON_ENVELOPE -> peelEnvelopeKnown(current, frame.jsonPath());
                    case URL_ENCODE -> percentDecode(current);
                };
            }
            return current;
        }

        /** Peel a known JSON envelope key, returning the inner string value's UTF-8 bytes (throws if absent). */
        private static byte[] peelEnvelopeKnown(byte[] wire, String key) {
            String s = new String(wire, StandardCharsets.UTF_8).trim();
            String value = extractStringMember(s, key);
            if (value == null) {
                throw new IllegalArgumentException("no string member \"" + key + "\" in envelope");
            }
            return value.getBytes(StandardCharsets.UTF_8);
        }

        // ---- percent-encoding (RFC 3986) -------------------------------------------------------

        /** Percent-encode every byte that is not an RFC 3986 unreserved char ({@code A-Za-z0-9-_.~}). */
        private static byte[] percentEncode(byte[] data) {
            StringBuilder sb = new StringBuilder(data.length * 3);
            for (byte b : data) {
                int c = b & 0xFF;
                boolean unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
                if (unreserved) {
                    sb.append((char) c);
                } else {
                    sb.append('%')
                            .append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xF, 16)))
                            .append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
                }
            }
            return sb.toString().getBytes(StandardCharsets.US_ASCII);
        }

        /** Strict RFC-3986 inverse of {@link #percentEncode}: decode {@code %XX} escapes; throws if malformed. */
        private static byte[] percentDecode(byte[] data) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(data.length);
            for (int i = 0; i < data.length; i++) {
                int c = data[i] & 0xFF;
                if (c == '%') {
                    if (i + 2 >= data.length) {
                        throw new IllegalArgumentException("truncated percent-escape");
                    }
                    int hi = Character.digit(data[i + 1], 16);
                    int lo = Character.digit(data[i + 2], 16);
                    if (hi < 0 || lo < 0) {
                        throw new IllegalArgumentException("malformed percent-escape");
                    }
                    out.write((hi << 4) | lo);
                    i += 2;
                } else {
                    out.write(c);
                }
            }
            return out.toByteArray();
        }

        // ---- Base64 ----------------------------------------------------------------------------

        /**
         * If {@code wire} is a lossless Base64 layer, decode it, append the discovered {@link WrapFrame}
         * to {@code spec}, and return the decoded bytes; otherwise return {@code null} and leave
         * {@code spec} untouched.
         */
        private static byte[] tryPeelBase64(byte[] wire, WrapSpec spec) {
            if (wire == null || wire.length == 0) {
                return null;
            }
            String s = new String(wire, StandardCharsets.US_ASCII);
            if (!isBase64Charset(s)) {
                return null;
            }

            // Flavor is genuinely ambiguous when the token carries no distinguishing char (every byte maps
            // to [A-Za-z0-9]). Default such tokens to URL_SAFE - WebAuthn wire fields are ALWAYS base64url,
            // and re-encoding a DIFFERENT value (a freshly re-signed signature, an edited authData) as
            // STANDARD can emit '+' / '/' that a base64url-strict RP (SimpleWebAuthn) rejects with
            // "...was not a base64url string". So classify STANDARD only when a '+' or '/' actually proves
            // it. (An unedited round-trip is byte-identical under either flavor here, so byte-identity holds.)
            Flavor flavor = s.indexOf('+') >= 0 || s.indexOf('/') >= 0 ? Flavor.STANDARD : Flavor.URL_SAFE;
            Padding padding = s.indexOf('=') >= 0 ? Padding.PADDED : Padding.UNPADDED;

            byte[] decoded;
            try {
                decoded = decodeBase64(wire, flavor);
            } catch (IllegalArgumentException e) {
                return null;
            }
            // Strict losslessness self-check: only accept this frame if its replay is exact.
            byte[] reencoded = encodeBase64(decoded, flavor, padding);
            if (!java.util.Arrays.equals(reencoded, wire)) {
                return null;
            }
            // A trivially short/degenerate decode (e.g. ASCII that happens to be valid base64 but is
            // not really a wrapper) is still accepted because the round-trip proved it lossless; the
            // CBOR/JSON layer below it decides whether the bytes are meaningful.
            spec.addFrame(WrapFrame.base64(flavor, padding));
            return decoded;
        }

        private static boolean isBase64Charset(String s) {
            boolean sawAlphabet = false;
            int pad = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '=') {
                    pad++;
                    continue;
                }
                if (pad > 0) {
                    return false; // '=' only ever trails
                }
                boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                        || c == '+' || c == '/' || c == '-' || c == '_';
                if (!ok) {
                    return false;
                }
                sawAlphabet = true;
            }
            if (!sawAlphabet) {
                return false;
            }
            // Reject mixed alphabets (both std and url-safe specials) - ambiguous, not a clean layer.
            boolean hasStd = s.indexOf('+') >= 0 || s.indexOf('/') >= 0;
            boolean hasUrl = s.indexOf('-') >= 0 || s.indexOf('_') >= 0;
            if (hasStd && hasUrl) {
                return false;
            }
            return pad <= 2;
        }

        private static byte[] decodeBase64(byte[] wire, Flavor flavor) {
            Base64.Decoder decoder = flavor == Flavor.URL_SAFE ? Base64.getUrlDecoder() : Base64.getDecoder();
            // Both JDK decoders accept missing padding; PADDED inputs carry their own '='. Padding presence
            // is re-asserted by the encode-side round-trip self-check in tryPeelBase64, not needed here.
            return decoder.decode(wire);
        }

        private static byte[] encodeBase64(byte[] data, Flavor flavor, Padding padding) {
            Base64.Encoder encoder = flavor == Flavor.URL_SAFE ? Base64.getUrlEncoder() : Base64.getEncoder();
            if (padding == Padding.UNPADDED) {
                encoder = encoder.withoutPadding();
            }
            return encoder.encode(data);
        }

        // ---- JSON envelope ---------------------------------------------------------------------

        /**
         * If {@code wire} is a JSON object {@code {"<key>": "<string>"}} for one of the configured keys,
         * append a JSON_ENVELOPE frame and return the string value's bytes (UTF-8 of the unescaped
         * value); otherwise return {@code null}.
         *
         * Minimal, dependency-free scan: the codec package stays free of Gson so {@code rewrap} can be
         * a pure inverse. Only flat single-string-member envelopes are recognised (the synthetic-fixture
         * shape); anything richer is left to the CBOR/JSON layer untouched.
         */
        private static byte[] peelJsonEnvelope(byte[] wire, WrapSpec spec) {
            if (wire == null) {
                return null;
            }
            String s = new String(wire, StandardCharsets.UTF_8).trim();
            if (s.length() < 2 || s.charAt(0) != '{') {
                return null;
            }
            for (String key : ENVELOPE_KEYS) {
                String value = extractStringMember(s, key);
                if (value != null) {
                    byte[] inner = value.getBytes(StandardCharsets.UTF_8);
                    // Strict losslessness self-check (same discipline as Base64): only descend the envelope
                    // when re-wrapping reproduces the wire byte-for-byte. wrapJsonEnvelope only models the
                    // canonical single-member, no-whitespace shape {"<key>":"<value>"}; a foreign envelope
                    // with extra whitespace or sibling members (CSRF tokens, ids, …) would NOT round-trip,
                    // so it is left raw here and the editor splices the value surgically instead of routing
                    // it through a lossy rewrap that would drop the siblings.
                    byte[] rewrapped = wrapJsonEnvelope(inner, key);
                    if (!java.util.Arrays.equals(rewrapped, wire)) {
                        return null;
                    }
                    spec.addFrame(WrapFrame.jsonEnvelope(key));
                    return inner;
                }
            }
            return null;
        }

        /**
         * Extract the (JSON-unescaped) string value of member {@code key} from a JSON object literal,
         * or {@code null} if absent / not a string. Handles {@code \"} and {@code \\} escapes within the
         * value; intentionally tiny (no full JSON parse) to keep the codec dependency-free and reversible.
         */
        private static String extractStringMember(String json, String key) {
            String needle = "\"" + key + "\"";
            int k = json.indexOf(needle);
            if (k < 0) {
                return null;
            }
            int i = k + needle.length();
            // skip whitespace and the ':'
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            if (i >= json.length() || json.charAt(i) != ':') {
                return null;
            }
            i++;
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            if (i >= json.length() || json.charAt(i) != '"') {
                return null; // value is not a string
            }
            i++;
            StringBuilder out = new StringBuilder();
            while (i < json.length()) {
                char c = json.charAt(i);
                if (c == '\\') {
                    if (i + 1 >= json.length()) {
                        return null;
                    }
                    char n = json.charAt(i + 1);
                    switch (n) {
                        case '"' -> out.append('"');
                        case '\\' -> out.append('\\');
                        case '/' -> out.append('/');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        default -> {
                            // Unsupported escape (e.g. \\uXXXX) - bail rather than corrupt.
                            return null;
                        }
                    }
                    i += 2;
                } else if (c == '"') {
                    return out.toString();
                } else {
                    out.append(c);
                    i++;
                }
            }
            return null; // unterminated
        }

        /**
         * Reconstruct the canonical single-member envelope {@code {"<key>":"<value>"}} with the inner
         * bytes as a JSON string value (escaping {@code "} and {@code \}). Inverse of
         * {@link #peelJsonEnvelope} for the canonical fixture shape this tool emits.
         */
        private static byte[] wrapJsonEnvelope(byte[] inner, String key) {
            String value = new String(inner, StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            sb.append('{').append('"').append(key).append('"').append(':').append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"' -> sb.append('\\').append('"');
                    case '\\' -> sb.append('\\').append('\\');
                    default -> sb.append(c);
                }
            }
            sb.append('"').append('}');
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        }
    }
}
