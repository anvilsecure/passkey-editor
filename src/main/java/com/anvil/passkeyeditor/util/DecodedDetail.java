package com.anvil.passkeyeditor.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Pure, Burp-free rendering of a located + decoded field value into the human-readable forms the
 * Profile-Editor Check panel expands on demand.
 *
 * The Check rows show a truncated one-line summary; that is enough to spot a malformed field but hides
 * the FULL value and makes it hard to confirm a parse is meaningful - e.g. a userHandle whose hex
 * {@code 776562617574686e696f…} is the correct decode of base64url {@code d2ViYXV0aG5pby…} (both = ASCII
 * {@code webauthnio-…}), invisible behind the truncation. This helper turns the decoded bytes into: detected
 * encoding + byte length, the full (untruncated) hex, pretty-printed JSON when the bytes are a JSON
 * object/array (clientDataJSON), or an ASCII view when the bytes are printable but not JSON (userHandle). It
 * re-decodes nothing - it renders the same bytes the Check engine already decoded
 * ({@link com.anvil.passkeyeditor.profile.ProfileValidator.CheckResult#decodedBytes()}).
 *
 * Like {@link com.anvil.passkeyeditor.ui.editor.CeremonyJson}, every method is pure + never throws, so
 * the logic is fully unit-testable and the UI is a thin renderer.
 */
public final class DecodedDetail {

    private DecodedDetail() {
    }

    /** HTML-escaping off so {@code =}, {@code <}, {@code &} inside clientDataJSON render literally. */
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    /** Full lowercase hex of the bytes - no truncation, no separators. Empty string for null/empty input. */
    public static String hex(byte[] bytes) {
        return bytes == null ? "" : HexFormat.of().formatHex(bytes);
    }

    /**
     * True when every byte is printable US-ASCII - the graphic range {@code 0x20}-{@code 0x7E} plus
     * tab/newline/CR. Null/empty input is not printable (there is nothing to render). This gates whether
     * the ASCII line is shown at all, so non-text blobs (CBOR attestationObject, DER signatures, raw COSE
     * keys) don't render as a dotted mess.
     */
    public static boolean isPrintableAscii(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return false;
        }
        for (byte b : bytes) {
            int c = b & 0xFF;
            boolean graphic = c >= 0x20 && c <= 0x7E;
            boolean ws = c == '\t' || c == '\n' || c == '\r';
            if (!graphic && !ws) {
                return false;
            }
        }
        return true;
    }

    /** The bytes as a US-ASCII string; only {@link #describe} shows it, and only when printable. */
    private static String ascii(byte[] bytes) {
        return bytes == null ? "" : new String(bytes, StandardCharsets.US_ASCII);
    }

    /**
     * Pretty-printed JSON when the bytes parse as a JSON object or array, else {@code null}. A bare scalar
     * (number / string / boolean / null) returns {@code null} - not worth a JSON block. Never throws.
     */
    public static String prettyJson(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8));
            if (el.isJsonObject() || el.isJsonArray()) {
                return PRETTY.toJson(el);
            }
        } catch (RuntimeException ignore) {
            // not JSON → no JSON block
        }
        return null;
    }

    /**
     * The full multi-section detail block the Check expander shows for one field. Labelled sections, each
     * on its own line(s): {@code encoding} (when known), {@code length}, full {@code hex}, then EITHER
     * {@code json} (when the bytes are a JSON object/array) OR {@code ascii} (when the bytes are printable
     * but not JSON) - never both, since for a JSON value the two are the same text. Never throws;
     * {@code null} bytes yield a single explanatory line.
     *
     * @param encoding the encoding label the locator applied (e.g. {@code "auto: base64url"}), or {@code null}
     * @param bytes    the decoded inner bytes the Check engine produced, or {@code null} if none
     */
    public static String render(String encoding, byte[] bytes) {
        if (bytes == null) {
            return "(no decoded bytes for this field)";
        }
        StringBuilder sb = new StringBuilder();
        if (encoding != null && !encoding.isBlank()) {
            sb.append("encoding : ").append(encoding).append('\n');
        }
        sb.append("length   : ").append(bytes.length).append(bytes.length == 1 ? " byte" : " bytes");
        sb.append('\n').append("hex      : ").append(hex(bytes));
        // ASCII and pretty-JSON are the same text for a JSON value (clientDataJSON), so show only the JSON to
        // avoid the duplicate; the ASCII line is for printable NON-JSON bytes (e.g. a userHandle).
        String json = prettyJson(bytes);
        if (json != null) {
            sb.append('\n').append("json     :").append('\n').append(json);
        } else if (isPrintableAscii(bytes)) {
            sb.append('\n').append("ascii    : ").append(ascii(bytes));
        }
        return sb.toString();
    }
}
