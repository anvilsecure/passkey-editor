package com.anvil.passkeyeditor.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Surgical, byte-level editing of a JSON string value on the wire - locate the value of a member by
 * key and replace exactly those bytes, leaving everything else (sibling members, whitespace, key
 * order, the rest of the body) byte-identical.
 *
 * This is the discipline the whole tool rests on: a relying party signs exact wire bytes, so
 * edits are never a re-serialization of a parsed view - they are a span replacement on the original
 * bytes. Two callers share this:
 *   - the request editor splices the assertion {@code signature} value (sig-strip);
 *
 * Pure functions, no Burp types - fully unit-testable.
 */
public final class JsonValueEditor {

    private JsonValueEditor() {
    }

    /**
     * Find the byte span {@code [start, end)} of the (unescaped-on-wire) string value of member
     * {@code key} in a JSON body, exclusive of the surrounding quotes.
     *
     * Scoped to the value shapes this tool edits - WebAuthn ceremony field values
     * (base64/base64url tokens) and policy enums like {@code "discouraged"} - which contain no JSON
     * escapes, so a direct quote-to-quote span is exact. If an escape ({@code \}) is encountered inside
     * the value the method bails (returns null) rather than returning a span it cannot losslessly
     * rewrite. The key is matched as the quoted literal {@code "key"}, so a longer key that merely
     * contains {@code key} as a substring (e.g. {@code requireUserVerification} vs {@code userVerification})
     * does not false-match.
     *
     * @param body the JSON body bytes
     * @param key  the member name (without quotes)
     * @return {@code {start, end}} of the value bytes between the quotes, or {@code null} if not found
     */
    public static int[] findStringValueSpan(byte[] body, String key) {
        int i = valueStartAfterKey(body, key);
        if (i < 0 || body[i] != '"') return null;            // must be a string value
        int valueStart = i + 1;
        int j = valueStart;
        while (j < body.length && body[j] != '"') {
            if (body[j] == '\\') return null;                // escapes aren't this tool's value shape; bail
            j++;
        }
        if (j >= body.length) return null;
        return new int[]{valueStart, j};
    }

    /**
     * Replace {@code body[span[0], span[1])} with {@code replacement}, returning a new array. Everything
     * outside the span is preserved verbatim.
     *
     * @param body        the original bytes
     * @param span        the {@code {start, end}} half-open span to replace (as returned by
     *                    {@link #findStringValueSpan})
     * @param replacement the bytes to write in place of the span
     * @return a new array with the span replaced
     */
    public static byte[] splice(byte[] body, int[] span, byte[] replacement) {
        int start = span[0];
        int end = span[1];
        byte[] out = new byte[start + replacement.length + (body.length - end)];
        System.arraycopy(body, 0, out, 0, start);
        System.arraycopy(replacement, 0, out, start, replacement.length);
        System.arraycopy(body, end, out, start + replacement.length, body.length - end);
        return out;
    }

    /**
     * Replace several non-overlapping value spans in one pass - used by the request editor to write back
     * an edited {@code clientDataJSON} + {@code authenticatorData} + {@code signature} together after a
     * re-sign. Splices are applied in descending start offset so replacing one span never shifts
     * the offsets of spans earlier in the body. {@code spans.get(i)} pairs with {@code replacements.get(i)}.
     *
     * @param body         the original bytes
     * @param spans        the half-open value spans to replace (must be mutually non-overlapping)
     * @param replacements the new bytes for each span, index-aligned with {@code spans}
     * @return a new array with every span replaced
     * @throws IllegalArgumentException if the two lists differ in length
     */
    public static byte[] spliceAll(byte[] body, java.util.List<int[]> spans, java.util.List<byte[]> replacements) {
        if (spans.size() != replacements.size()) {
            throw new IllegalArgumentException("spans and replacements must be the same length");
        }
        Integer[] order = new Integer[spans.size()];
        for (int i = 0; i < order.length; i++) {
            order[i] = i;
        }
        // Apply highest-offset span first so earlier spans' offsets stay valid through the rewrite.
        java.util.Arrays.sort(order, (a, b) -> Integer.compare(spans.get(b)[0], spans.get(a)[0]));
        byte[] out = body;
        for (int idx : order) {
            out = splice(out, spans.get(idx), replacements.get(idx));
        }
        return out;
    }

    /**
     * Find the byte span {@code [start, end)} of the bare (non-string) primitive value of member
     * {@code key} - a {@code true}/{@code false}/number/{@code null} literal written directly after the
     * colon, with no surrounding quotes. The counterpart of {@link #findStringValueSpan} for the value
     * shapes that carry no quotes; WebAuthn's {@code clientDataJSON.crossOrigin} boolean is the motivating
     * case (a bare {@code true}/{@code false}, which {@link #findStringValueSpan} cannot address).
     *
     * Matches the key as the quoted literal {@code "key"} at its first occurrence anywhere in the body
     * (the same scoping as {@link #findStringValueSpan}). Returns {@code null} if the key is absent, or if
     * its value is a string / object / array (i.e. not a bare literal) - so a caller can distinguish
     * "boolean present" from "string present" and choose the right editor.
     *
     * @param body the JSON body bytes
     * @param key  the member name (without quotes)
     * @return {@code {start, end}} of the literal's bytes, or {@code null} if there is no bare-literal value
     */
    public static int[] findPrimitiveValueSpan(byte[] body, String key) {
        int i = valueStartAfterKey(body, key);
        if (i < 0) return null;
        byte c = body[i];
        if (c == '"' || c == '{' || c == '[') return null;   // a string / object / array, not a bare literal
        int valueStart = i;
        int j = valueStart;
        while (j < body.length) {
            byte b = body[j];
            if (b == ',' || b == '}' || b == ']' || isWs(b)) break;
            j++;
        }
        if (j == valueStart) return null;                    // empty span - not a value
        return new int[]{valueStart, j};
    }

    /**
     * Insert a new member {@code "key":<rawValue>} into the root JSON object, returning a new array;
     * every existing byte is preserved. The member is inserted immediately before the object's closing
     * brace, with the comma placed to keep the result well-formed: an empty object {@code {}} becomes
     * {@code {"key":value}}, and a non-empty object gains {@code ,"key":value} after its last member.
     * {@code rawValue} is written verbatim, so the caller supplies the exact value bytes - e.g.
     * {@code true} for a boolean, or an already-quoted {@code "https://…"} for a string value.
     *
     * Used to add {@code clientDataJSON} framing members ({@code crossOrigin} / {@code topOrigin}) that a
     * same-origin ceremony omits - the byte-surgical counterpart of {@link #splice} for absent members.
     *
     * @param body     the JSON body bytes (must be a root object)
     * @param key      the new member name (without quotes)
     * @param rawValue the verbatim value bytes to write after {@code "key":}
     * @return a new array with the member inserted, or {@code null} if {@code body} is not a root object
     */
    public static byte[] insertMember(byte[] body, String key, byte[] rawValue) {
        if (body == null || key == null || rawValue == null) {
            return null;
        }
        int rootStart = firstNonWs(body, 0, body.length);
        if (rootStart >= body.length || body[rootStart] != '{') {
            return null;
        }
        int rootEnd = skipBalanced(body, rootStart, body.length, (byte) '{', (byte) '}');
        if (rootEnd < 0) {
            return null;
        }
        int closeBrace = rootEnd - 1;                                    // index of the matching '}'
        boolean empty = firstNonWs(body, rootStart + 1, closeBrace) >= closeBrace;
        ByteArrayOutputStream ins = new ByteArrayOutputStream();
        if (!empty) {
            ins.write(',');
        }
        ins.writeBytes(("\"" + key + "\":").getBytes(StandardCharsets.US_ASCII));
        ins.writeBytes(rawValue);
        return splice(body, new int[]{closeBrace, closeBrace}, ins.toByteArray());   // zero-width = insert
    }

    private static boolean isWs(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    /**
     * The index of the first non-whitespace byte of member {@code key}'s value - just past the {@code "key"}
     * needle, its surrounding whitespace and the {@code :}. Returns {@code -1} if {@code body}/{@code key} is
     * null, the quoted key is absent, no {@code :} follows, or the body ends before any value byte. The shared
     * prefix of {@link #findStringValueSpan} / {@link #findPrimitiveValueSpan}; each then inspects
     * {@code body[i]} for its own value shape.
     */
    private static int valueStartAfterKey(byte[] body, String key) {
        if (body == null || key == null) {
            return -1;
        }
        byte[] needle = ("\"" + key + "\"").getBytes(StandardCharsets.US_ASCII);
        int k = indexOf(body, needle);
        if (k < 0) {
            return -1;
        }
        int i = firstNonWs(body, k + needle.length, body.length); // whitespace before ':'
        if (i >= body.length || body[i] != ':') return -1;
        i = firstNonWs(body, i + 1, body.length);                 // whitespace after ':'
        return i >= body.length ? -1 : i;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (regionEquals(haystack, i, needle)) {
                return i;
            }
        }
        return -1;
    }

    // ---- Path-addressed location (Target Profiles) ---------------------------------------------
    // findStringValueSpan locates the FIRST "key" anywhere in the body - correct only when a field name
    // is unique. Real RPs nest the credential (response.response.X), wrap it in an array ([2]...), give
    // it a differently-named wrapper, or hide the value behind an envelope key ($base64) - so the field
    // must be addressed by its exact structural PATH. This walks object-key / array-index hops with a
    // string/brace/bracket-aware scanner (no JSON library, so it composes with the byte-exact splice
    // above) and returns the located string value's span. Escape-bearing string values (Descope's
    // stringified-JSON layer, ctap's raw clientDataJSON) are out of scope and return null by design.

    /**
     * Find the byte span {@code [start, end)} of the (escape-free) string value at {@code path} in a JSON
     * body, exclusive of its surrounding quotes - the path-addressed counterpart of
     * {@link #findStringValueSpan}.
     *
     * @param body the JSON body bytes
     * @param path the structural address of the value (object keys + array indices)
     * @return {@code {start, end}} of the value bytes between the quotes, or {@code null} if the path does
     *     not resolve to a string value (or the value contains a JSON escape - out of scope)
     */
    public static int[] findStringValueSpanAtPath(byte[] body, JsonPath path) {
        if (body == null || path == null) {
            return null;
        }
        int rootStart = firstNonWs(body, 0, body.length);
        if (rootStart >= body.length) {
            return null;
        }
        int rootEnd = skipValue(body, rootStart, body.length);
        if (rootEnd < 0) {
            return null;
        }
        int[] region = {rootStart, rootEnd};
        for (JsonPath.Seg seg : path.segments()) {
            region = descend(body, region, seg);
            if (region == null) {
                return null;
            }
        }
        // The located value must be a string: return its inner span, bailing on escapes (out of scope).
        int p = firstNonWs(body, region[0], region[1]);
        if (p >= region[1] || body[p] != '"') {
            return null;
        }
        int valueStart = p + 1;
        int j = valueStart;
        while (j < region[1] && body[j] != '"') {
            if (body[j] == '\\') {
                return null;
            }
            j++;
        }
        if (j >= region[1]) {
            return null;
        }
        return new int[]{valueStart, j};
    }

    /** Resolve one hop within the current value {@code region}, returning the child value's region. */
    private static int[] descend(byte[] body, int[] region, JsonPath.Seg seg) {
        int start = firstNonWs(body, region[0], region[1]);
        if (start >= region[1]) {
            return null;
        }
        if (seg instanceof JsonPath.Key key) {
            if (body[start] != '{') {
                return null;
            }
            return memberValueRegion(body, start, region[1], key.name());
        }
        if (body[start] != '[') {
            return null;
        }
        return elementRegion(body, start, region[1], ((JsonPath.Index) seg).i());
    }

    /** Region {@code [start,end)} of the value of direct member {@code key} in the object at {@code objStart}. */
    private static int[] memberValueRegion(byte[] body, int objStart, int limit, String key) {
        byte[] needle = key.getBytes(StandardCharsets.UTF_8);
        int i = objStart + 1; // past '{'
        while (true) {
            i = firstNonWs(body, i, limit);
            if (i >= limit || body[i] == '}') {
                return null; // end of object - key absent
            }
            if (body[i] != '"') {
                return null; // expected a member key
            }
            int ks = i + 1;
            int ke = skipStringContent(body, ks, limit);
            if (ke < 0) {
                return null;
            }
            boolean keyMatch = (ke - ks == needle.length) && regionEquals(body, ks, needle);
            i = firstNonWs(body, ke + 1, limit); // past closing key quote
            if (i >= limit || body[i] != ':') {
                return null;
            }
            int vStart = firstNonWs(body, i + 1, limit);
            if (vStart >= limit) {
                return null;
            }
            int vEnd = skipValue(body, vStart, limit);
            if (vEnd < 0) {
                return null;
            }
            if (keyMatch) {
                return new int[]{vStart, vEnd};
            }
            i = firstNonWs(body, vEnd, limit);
            if (i >= limit || body[i] == '}') {
                return null; // key absent
            }
            if (body[i] != ',') {
                return null;
            }
            i++; // past ','
        }
    }

    /** Region {@code [start,end)} of element {@code index} in the array at {@code arrStart}. */
    private static int[] elementRegion(byte[] body, int arrStart, int limit, int index) {
        int i = arrStart + 1; // past '['
        int n = 0;
        while (true) {
            i = firstNonWs(body, i, limit);
            if (i >= limit || body[i] == ']') {
                return null; // index out of range
            }
            int vEnd = skipValue(body, i, limit);
            if (vEnd < 0) {
                return null;
            }
            if (n == index) {
                return new int[]{i, vEnd};
            }
            n++;
            i = firstNonWs(body, vEnd, limit);
            if (i >= limit || body[i] == ']') {
                return null; // index out of range
            }
            if (body[i] != ',') {
                return null;
            }
            i++; // past ','
        }
    }

    /** Index just past the value starting at {@code p} (string / object / array / primitive), or -1 if malformed. */
    private static int skipValue(byte[] body, int p, int limit) {
        if (p >= limit) {
            return -1;
        }
        byte c = body[p];
        if (c == '"') {
            int end = skipStringContent(body, p + 1, limit);
            return end < 0 ? -1 : end + 1; // include the closing quote
        }
        if (c == '{') {
            return skipBalanced(body, p, limit, (byte) '{', (byte) '}');
        }
        if (c == '[') {
            return skipBalanced(body, p, limit, (byte) '[', (byte) ']');
        }
        // primitive: number / true / false / null - up to the next structural delimiter
        int i = p;
        while (i < limit) {
            byte b = body[i];
            if (b == ',' || b == '}' || b == ']' || isWs(b)) {
                break;
            }
            i++;
        }
        return i;
    }

    /** Index of the closing quote for a string whose content starts at {@code from} (after the opening quote). */
    private static int skipStringContent(byte[] body, int from, int limit) {
        int i = from;
        while (i < limit) {
            byte b = body[i];
            if (b == '\\') {
                i += 2;
                continue;
            }
            if (b == '"') {
                return i;
            }
            i++;
        }
        return -1;
    }

    /** Index just past the balanced {@code open..close} region starting at {@code p} (string-aware). */
    private static int skipBalanced(byte[] body, int p, int limit, byte open, byte close) {
        int depth = 0;
        int i = p;
        boolean inStr = false;
        while (i < limit) {
            byte b = body[i];
            if (inStr) {
                if (b == '\\') {
                    i += 2;
                    continue;
                }
                if (b == '"') {
                    inStr = false;
                }
                i++;
                continue;
            }
            if (b == '"') {
                inStr = true;
            } else if (b == open) {
                depth++;
            } else if (b == close) {
                depth--;
                if (depth == 0) {
                    return i + 1;
                }
            }
            i++;
        }
        return -1;
    }

    private static boolean regionEquals(byte[] body, int start, byte[] needle) {
        if (start + needle.length > body.length) {
            return false;
        }
        for (int j = 0; j < needle.length; j++) {
            if (body[start + j] != needle[j]) {
                return false;
            }
        }
        return true;
    }

    /** First non-whitespace index in {@code [from, limit)}, or {@code limit} if none. */
    private static int firstNonWs(byte[] body, int from, int limit) {
        int i = Math.max(from, 0);
        while (i < limit && isWs(body[i])) {
            i++;
        }
        return i;
    }
}
