package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.util.JsonPath;
import com.anvil.passkeyeditor.util.JsonValueEditor;
import com.anvil.passkeyeditor.util.SafeRegex;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Where one {@link Field} lives in a given RP's body, and how it is encoded. Two locator kinds:
 *
 *   - {@link Kind#PATH} - an ordered list of candidate {@link JsonPath}s (first that resolves wins),
 *       the structural locator proven in (object keys, array indices, envelope-key descent).
 *   - {@link Kind#REGEX} - a user-supplied regex whose capture group 1 (or group 0 if it has no
 *       groups) delimits the value (e.g. {@code "signature":"([^"]+)"}). For the
 *       wire shapes a structural path cannot reach (an escaped/stringified layer, an exotic envelope) the
 *       operator drops to a regex.
 *
 * Both kinds return the same {@code {start,end}} byte span the splice path already consumes
 * ({@link JsonValueEditor#splice}), so the write path is identical regardless of how a field was located.
 *
 * A learned/seeded profile usually has a single exact path; the Default profile uses
 * {@code [response.<name>, <name>]} so it covers both the SimpleWebAuthn nested shape and a flat
 * top-level one - reproducing the "response object else root" behaviour as data.
 *
 * {@code encoding == null} means "auto-detect at runtime" via
 * {@link com.anvil.passkeyeditor.codec.WrapperCodec#unwrap} - the lossless self-check already
 * proven, which handles every mainstream wrapping (base64 url/std × pad + envelope key). An explicit
 * encoding (the per-field {@code EncodingSpec}) is the learn-once refinement.
 */
public record FieldLocator(Kind kind, List<JsonPath> candidates, String regex, EncodingSpec encoding) {

    /** How a field's value is addressed in the body. */
    public enum Kind { PATH, REGEX }

    /**
     * Compile-once cache for {@link Kind#REGEX} patterns. {@link #locate} runs per request on Burp's UI
     * thread, so a record can't hold a per-instance compiled {@link Pattern} - this shared, thread-safe
     * cache avoids recompiling the same pattern on every decode (mirrors {@link HostMatch}). The input cap
     * + backtracking step budget live in {@link SafeRegex}.
     */
    private static final Map<String, Pattern> REGEX_CACHE = new ConcurrentHashMap<>();

    public FieldLocator {
        if (kind == null) {
            throw new IllegalArgumentException("FieldLocator kind is required");
        }
        if (kind == Kind.PATH) {
            candidates = List.copyOf(candidates);
            if (candidates.isEmpty()) {
                throw new IllegalArgumentException("a PATH FieldLocator needs at least one candidate path");
            }
        } else { // REGEX
            if (regex == null || regex.isBlank()) {
                throw new IllegalArgumentException("a REGEX FieldLocator needs a non-blank pattern");
            }
            candidates = List.of(); // a regex locator carries no structural paths
        }
    }

    /** A PATH locator over one or more candidate path strings, with auto-detected encoding. */
    public static FieldLocator of(String... paths) {
        return of(null, paths);
    }

    /** A PATH locator over one or more candidate path strings, with an explicit (or {@code null}=auto) encoding. */
    public static FieldLocator of(EncodingSpec encoding, String... paths) {
        if (paths.length == 0) {
            throw new IllegalArgumentException("at least one path required");
        }
        List<JsonPath> parsed = new ArrayList<>(paths.length);
        for (String p : paths) {
            parsed.add(JsonPath.parse(p));
        }
        return new FieldLocator(Kind.PATH, parsed, null, encoding);
    }

    /** A REGEX locator: capture group 1 (or group 0) delimits the value. Auto-detected encoding. */
    public static FieldLocator regex(String pattern) {
        return regex(pattern, null);
    }

    /** A REGEX locator with an explicit (or {@code null}=auto) encoding. */
    public static FieldLocator regex(String pattern, EncodingSpec encoding) {
        return new FieldLocator(Kind.REGEX, List.of(), pattern, encoding);
    }

    /** A copy of this locator with a different encoding (same kind/paths/regex) - for the Check panel's tick. */
    public FieldLocator withEncoding(EncodingSpec enc) {
        return new FieldLocator(kind, candidates, regex, enc);
    }

    /**
     * Locate this field's value span in {@code body}.
     *
     * PATH: try each candidate path in order. REGEX: the first match's capture group 1 (or group 0 if the
     * pattern has no groups). A bad pattern or a group that did not participate yields {@code null} - a
     * locator never throws into the per-request decode path.
     *
     * @return the {@code {start, end}} span (for {@link JsonValueEditor#splice}), or {@code null} if nothing
     *     resolves to an editable value
     */
    public int[] locate(byte[] body) {
        if (body == null) {
            return null;
        }
        return kind == Kind.REGEX ? locateRegex(body) : locatePath(body);
    }

    private int[] locatePath(byte[] body) {
        for (JsonPath path : candidates) {
            int[] span = JsonValueEditor.findStringValueSpanAtPath(body, path);
            if (span != null) {
                return span;
            }
        }
        return null;
    }

    private int[] locateRegex(byte[] body) {
        // ISO-8859-1 is byte-preserving (each byte 0x00..0xFF ⇄ one char), so a regex char index equals the
        // byte index the splice needs - exact for any body, including non-ASCII bytes before the match.
        String s = new String(body, StandardCharsets.ISO_8859_1);
        try {
            Pattern pattern = REGEX_CACHE.computeIfAbsent(regex, Pattern::compile);
            // Run against SafeRegex's input-capped, step-budgeted view: a catastrophic pattern trips the
            // budget (caught below as a clean null) instead of hanging the UI thread. start()/end() index
            // the same chars/bytes as the splice.
            Matcher m = pattern.matcher(SafeRegex.budgeted(s));
            if (!m.find()) {
                return null;
            }
            int group = m.groupCount() >= 1 ? 1 : 0;
            int start = m.start(group);
            int end = m.end(group);
            if (start < 0 || end < 0) {
                return null; // an optional capture group that did not participate
            }
            return new int[]{start, end};
        } catch (RuntimeException e) {
            return null; // invalid pattern OR step budget exceeded - never throw into per-request decode
        }
    }
}
