package com.anvil.passkeyeditor.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A minimal, dependency-free locator into a JSON body - the address of one value, as a sequence of
 * object-key and array-index hops.
 *
 * This is the per-field path a {@code TargetProfile} stores so the editor can find a WebAuthn field
 * wherever a given RP nests it, instead of assuming a flat {@code response.<field>} shape. Real
 * captures need: deep object nesting ({@code response.response.attestationObject} - webauthn.io), an
 * array root ({@code [2].response.response.signature} - a Next.js server action), a differently-named
 * wrapper ({@code input_data.public_key.response.attestationObject} - Hanko), and descent into an
 * envelope key ({@code attestation.attestationObject.$base64} - Yubico, where the value is itself a
 * {@code {"$base64":"…"}} object). All four are just key/index hops, so no JSONPath dependency is
 * needed - see {@link JsonValueEditor#findStringValueSpanAtPath}.
 *
 * Out of scope here (deferred to a later release): descending into a stringified-JSON value (Descope
 * double-serialization) - that is a codec frame, not a structural hop. A plain {@code key}/{@code [i]}
 * grammar deliberately cannot express it.
 *
 * Syntax: dotted keys with bracketed indices, e.g. {@code "response.response.clientDataJSON"},
 * {@code "[2].response.response.signature"}, {@code "attestation.clientDataJSON.$base64"}. Keys may
 * contain any character except {@code '.'} and {@code '['} (so {@code $base64}, {@code input_data},
 * {@code public_key} are all valid keys).
 */
public final class JsonPath {

    /** One hop: a {@link Key} (object member) or an {@link Index} (array element). */
    public sealed interface Seg permits Key, Index {}

    /** An object-member hop. */
    public record Key(String name) implements Seg {
        public Key {
            // Fail loud on a name that {@link #toString()} could not round-trip through {@link #parse}: '.'
            // and '[' are the path delimiters, and an empty key is unrepresentable. Today every Key is born
            // from parse() (which can never emit these), so this only fires when a future caller -
            // auto-learn harvesting real wire key names - hits a dotted/namespaced key, which then needs an
            // escape grammar rather than silent persistence corruption.
            if (name == null || name.isEmpty() || name.indexOf('.') >= 0 || name.indexOf('[') >= 0) {
                throw new IllegalArgumentException("JsonPath key must be non-empty and free of '.'/'[' "
                        + "(the path delimiters); got: '" + name + "'. A key containing those needs an "
                        + "escape grammar (deferred to auto-learn).");
            }
        }
    }

    /** An array-element hop (0-based). */
    public record Index(int i) implements Seg {}

    private final List<Seg> segments;

    private JsonPath(List<Seg> segments) {
        this.segments = segments;
    }

    /** The hops, outermost-first. Empty == the whole body (the root value). */
    public List<Seg> segments() {
        return Collections.unmodifiableList(segments);
    }

    public boolean isEmpty() {
        return segments.isEmpty();
    }

    /**
     * Parse a dotted/bracketed path string into segments.
     *
     * @throws IllegalArgumentException on an unterminated {@code [..]}, a non-integer index, or an empty key
     */
    public static JsonPath parse(String path) {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        }
        List<Seg> segs = new ArrayList<>();
        int i = 0;
        int n = path.length();
        while (i < n) {
            char c = path.charAt(i);
            if (c == '.') {
                i++;
                continue;
            }
            if (c == '[') {
                int j = path.indexOf(']', i);
                if (j < 0) {
                    throw new IllegalArgumentException("unterminated '[' in path: " + path);
                }
                String num = path.substring(i + 1, j).trim();
                try {
                    segs.add(new Index(Integer.parseInt(num)));
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("non-integer index '" + num + "' in path: " + path);
                }
                i = j + 1;
            } else {
                int j = i;
                while (j < n && path.charAt(j) != '.' && path.charAt(j) != '[') {
                    j++;
                }
                String key = path.substring(i, j);
                if (key.isEmpty()) {
                    throw new IllegalArgumentException("empty key in path: " + path);
                }
                segs.add(new Key(key));
                i = j;
            }
        }
        return new JsonPath(segs);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Seg seg : segments) {
            if (seg instanceof Index idx) {
                sb.append('[').append(idx.i()).append(']');
            } else {
                if (sb.length() > 0) {
                    sb.append('.');
                }
                sb.append(((Key) seg).name());
            }
        }
        return sb.toString();
    }
}
