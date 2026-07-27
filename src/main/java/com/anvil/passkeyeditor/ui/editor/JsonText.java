package com.anvil.passkeyeditor.ui.editor;

import com.google.gson.JsonElement;

/**
 * Leaf JSON-text primitives shared by the two decoded-JSON renderers - {@link CeremonyJson} (the WebAuthn
 * tree) and {@link OptionsJson} (the generic options view). Only the value-shape-independent helpers live
 * here: string escaping, indentation, and leaf equality. Each renderer keeps its own {@code emit*}/{@code
 * diff} structure and its own {@code Span} record, so sharing these leaves the two renderers' structure -
 * and the byte-untouched request path - unchanged; this is display-only text formatting.
 */
final class JsonText {

    private JsonText() {
    }

    /** Escape a string for embedding between JSON double quotes (control chars &lt; 0x20 → {@code \\uXXXX}). */
    static String escape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.toString();
    }

    /** Append {@code depth} levels of two-space indentation to {@code sb}. */
    static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) {
            sb.append("  ");
        }
    }

    /** Leaf equality treating a Java {@code null} and a JSON {@code null} as equal. */
    static boolean leafEquals(JsonElement a, JsonElement b) {
        boolean an = a == null || a.isJsonNull();
        boolean bn = b == null || b.isJsonNull();
        if (an || bn) {
            return an && bn;
        }
        return a.equals(b);
    }
}
