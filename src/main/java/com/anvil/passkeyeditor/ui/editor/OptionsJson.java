package com.anvil.passkeyeditor.ui.editor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import static com.anvil.passkeyeditor.ui.editor.JsonText.escape;
import static com.anvil.passkeyeditor.ui.editor.JsonText.indent;
import static com.anvil.passkeyeditor.ui.editor.JsonText.leafEquals;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure, Burp-free renderer for the options-response Passkey Editor tab's editable coloured JSON view.
 *
 * It is the generic-JSON sibling of {@link CeremonyJson}: the options response ({@code
 * generate-*-options}) is arbitrary unsigned JSON (objects, arrays like {@code pubKeyCredParams} /
 * {@code allowCredentials}, and scalars), not a fixed WebAuthn structure, so this renders any JSON tree -
 * pretty-printed with recorded key / string / scalar / changed-value spans for syntax highlighting + the
 * amber "what changed" diff. It is deliberately kept separate from {@link CeremonyJson} (which is
 * WebAuthn-tree-specific and on the demo-critical request path) so the request tab is untouched.
 *
 * Every method is pure + never throws; the editor is a thin renderer over these, so the logic is fully
 * unit-testable ({@code OptionsJsonTest}).
 */
final class OptionsJson {

    private OptionsJson() {
    }

    /** Compact serializer for write-back; HTML-escaping off so base64url / origins stay literal on the wire. */
    private static final Gson COMPACT = new GsonBuilder().disableHtmlEscaping().create();

    // ---- parse / serialize ---------------------------------------------------------------------

    /** Parse UTF-8 bytes as a JSON value, or {@code null} if not valid JSON. Never throws. */
    static JsonElement parse(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return parse(new String(bytes, StandardCharsets.UTF_8));
    }

    /** Parse a string as a JSON value, or {@code null} if not valid JSON. Never throws. */
    static JsonElement parse(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return JsonParser.parseString(text);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Compact UTF-8 bytes for the wire (only ever used for an EDITED response; unedited returns the original). */
    static byte[] toWireBytes(JsonElement el) {
        return COMPACT.toJson(el).getBytes(StandardCharsets.UTF_8);
    }

    // ---- leaf diff (objects + arrays) ----------------------------------------------------------

    /** The dotted paths of the leaf values that differ between {@code orig} and {@code edited} (arrays by index). */
    static Set<String> changedLeafPaths(JsonElement orig, JsonElement edited) {
        Set<String> out = new LinkedHashSet<>();
        diff("", orig, edited, out);
        return out;
    }

    private static void diff(String path, JsonElement a, JsonElement b, Set<String> out) {
        if (a != null && a.isJsonObject() && b != null && b.isJsonObject()) {
            JsonObject ao = a.getAsJsonObject();
            JsonObject bo = b.getAsJsonObject();
            Set<String> keys = new LinkedHashSet<>(ao.keySet());
            keys.addAll(bo.keySet());
            for (String k : keys) {
                diff(join(path, k), ao.get(k), bo.get(k), out);
            }
            return;
        }
        if (a != null && a.isJsonArray() && b != null && b.isJsonArray()) {
            JsonArray aa = a.getAsJsonArray();
            JsonArray ba = b.getAsJsonArray();
            int n = Math.max(aa.size(), ba.size());
            for (int i = 0; i < n; i++) {
                diff(path + "." + i, i < aa.size() ? aa.get(i) : null, i < ba.size() ? ba.get(i) : null, out);
            }
            return;
        }
        if (!leafEquals(a, b)) {
            out.add(path);
        }
    }

    // ---- range-tracking pretty render ----------------------------------------------------------

    record Span(int start, int end) {
    }

    /** The pretty JSON text plus the char ranges of keys, string values, scalar values, and changed values. */
    record Rendered(String text, List<Span> keys, List<Span> strings, List<Span> scalars, List<Span> changed) {
    }

    /** Pretty-print {@code root} (2-space indent), recording spans; values whose path is in {@code changedPaths}
     *  are recorded as {@code changed} (amber) instead of string/scalar so the editor colours exactly them. */
    static Rendered render(JsonElement root, Set<String> changedPaths) {
        StringBuilder sb = new StringBuilder();
        List<Span> keys = new ArrayList<>();
        List<Span> strings = new ArrayList<>();
        List<Span> scalars = new ArrayList<>();
        List<Span> changed = new ArrayList<>();
        Set<String> chg = changedPaths != null ? changedPaths : Set.of();
        emitValue(root, "", 0, sb, keys, strings, scalars, changed, chg);
        sb.append('\n');
        return new Rendered(sb.toString(), keys, strings, scalars, changed);
    }

    private static void emitValue(JsonElement el, String path, int depth, StringBuilder sb, List<Span> keys,
            List<Span> strings, List<Span> scalars, List<Span> changed, Set<String> chg) {
        if (el == null || el.isJsonNull()) {
            scalar("null", path, sb, scalars, changed, chg);
        } else if (el.isJsonObject()) {
            int start = sb.length();
            emitObject(el.getAsJsonObject(), path, depth, sb, keys, strings, scalars, changed, chg);
            if (chg.contains(path)) {
                changed.add(new Span(start, sb.length())); // a whole object added/retyped - colour it all
            }
        } else if (el.isJsonArray()) {
            int start = sb.length();
            emitArray(el.getAsJsonArray(), path, depth, sb, keys, strings, scalars, changed, chg);
            if (chg.contains(path)) {
                changed.add(new Span(start, sb.length()));
            }
        } else {
            JsonPrimitive p = el.getAsJsonPrimitive();
            if (p.isString()) {
                int start = sb.length();
                sb.append('"').append(escape(p.getAsString())).append('"');
                (chg.contains(path) ? changed : strings).add(new Span(start, sb.length()));
            } else {
                scalar(p.toString(), path, sb, scalars, changed, chg);
            }
        }
    }

    private static void scalar(String text, String path, StringBuilder sb, List<Span> scalars,
            List<Span> changed, Set<String> chg) {
        int start = sb.length();
        sb.append(text);
        (chg.contains(path) ? changed : scalars).add(new Span(start, sb.length()));
    }

    private static void emitObject(JsonObject o, String path, int depth, StringBuilder sb, List<Span> keys,
            List<Span> strings, List<Span> scalars, List<Span> changed, Set<String> chg) {
        if (o.size() == 0) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        int i = 0;
        int n = o.size();
        for (Map.Entry<String, JsonElement> e : o.entrySet()) {
            indent(sb, depth + 1);
            int ks = sb.length();
            sb.append('"').append(escape(e.getKey())).append('"');
            keys.add(new Span(ks, sb.length()));
            sb.append(": ");
            emitValue(e.getValue(), join(path, e.getKey()), depth + 1, sb, keys, strings, scalars, changed, chg);
            if (++i < n) {
                sb.append(',');
            }
            sb.append('\n');
        }
        indent(sb, depth);
        sb.append('}');
    }

    private static void emitArray(JsonArray a, String path, int depth, StringBuilder sb, List<Span> keys,
            List<Span> strings, List<Span> scalars, List<Span> changed, Set<String> chg) {
        if (a.size() == 0) {
            sb.append("[]");
            return;
        }
        sb.append("[\n");
        for (int i = 0; i < a.size(); i++) {
            indent(sb, depth + 1);
            emitValue(a.get(i), path + "." + i, depth + 1, sb, keys, strings, scalars, changed, chg);
            if (i + 1 < a.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        indent(sb, depth);
        sb.append(']');
    }

    private static String join(String path, String key) {
        return path.isEmpty() ? key : path + "." + key;
    }

    // ---- the one built-in attack preset: UV downgrade ------------------------------------------

    /** COSE-standard member names for the UV-downgrade preset. */
    static final String UV_KEY = "userVerification";
    static final String DISCOURAGED = "discouraged";
    static final String AUTH_SELECTION = "authenticatorSelection";

    /** The current {@code userVerification} value - top-level (auth options) or under authenticatorSelection
     *  (reg options), or {@code null} if absent. Pure read; never throws. */
    static String userVerification(JsonElement root) {
        if (root == null || !root.isJsonObject()) {
            return null;
        }
        JsonObject o = root.getAsJsonObject();
        String top = strMember(o, UV_KEY);
        if (top != null) {
            return top;
        }
        if (o.has(AUTH_SELECTION) && o.get(AUTH_SELECTION).isJsonObject()) {
            return strMember(o.getAsJsonObject(AUTH_SELECTION), UV_KEY);
        }
        return null;
    }

    /**
     * Set {@code userVerification} to {@code "discouraged"} wherever it currently lives (top-level or under
     * authenticatorSelection). Mutates {@code root}; returns {@code true} if a value was actually changed.
     * Never throws.
     */
    static boolean downgradeUv(JsonElement root) {
        if (root == null || !root.isJsonObject()) {
            return false;
        }
        JsonObject o = root.getAsJsonObject();
        boolean changed = false;
        if (isDowngradeable(strMember(o, UV_KEY))) {
            o.addProperty(UV_KEY, DISCOURAGED);
            changed = true;
        }
        if (o.has(AUTH_SELECTION) && o.get(AUTH_SELECTION).isJsonObject()) {
            JsonObject sel = o.getAsJsonObject(AUTH_SELECTION);
            if (isDowngradeable(strMember(sel, UV_KEY))) {
                sel.addProperty(UV_KEY, DISCOURAGED);
                changed = true;
            }
        }
        return changed;
    }

    private static boolean isDowngradeable(String uv) {
        return uv != null && !DISCOURAGED.equals(uv);
    }

    private static String strMember(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : null;
    }
}
