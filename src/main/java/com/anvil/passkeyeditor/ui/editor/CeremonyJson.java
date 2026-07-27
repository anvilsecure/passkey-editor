package com.anvil.passkeyeditor.ui.editor;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CeremonyModel;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.model.ClientData;
import com.anvil.passkeyeditor.model.CoseKey;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import static com.anvil.passkeyeditor.ui.editor.JsonText.escape;
import static com.anvil.passkeyeditor.ui.editor.JsonText.indent;
import static com.anvil.passkeyeditor.ui.editor.JsonText.leafEquals;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure, Burp-free helper for the Passkey Editor tab's decoded JSON view:
 * builds an ordered JSON tree from a {@link CeremonyModel}, diffs two trees by leaf path (for the
 * Original→Edited colouring), pretty-renders a tree while tracking the character ranges of keys / values /
 * changed-values (so the editor can syntax-highlight + colour what changed), and reads an operator's edited
 * JSON back into the field-level edits the existing re-sign path understands.
 *
 * It also exposes {@link #attestationObjectJson(byte[])} / {@link #authenticatorDataJson(byte[])} so the
 * Profile-Editor Check panel can show the SAME structured CBOR decode this tab shows for those fields
 * (coherent with the editor), instead of a raw-hex dump.
 *
 * Unit-tested headlessly ({@code CeremonyJsonTest}); it touches no Burp/Swing API and never re-encodes the
 * wire itself - the editor routes the {@link Edits} it returns through the proven {@code forgeWith} path.
 */
public final class CeremonyJson {

    private CeremonyJson() {
    }

    /** Pretty-printer for the standalone field-decode views; HTML-escaping off so wire punctuation stays literal. */
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    /** Shared decode-only codec (webauthn4j converters are constructed once + reusable) for the field-decode views. */
    private static final CborCodec CODEC = new Webauthn4jCborCodec();

    // ---- standalone field decode (Check panel) -------------------------------------------------

    /**
     * The registration {@code attestationObject} CBOR bytes rendered as the SAME decoded JSON the Passkey
     * Editor tab shows (attestationStatement / authenticatorData / fmt, with the nested flags + COSE key), so
     * the Check panel's decoded view is coherent with the editor rather than an opaque hex blob. Returns
     * {@code null} if the bytes do not decode as an attestation object (the caller then shows raw hex). Never
     * throws.
     */
    public static String attestationObjectJson(byte[] cbor) {
        if (cbor == null) {
            return null;
        }
        try {
            AttestationObject att = CODEC.decodeAttestationObject(cbor);
            if (att.authData() == null) {
                return null; // no decodable authData → not a usable attestation object
            }
            CeremonyModel m = new CeremonyModel(CeremonyType.CREATE);
            m.setAttestationObject(att);
            m.setAuthenticatorData(att.authData());
            JsonElement sub = tree(m).get("attestationObject");
            return sub == null ? null : PRETTY.toJson(sub);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * The assertion {@code authenticatorData} CBOR bytes rendered as the SAME decoded JSON the Passkey Editor
     * tab shows (rpIdHash / signCount / nested flags). Returns {@code null} if the bytes do not decode. Never
     * throws.
     */
    public static String authenticatorDataJson(byte[] authData) {
        if (authData == null) {
            return null;
        }
        try {
            AuthenticatorData ad = CODEC.decodeAuthData(authData);
            if (ad.rpIdHash() == null) {
                return null;
            }
            CeremonyModel m = new CeremonyModel(CeremonyType.GET);
            m.setAuthenticatorData(ad);
            JsonElement sub = tree(m).get("authenticatorData");
            return sub == null ? null : PRETTY.toJson(sub);
        } catch (RuntimeException e) {
            return null;
        }
    }

    // authData flag bits (mirror AuthenticatorData; kept local so this stays a pure helper).
    private static final int FLAG_UP = 0x01;
    private static final int FLAG_UV = 0x04;
    private static final int FLAG_BE = 0x08;
    private static final int FLAG_BS = 0x10;
    private static final int FLAG_AT = 0x40;
    private static final int FLAG_ED = 0x80;

    private static final Gson COMPACT = new Gson();
    private static final BigDecimal UINT32_MAX = BigDecimal.valueOf(0xFFFFFFFFL);

    // ---- model → JSON tree --------------------------------------------------

    /** An ordered JSON tree decoding {@code m}. Never throws. */
    static JsonObject tree(CeremonyModel m) {
        JsonObject root = new JsonObject();
        if (m == null) {
            return root;
        }
        root.add("clientDataJSON", clientDataJson(m.clientData()));
        if (m.type() == CeremonyType.CREATE) {
            JsonObject att = new JsonObject();
            JsonObject stmt = new JsonObject();
            AttestationObject ao = m.attestationObject();
            String fmt = ao != null && ao.fmt() != null ? ao.fmt() : "none";
            stmt.addProperty("format", fmt);
            att.add("attestationStatement", stmt);
            att.add("authenticatorData", authDataJson(m.authenticatorData(), true));
            att.addProperty("fmt", fmt);
            root.add("attestationObject", att);
        } else {
            root.add("authenticatorData", authDataJson(m.authenticatorData(), false));
            root.addProperty("signature", m.signature() != null ? hex(m.signature()) : null);
        }
        return root;
    }

    /** The real parsed clientDataJSON object (preserving any extra members), else a 4-field fallback. */
    private static JsonElement clientDataJson(ClientData cd) {
        if (cd == null) {
            return new JsonObject();
        }
        if (cd.raw() != null) {
            try {
                JsonElement el = JsonParser.parseString(new String(cd.raw(), StandardCharsets.UTF_8));
                if (el.isJsonObject()) {
                    return el;
                }
            } catch (RuntimeException ignored) {
                // fall through to the field view
            }
        }
        JsonObject o = new JsonObject();
        o.addProperty("type", cd.type());
        o.addProperty("challenge", cd.challenge());
        o.addProperty("origin", cd.origin());
        if (cd.crossOrigin() != null) {
            o.addProperty("crossOrigin", cd.crossOrigin());
        }
        return o;
    }

    private static JsonObject authDataJson(AuthenticatorData ad, boolean create) {
        JsonObject o = new JsonObject();
        if (ad == null || ad.rpIdHash() == null) {
            return o; // not decoded - leave empty rather than emit misleading zeros
        }
        o.addProperty("rpIdHash", hex(ad.rpIdHash()));
        o.add("extensions", new JsonObject());
        o.addProperty("signCount", ad.signCount());
        o.add("flags", flagsJson(ad.flags()));
        if (create) {
            JsonObject acd = new JsonObject();
            acd.addProperty("aaguid", ad.aaguid() != null ? aaguid(ad.aaguid()) : null);
            acd.add("coseKey", coseKeyJson(ad.credentialPublicKey()));
            acd.addProperty("credentialId", ad.credentialId() != null ? hex(ad.credentialId()) : null);
            o.add("attestedCredentialData", acd);
        } else {
            o.add("attestedCredentialData", new JsonObject()); // empty on an assertion (AT=0)
        }
        return o;
    }

    private static JsonObject flagsJson(int f) {
        JsonObject o = new JsonObject();
        o.addProperty("userPresent", (f & FLAG_UP) != 0);
        o.addProperty("userVerified", (f & FLAG_UV) != 0);
        o.addProperty("backupEligible", (f & FLAG_BE) != 0);
        o.addProperty("backupState", (f & FLAG_BS) != 0);
        o.addProperty("attestedCredentialData", (f & FLAG_AT) != 0);
        o.addProperty("extensionDataIncluded", (f & FLAG_ED) != 0);
        return o;
    }

    private static JsonObject coseKeyJson(CoseKey k) {
        JsonObject o = new JsonObject();
        if (k == null) {
            return o;
        }
        o.addProperty("keyType", ktyName(k.kty()));
        o.addProperty("algorithm", algName(k.alg()));
        int kty = k.kty();
        if (kty == 1 || kty == 2) { // OKP / EC2
            o.addProperty("curve", crvName(k.crv()));
            if (k.x() != null) {
                o.addProperty("x", hex(k.x()));
            }
            if (kty == 2 && k.y() != null) {
                o.addProperty("y", hex(k.y()));
            }
        } else if (kty == 3 && k.n() != null) { // RSA with n/e decoded
            // Show the modulus size, which is the property an operator actually reads off an RSA key, then
            // the modulus and exponent themselves. No `raw` here: it would restate the same bytes as an
            // unreadable blob directly under their decoded form.
            o.addProperty("modulusBits", k.n().length * 8);
            o.addProperty("n", hex(k.n()));
            if (k.e() != null) {
                o.addProperty("e", hex(k.e()));
            }
        } else { // an RSA key we could not decode, or an unknown key type
            if (k.raw() != null) {
                o.addProperty("raw", hex(k.raw()));
            }
        }
        return o;
    }

    private static String ktyName(int kty) {
        return switch (kty) {
            case 1 -> "OKP";
            case 2 -> "EC2";
            case 3 -> "RSA";
            default -> "kty" + kty;
        };
    }

    private static String algName(int alg) {
        try {
            return SignerAlgorithm.forCoseId(alg).label();
        } catch (RuntimeException e) {
            return "alg" + alg;
        }
    }

    private static String crvName(int crv) {
        return switch (crv) {
            case 1 -> "P-256";
            case 2 -> "P-384";
            case 3 -> "P-521";
            case 6 -> "Ed25519";
            default -> "crv" + crv;
        };
    }

    // ---- leaf diff -----------------------------------------------------------------------------

    /** The dotted paths of the leaf values that differ between {@code orig} and {@code edited}. */
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
                diff(path.isEmpty() ? k : path + "." + k, ao.get(k), bo.get(k), out);
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

    /** Pretty-print {@code tree} (2-space indent), recording spans; values whose path ∈ {@code changed} go to
     *  the {@code changed} span list instead of strings/scalars so the editor can colour exactly them. */
    static Rendered render(JsonObject tree, Set<String> changedPaths) {
        StringBuilder sb = new StringBuilder();
        List<Span> keys = new ArrayList<>();
        List<Span> strings = new ArrayList<>();
        List<Span> scalars = new ArrayList<>();
        List<Span> changed = new ArrayList<>();
        Set<String> chg = changedPaths != null ? changedPaths : Set.of();
        emitValue(tree, "", 0, sb, keys, strings, scalars, changed, chg);
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
                changed.add(new Span(start, sb.length())); // a leaf retyped to an object - colour the whole member
            }
        } else if (el.isJsonArray()) {
            scalar(el.toString(), path, sb, scalars, changed, chg); // our trees carry no arrays; safe fallback
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
            String childPath = path.isEmpty() ? e.getKey() : path + "." + e.getKey();
            emitValue(e.getValue(), childPath, depth + 1, sb, keys, strings, scalars, changed, chg);
            if (++i < n) {
                sb.append(',');
            }
            sb.append('\n');
        }
        indent(sb, depth);
        sb.append('}');
    }

    // ---- edited JSON → field-level edits -------------------------------------------------------

    /** Field-level edits read back from the operator's edited JSON (null = unchanged). On a rejected edit,
     *  {@code parseError} is set and {@code error} carries a specific, operator-facing reason to display. */
    record Edits(byte[] clientData, Integer flags, Long signCount, byte[] rpIdHash, boolean parseError,
            String error) {
    }

    private static Edits parseFail(String error) {
        return new Edits(null, null, null, null, true, error);
    }

    /**
     * Diff the operator's edited JSON against {@link #tree(CeremonyModel) tree(original)} and return only the
     * genuinely-changed editable fields, ready for the existing {@code forgeWith} path. {@code signature} is
     * ignored (it is re-signed). Any parse problem ⇒ {@code parseError=true} with all fields null.
     */
    static Edits diffEdits(String editedJsonText, CeremonyModel original) {
        JsonObject edited;
        try {
            JsonElement el = JsonParser.parseString(editedJsonText);
            if (!el.isJsonObject()) {
                return parseFail("invalid JSON: the edited body must be a JSON object.");
            }
            edited = el.getAsJsonObject();
        } catch (RuntimeException e) {
            return parseFail("invalid JSON: fix the syntax and try again.");
        }
        try {
            JsonObject orig = tree(original);
            AuthenticatorData oad = original != null ? original.authenticatorData() : null;

            byte[] clientData = null;
            JsonElement ecd = edited.get("clientDataJSON");
            if (ecd != null && ecd.isJsonObject() && !ecd.equals(orig.get("clientDataJSON"))) {
                clientData = COMPACT.toJson(ecd).getBytes(StandardCharsets.UTF_8);
            }

            Integer flags = null;
            Long signCount = null;
            byte[] rpIdHash = null;
            JsonObject ead = childObj(edited, "authenticatorData"); // GET shape (assertion edits)
            if (ead != null) {
                JsonObject ef = childObj(ead, "flags");
                if (ef != null) {
                    int nf = flagsByte(ef);
                    if (oad == null || nf != oad.flags()) {
                        flags = nf;
                    }
                }
                JsonElement scEl = ead.get("signCount");
                if (scEl != null && scEl.isJsonPrimitive() && scEl.getAsJsonPrimitive().isNumber()) {
                    BigDecimal bd = scEl.getAsBigDecimal();
                    if (bd.signum() < 0 || bd.stripTrailingZeros().scale() > 0 || bd.compareTo(UINT32_MAX) > 0) {
                        // non-integer or out of uint32 range - reject with a reason, never silently truncate
                        return parseFail("signCount must be a whole number between 0 and 4294967295.");
                    }
                    long sc = bd.longValueExact();
                    if (oad == null || sc != oad.signCount()) {
                        signCount = sc;
                    }
                }
                // rpIdHash is a fixed 32-byte slot in authData (a SHA-256 digest), so an edit must decode to
                // exactly 32 bytes. Read it back only when it actually differs from the displayed value; a
                // changed-but-malformed value is a specific error - it used to be dropped silently, which read
                // as the edit being "refused" (adding a character, or any non-hex character, both hit this).
                if (ead.has("rpIdHash") && ead.get("rpIdHash").isJsonPrimitive()) {
                    String typed = ead.get("rpIdHash").getAsString().trim();
                    String origHex = oad != null && oad.rpIdHash() != null
                            ? HexFormat.of().withUpperCase().formatHex(oad.rpIdHash()) : null;
                    if (origHex == null || !typed.equalsIgnoreCase(origHex)) {
                        byte[] rh = parseRpIdHash(typed);
                        if (rh == null) {
                            // Two sentences, two lines: what the field must be, then the easier route. The
                            // status area wraps, but an explicit break keeps the "do this instead" hint from
                            // trailing off the end of a wrapped paragraph.
                            return parseFail("rpIdHash must be a 32-byte SHA-256 hash: 64 hex digits (as "
                                    + "shown) or base64/base64url.\n"
                                    + "To target a different RP, use Attacks ▾ → Mutate RP-ID, which hashes "
                                    + "a domain for you.");
                        }
                        if (oad == null || !Arrays.equals(rh, oad.rpIdHash())) {
                            rpIdHash = rh;
                        }
                    }
                }
            }
            return new Edits(clientData, flags, signCount, rpIdHash, false, null);
        } catch (RuntimeException e) {
            return parseFail("could not read the edited JSON: " + e.getMessage());
        }
    }

    private static JsonObject childObj(JsonObject o, String key) {
        JsonElement e = o != null ? o.get(key) : null;
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    private static int flagsByte(JsonObject f) {
        int v = 0;
        v |= bool(f, "userPresent") ? FLAG_UP : 0;
        v |= bool(f, "userVerified") ? FLAG_UV : 0;
        v |= bool(f, "backupEligible") ? FLAG_BE : 0;
        v |= bool(f, "backupState") ? FLAG_BS : 0;
        v |= bool(f, "attestedCredentialData") ? FLAG_AT : 0;
        v |= bool(f, "extensionDataIncluded") ? FLAG_ED : 0;
        return v;
    }

    private static boolean bool(JsonObject o, String key) {
        JsonElement e = o.get(key);
        try {
            return e != null && e.isJsonPrimitive() && e.getAsBoolean();
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static byte[] tryHex(String s) {
        if (s == null) {
            return null;
        }
        try {
            return HexFormat.of().parseHex(s.trim());
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Parse an operator-typed rpIdHash to its 32 raw bytes, or {@code null} if it is not a 32-byte value.
     * Tries the displayed hex form first (64 digits, any case), then base64 / base64url as a paste
     * convenience (mirroring the credentialId field). Every form must decode to exactly 32 bytes:
     * rpIdHash is a fixed-width SHA-256 slot in the assertion authData, so a different length would corrupt
     * the flags / signCount that follow it.
     */
    private static byte[] parseRpIdHash(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        byte[] hex = tryHex(s);
        if (hex != null) {
            return hex.length == 32 ? hex : null; // valid hex, wrong length - malformed; don't reinterpret as base64
        }
        for (Base64.Decoder dec : new Base64.Decoder[]{Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                byte[] out = dec.decode(s);
                if (out.length == 32) {
                    return out;
                }
            } catch (RuntimeException ignored) {
                // try the next flavor
            }
        }
        return null;
    }

    private static String hex(byte[] b) {
        return HexFormat.of().withUpperCase().formatHex(b);
    }

    /** A 16-byte AAGUID as a lower-case dashed UUID (8-4-4-4-12); else raw hex. */
    private static String aaguid(byte[] b) {
        if (b.length != 16) {
            return hex(b);
        }
        String h = HexFormat.of().formatHex(b); // lower-case for the UUID convention
        return h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-"
                + h.substring(16, 20) + "-" + h.substring(20, 32);
    }
}
