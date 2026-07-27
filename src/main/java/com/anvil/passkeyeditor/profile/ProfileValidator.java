package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;
import com.anvil.passkeyeditor.util.DecodedDetail;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HexFormat;

/**
 * The Check engine: given a captured body and a
 * profile's {@link FieldLocator}, it reports exactly what a field extracts and decodes - the raw
 * located value, its decoded view, and a status - so an operator can see the profile is sound before
 * trusting it live. Configuring paths and encodings is one thing; confirming they work is
 * another - this does it on the operator's own pasted reg/auth body.
 *
 * Pure + Burp-free (the UI just renders {@link CheckResult}s), so it is fully unit-testable. Decoding
 * reuses the same {@link WrapperCodec} unwrap + {@link CborCodec} the editor uses, so "green here" means
 * "green in the ceremony tab".
 */
public final class ProfileValidator {

    /** What a single field's locator produced against a body. */
    public enum Status {
        /** Located and decoded to a well-formed value. */
        OK,
        /** The locator resolved nothing on this body (wrong path/regex, or the field is absent). */
        NOT_FOUND,
        /** Located, but the bytes did not decode as expected (wrong encoding, or a malformed/foreign value). */
        SUSPECT,
        /**
         * An optional field the body simply does not carry (see {@link Field#required()}). Not an
         * error and not actionable: for an optional field, "the locator missed" and "the ceremony omits it"
         * are indistinguishable, and the honest report is that there is nothing there. Rendered muted, not
         * red, so a genuine misconfiguration keeps the operator's attention.
         */
        ABSENT
    }

    /**
     * The outcome of checking one field.
     *
     * @param field        the WebAuthn field checked
     * @param status       {@link Status}
     * @param located      the raw located value as it sits on the wire (truncated for display), or {@code null}
     * @param decoded      a human decode preview (ceremony-appropriate), or {@code null} if not found
     * @param encoding     the encoding that was applied ({@code "auto: …"} or a pinned label)
     * @param note         a short explanation, especially for {@link Status#SUSPECT} / {@link Status#NOT_FOUND}
     * @param summary      a CONCISE one-line verdict (located + what it is) for the Check row - e.g.
     *                     {@code "webauthn.create"}, {@code "fmt=none, ES256 key"}, {@code "UP UV, signCount 1"},
     *                     {@code "Ed25519, 64B"}. {@code null} for non-OK results (the row shows {@code note}).
     * @param decodedBytes the decoded inner bytes (after unwrap), or {@code null} when nothing decoded -
     *                     the full value the Check expander renders (hex / ASCII / pretty JSON), so
     *                     the UI never re-decodes. {@code null} for NOT_FOUND and for an unwrap that threw.
     */
    public record CheckResult(Field field, Status status, String located, String decoded,
                              String encoding, String note, String summary, byte[] decodedBytes) {

        public boolean ok() {
            return status == Status.OK;
        }

        /** A compact one-line rendering (status tag + field + decode), for logs/tests. */
        public String line() {
            String tag = switch (status) {
                case OK -> "OK";
                case NOT_FOUND -> "NOT_FOUND";
                case ABSENT -> "ABSENT";
                case SUSPECT -> "SUSPECT";
            };
            String body = status == Status.NOT_FOUND || status == Status.ABSENT ? note : decoded;
            return tag + " " + field.jsonName() + " [" + encoding + "] → " + body;
        }
    }

    private final WrapperCodec wrapperCodec;
    private final CborCodec cborCodec;

    public ProfileValidator() {
        this(new WrapperCodec.Default(), new Webauthn4jCborCodec());
    }

    public ProfileValidator(WrapperCodec wrapperCodec, CborCodec cborCodec) {
        this.wrapperCodec = wrapperCodec;
        this.cborCodec = cborCodec;
    }

    /** Check every field a {@link PhaseSpec} declares, in Field-declaration (enum ordinal) order - the
     *  PhaseSpec backs its map with an EnumMap, so this iteration order is deterministic across runs. */
    public Map<Field, CheckResult> checkAll(byte[] body, PhaseSpec spec) {
        Map<Field, CheckResult> out = new LinkedHashMap<>();
        if (spec == null) {
            return out;
        }
        for (Map.Entry<Field, FieldLocator> e : spec.fields().entrySet()) {
            out.put(e.getKey(), check(body, e.getKey(), e.getValue()));
        }
        return out;
    }

    /** A NOT_FOUND result carrying only an explanatory note (no decoded value / preview). */
    private static CheckResult notFound(Field field, String note) {
        return new CheckResult(field, Status.NOT_FOUND, null, null, "-", note, null, null);
    }

    /**
     * Locate + decode one field, never throwing - every failure becomes a {@link Status} the panel renders.
     */
    public CheckResult check(byte[] body, Field field, FieldLocator locator) {
        if (locator == null) {
            return notFound(field, "no locator configured");
        }
        int[] span;
        try {
            span = locator.locate(body);
        } catch (RuntimeException e) {
            return notFound(field, "locator error: " + e.getMessage());
        }
        if (span == null || body == null) {
            if (!field.required()) {
                return new CheckResult(field, Status.ABSENT, null, null, "-",
                        "not present in this ceremony (optional)", null, null);
            }
            return notFound(field, locator.kind() == FieldLocator.Kind.REGEX
                    ? "regex matched nothing" : "path did not resolve to a string value");
        }
        String wire = new String(body, span[0], span[1] - span[0], StandardCharsets.ISO_8859_1);

        // Unwrap: AUTO (self-detect base64/envelope) + optional URL tick, or a fully-pinned EncodingSpec -
        // all via Encodings.decode. A pinned-layer mismatch throws and lands as SUSPECT.
        byte[] inner;
        String encLabel;
        try {
            EncodingSpec enc = locator.encoding();
            WrapperCodec.Unwrapped uw = Encodings.decode(wrapperCodec, slice(body, span), enc);
            inner = uw.inner();
            encLabel = (enc == null || enc.isAuto()) ? "auto: " + autoLabel(uw.spec()) : enc.label();
            // If the operator ticked URL-encoded but this value isn't actually percent-encoded, Encodings'
            // self-check dropped the layer (so the wire still rebuilds byte-exact) - say so, so a ticked box
            // with no effect doesn't read as a confirmed url-encoding.
            if (enc != null && enc.urlEncoded() && !hasUrlFrame(uw.spec())) {
                encLabel += ", url tick: no %-escapes";
            }
        } catch (RuntimeException e) {
            return new CheckResult(field, Status.SUSPECT, truncate(wire),
                    "could not decode under the pinned encoding", labelOrAuto(locator), e.getMessage(), null, null);
        }

        Decoded d = decodeForField(field, inner);
        // Attach the decoded inner bytes so the Check expander shows the full hex / ASCII / pretty
        // JSON without re-decoding - even for SUSPECT (e.g. a header-recovered authData), where seeing the
        // actual bytes is exactly what tells the operator the field is mis-located.
        return new CheckResult(field, d.status, truncate(wire), d.preview, encLabel, d.note, d.summary, inner);
    }

    // ---- field-specific decode previews --------------------------------------------------------

    /** {@code preview} = the verbose one-liner (logs/tests); {@code summary} = the CONCISE row verdict (OK only). */
    private record Decoded(Status status, String preview, String summary, String note) {}

    private Decoded decodeForField(Field field, byte[] inner) {
        try {
            return switch (field) {
                case CLIENT_DATA_JSON -> clientData(inner);
                case ATTESTATION_OBJECT -> attestation(inner);
                case AUTHENTICATOR_DATA -> authData(inner);
                case SIGNATURE -> signature(inner);
                case USER_HANDLE, CREDENTIAL_ID -> opaque(inner);
            };
        } catch (RuntimeException e) {
            return new Decoded(Status.SUSPECT, "(" + inner.length + " bytes raw)", null,
                    "decode failed: " + e.getMessage());
        }
    }

    private static Decoded clientData(byte[] inner) {
        JsonObject o;
        try {
            o = JsonParser.parseString(new String(inner, StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (RuntimeException e) {
            return new Decoded(Status.SUSPECT, "(" + inner.length + " bytes, not JSON)", null, "clientDataJSON is not JSON");
        }
        String type = str(o, "type");
        String origin = str(o, "origin");
        String challenge = str(o, "challenge");
        String preview = "type=" + nz(type) + "  origin=" + nz(origin) + "  challenge=" + previewStr(challenge);
        // A clientDataJSON must carry a NON-EMPTY ceremony type marker; its absence - or an empty-string type -
        // means we located the wrong value (an empty type also gives no concise verdict, so treat it as SUSPECT).
        boolean hasType = type != null && !type.isBlank();
        Status st = hasType ? Status.OK : Status.SUSPECT;
        // Concise verdict = the ceremony type (webauthn.create / webauthn.get) - the field's "what it is".
        return new Decoded(st, preview, hasType ? type : null,
                hasType ? null : "missing or empty \"type\" member, likely the wrong value");
    }

    private Decoded attestation(byte[] inner) {
        AttestationObject att = cborCodec.decodeAttestationObject(inner);
        if (att.authData() == null) {
            return new Decoded(Status.SUSPECT, "(" + inner.length + " bytes, no authData)", null, "attestationObject has no authData");
        }
        AuthenticatorData ad = att.authData();
        String fmt = att.fmt() != null ? att.fmt() : "(unrecognized)";
        StringBuilder sb = new StringBuilder("fmt=").append(fmt)
                .append("  flags=").append(flags(ad)).append("  credId=")
                .append(ad.credentialId() != null ? ad.credentialId().length + "B" : "-");
        CoseKey key = ad.credentialPublicKey();
        if (key != null) {
            sb.append("  key=").append(keyLabel(key));
        }
        // Soundness gate: a real registration attestation has a parsed fmt AND an embedded credential key.
        // A null fmt (webauthn4j couldn't read the attestation map) or a header-recovered / keyless authData
        // means we located something that isn't a clean attestationObject - flag it, don't greenlight garbage.
        if (att.fmt() == null) {
            return new Decoded(Status.SUSPECT, sb.toString(), null,
                    "attestation format unrecognized, likely not an attestationObject");
        }
        if (key == null || ad.headerRecovered()) {
            return new Decoded(Status.SUSPECT, sb.toString(), null, "embedded authData / credential key did not decode");
        }
        // Concise verdict = the attestation format + the embedded credential key's algorithm.
        return new Decoded(Status.OK, sb.toString(), "fmt=" + att.fmt() + ", " + algShort(key.alg()) + " key", null);
    }

    private Decoded authData(byte[] inner) {
        AuthenticatorData ad = cborCodec.decodeAuthData(inner);
        if (ad.rpIdHash() == null) {
            return new Decoded(Status.SUSPECT, "(" + inner.length + " bytes, undecodable)", null, "authenticatorData did not decode");
        }
        String preview = "flags=" + flags(ad) + "  signCount=" + ad.signCount()
                + "  rpIdHash=" + hexPreview(ad.rpIdHash(), 6) + "  (" + inner.length + "B)";
        // rpIdHash-presence alone is NOT proof of a real authData: the codec length-recovers a 37-byte header
        // for ANY ≥37-byte blob when the structural parse fails. A header-recovered value is a mis-located
        // field masquerading as authData - SUSPECT, not OK (the Check engine must not mislead).
        if (ad.headerRecovered()) {
            return new Decoded(Status.SUSPECT, preview, null,
                    "header recovered by length only, not valid authData CBOR (likely a mis-located field)");
        }
        // Concise verdict = the set flag names + the signCount.
        return new Decoded(Status.OK, preview, flagNames(ad) + ", signCount " + ad.signCount(), null);
    }

    private static Decoded signature(byte[] inner) {
        // A locator that resolves to an EMPTY value (e.g. "" or a mis-addressed field) decodes to 0 bytes;
        // that is a mis-located field, not a valid signature - SUSPECT, never a green "raw · 0B" false-pass.
        if (inner.length == 0) {
            return new Decoded(Status.SUSPECT, "empty (0 bytes)", null,
                    "located value is empty; check the locator resolves the signature");
        }
        boolean der = (inner[0] & 0xFF) == 0x30; // inner is non-empty here (the 0-byte case returned above)
        String kind = der ? "DER ECDSA (ES256/384/512)"
                : (inner.length == 64 ? "raw 64B (Ed25519?)" : "raw (RSA/PSS or unknown)");
        String preview = kind + ", " + inner.length + "B (" + hexPreview(inner, 6) + ")";
        // Concise verdict = the signature shape + byte length.
        String shortKind = der ? "DER ECDSA" : (inner.length == 64 ? "Ed25519" : "raw");
        return new Decoded(Status.OK, preview, shortKind + ", " + inner.length + "B", null);
    }

    private static Decoded opaque(byte[] inner) {
        // Empty located value = a mis-located field, not a valid 0-byte credential/userHandle - SUSPECT.
        if (inner.length == 0) {
            return new Decoded(Status.SUSPECT, "empty (0 bytes)", null,
                    "located value is empty; check the locator");
        }
        String preview = inner.length + "B  hex=" + hexPreview(inner, 8);
        // Concise verdict = length + a printable-ASCII peek when the bytes are text (userHandle often is),
        // else a short hex peek (credentialId etc.). Reuses the same printable check as the decoded expander.
        String summary = DecodedDetail.isPrintableAscii(inner)
                ? inner.length + "B, \"" + asciiPreview(inner) + "\""
                : inner.length + "B, " + hexPreview(inner, 6);
        return new Decoded(Status.OK, preview, summary, null);
    }

    // ---- formatting helpers --------------------------------------------------------------------

    private static String flags(AuthenticatorData ad) {
        return String.format("0x%02x [", ad.flags() & 0xFF) + setFlagTokens(ad) + "]";
    }

    /** The SET flag names in bit order, space-joined and trimmed (e.g. {@code "UP UV"}); empty string if none set. */
    private static String setFlagTokens(AuthenticatorData ad) {
        StringBuilder f = new StringBuilder();
        if (ad.hasFlag(AuthenticatorData.FLAG_UP)) f.append("UP ");
        if (ad.hasFlag(AuthenticatorData.FLAG_UV)) f.append("UV ");
        if (ad.hasFlag(AuthenticatorData.FLAG_BE)) f.append("BE ");
        if (ad.hasFlag(AuthenticatorData.FLAG_BS)) f.append("BS ");
        if (ad.hasFlag(AuthenticatorData.FLAG_AT)) f.append("AT ");
        if (ad.hasFlag(AuthenticatorData.FLAG_ED)) f.append("ED ");
        return f.toString().trim();
    }

    private static String keyLabel(CoseKey key) {
        return "kty=" + key.kty() + "/" + algShort(key.alg());
    }

    /** Short COSE algorithm label for a concise verdict (superset of the 11 signer algs); {@code alg<n>} otherwise. */
    private static String algShort(int alg) {
        return switch (alg) {
            case -7 -> "ES256";
            case -35 -> "ES384";
            case -36 -> "ES512";
            case -8 -> "Ed25519";
            case -257 -> "RS256";
            case -258 -> "RS384";
            case -259 -> "RS512";
            case -37 -> "PS256";
            case -38 -> "PS384";
            case -39 -> "PS512";
            default -> "alg" + alg;
        };
    }

    /** The SET flag names, space-joined (e.g. {@code "UP UV"}), or {@code "no flags"} - for the concise verdict. */
    private static String flagNames(AuthenticatorData ad) {
        String s = setFlagTokens(ad);
        return s.isEmpty() ? "no flags" : s;
    }

    /** A short printable-ASCII peek (≤ 20 chars, ellipsised) for the concise verdict of a text-y opaque field. */
    private static String asciiPreview(byte[] b) {
        String s = new String(b, StandardCharsets.US_ASCII);
        return s.length() > 20 ? s.substring(0, 20) + "…" : s;
    }

    private static String autoLabel(com.anvil.passkeyeditor.codec.WrapSpec spec) {
        EncodingSpec derived = EncodingSpec.fromWrapSpec(spec);
        return derived != null ? derived.label() : (spec.isEmpty() ? "raw" : "multi-layer");
    }

    private static boolean hasUrlFrame(com.anvil.passkeyeditor.codec.WrapSpec spec) {
        return spec.frames().stream().anyMatch(
                f -> f.codec() == com.anvil.passkeyeditor.codec.WrapSpec.Codec.URL_ENCODE);
    }

    private static String labelOrAuto(FieldLocator loc) {
        return loc.encoding() == null ? "auto" : loc.encoding().label();
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : null;
    }

    private static String nz(String s) {
        return s != null ? s : "(none)";
    }

    private static String previewStr(String s) {
        if (s == null) return "(none)";
        return s.length() > 18 ? s.substring(0, 18) + "…" : s;
    }

    private static String truncate(String s) {
        return s.length() > 64 ? s.substring(0, 64) + "… (" + s.length() + "B)" : s;
    }

    private static String hexPreview(byte[] b, int n) {
        if (b == null) return "(none)";
        int len = Math.min(n, b.length);
        String prefix = HexFormat.of().formatHex(b, 0, len);
        return b.length > n ? prefix + "…" : prefix;
    }

    private static byte[] slice(byte[] b, int[] span) {
        byte[] out = new byte[span[1] - span[0]];
        System.arraycopy(b, span[0], out, 0, out.length);
        return out;
    }
}
