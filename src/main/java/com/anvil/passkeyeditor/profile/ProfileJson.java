package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.codec.WrapSpec;
import com.anvil.passkeyeditor.util.JsonPath;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Burp-free (de)serialisation of a profile list to/from JSON bytes, for {@link ProfileStore} persistence.
 *
 * Hand-written JsonObject mapping (not record reflection) so the on-disk shape is stable and readable.
 * v2 persists the full per-field configuration the integrated editor produces - a
 * {@link FieldLocator}'s {@link FieldLocator.Kind kind} (PATH candidates or a REGEX), its explicit
 * {@link EncodingSpec} (or absent = AUTO), each phase's optional {@link UrlMatch}, and the profile's
 * {@code enabled} flag. v3 adds the profile's {@link SignerSpec} (default signing algorithm)
 * as a single {@code signer} COSE-id int. v4 adds the per-profile AUTO switches {@code autoPlant} /
 * {@code autoResign} (booleans). v5 adds the AUTO {@code plantAttestation} format (a
 * {@link PlantAttestation} name). Reading is resilient: a missing field defaults to the 1a behaviour (PATH,
 * AUTO encoding, no URL scope, enabled), an absent {@code signer} defaults to ES256, absent auto flags
 * default {@code false}, and an absent/unknown {@code plantAttestation} defaults to {@code NONE} - so a
 * v1..v4 store loads unchanged and AUTO-inert (freeze-safe).
 */
public final class ProfileJson {

    private static final int VERSION = 5;
    /** Refuse an absurdly large persisted blob - the operator's own extensionData, but cap the EDT parse. */
    private static final int MAX_BYTES = 8 * 1024 * 1024;
    /**
     * Per-field cap on a persisted sample body. A sample longer than this is omitted on write so one
     * oversized scratch paste can never push the whole store past {@link #MAX_BYTES} (which would reject the
     * entire document on next load → a silent reseed that drops every custom profile). Real ceremony bodies
     * are KB-scale; the operator can re-paste a huge one into the Check panel without persisting it.
     */
    private static final int MAX_SAMPLE_CHARS = 256 * 1024;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private ProfileJson() {
    }

    public static byte[] toJson(List<TargetProfile> profiles) {
        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);
        JsonArray arr = new JsonArray();
        for (TargetProfile p : profiles) {
            arr.add(profileToJson(p));
        }
        root.add("profiles", arr);
        return GSON.toJson(root).getBytes(StandardCharsets.UTF_8);
    }

    /** Parse a profile list; returns an empty list on null/empty/garbage rather than throwing. */
    public static List<TargetProfile> fromJson(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES) {
            return new ArrayList<>();
        }
        try {
            JsonElement el = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8));
            if (!el.isJsonObject()) {
                return new ArrayList<>();
            }
            JsonArray arr = el.getAsJsonObject().getAsJsonArray("profiles");
            if (arr == null) {
                return new ArrayList<>();
            }
            List<TargetProfile> out = new ArrayList<>();
            for (JsonElement e : arr) {
                try {
                    out.add(profileFromJson(e.getAsJsonObject()));
                } catch (RuntimeException perProfile) {
                    // Skip ONE malformed entry rather than discarding every valid profile in the store.
                }
            }
            return out;
        } catch (Throwable e) {
            // Corrupt at the document level - the caller re-seeds the built-in profiles. Catch Throwable (not
            // just RuntimeException) so a StackOverflowError from Gson's recursive parse on a deeply-nested
            // blob still degrades to reseed rather than throwing on load and bricking the extension.
            return new ArrayList<>();
        }
    }

    // ---- profile --------------------------------------------------------------------------------

    private static JsonObject profileToJson(TargetProfile p) {
        JsonObject o = new JsonObject();
        o.addProperty("id", p.id());
        o.addProperty("name", p.name());
        o.addProperty("enabled", p.enabled());
        o.addProperty("signer", p.signer().coseAlg()); // v3: default signing algorithm (COSE id)
        o.addProperty("autoPlant", p.autoPlant());     // v4: per-profile AUTO switches (default false)
        o.addProperty("autoResign", p.autoResign());
        o.addProperty("plantAttestation", p.plantAttestation().name()); // v5: AUTO plant attestation format
        addSample(o, "sampleRegBody", p.sampleRegBody());
        addSample(o, "sampleAuthBody", p.sampleAuthBody());

        JsonObject host = new JsonObject();
        host.addProperty("kind", p.host().kind().name());
        host.addProperty("pattern", p.host().pattern());
        o.add("host", host);

        JsonObject phases = new JsonObject();
        for (Map.Entry<Phase, PhaseSpec> ph : p.phases().entrySet()) {
            phases.add(ph.getKey().name(), phaseToJson(ph.getValue()));
        }
        o.add("phases", phases);
        return o;
    }

    private static TargetProfile profileFromJson(JsonObject o) {
        String id = getStr(o, "id", null);
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("profile id required"); // skipped per-element by fromJson
        }
        String name = getStr(o, "name", id);
        boolean enabled = getBool(o, "enabled", true); // default true (v1); a non-boolean does NOT flip it

        JsonObject host = o.has("host") && o.get("host").isJsonObject() ? o.getAsJsonObject("host") : null;
        HostMatch hostMatch = host != null
                ? new HostMatch(HostMatch.Kind.valueOf(getStr(host, "kind", "EXACT")), getStr(host, "pattern", ""))
                : new HostMatch(HostMatch.Kind.EXACT, ""); // safe inert default (matches nothing), never ANY

        Map<Phase, PhaseSpec> phases = new EnumMap<>(Phase.class);
        for (Map.Entry<String, JsonElement> ph : o.getAsJsonObject("phases").entrySet()) {
            phases.put(Phase.valueOf(ph.getKey()), phaseFromJson(ph.getValue().getAsJsonObject()));
        }
        // v3 signer (COSE id); absent (v1/v2) → ES256. The id is not validated here - an unknown alg
        // round-trips as data and is resolved (or falls back) only when a signer is actually built.
        SignerSpec signer = new SignerSpec(getInt(o, "signer", SignerSpec.ES256.coseAlg()));
        // v4 AUTO switches; absent (v1/v2/v3) or non-boolean → false (AUTO-inert, freeze-safe).
        boolean autoPlant = getBool(o, "autoPlant", false);
        boolean autoResign = getBool(o, "autoResign", false);
        // v5 AUTO plant attestation; absent (v1..v4) or unknown name → NONE (freeze-safe).
        PlantAttestation plantAttestation = PlantAttestation.fromName(getStr(o, "plantAttestation", null));
        return new TargetProfile(id, name, hostMatch, phases, enabled,
                getStr(o, "sampleRegBody", null), getStr(o, "sampleAuthBody", null), signer, autoPlant, autoResign,
                plantAttestation);
    }

    // ---- phase ----------------------------------------------------------------------------------

    private static JsonObject phaseToJson(PhaseSpec spec) {
        JsonObject phaseObj = new JsonObject();
        if (spec.url() != null && spec.url().isActive()) {
            phaseObj.add("url", urlToJson(spec.url()));
        }
        JsonObject fields = new JsonObject();
        for (Map.Entry<Field, FieldLocator> f : spec.fields().entrySet()) {
            fields.add(f.getKey().name(), fieldLocatorToJson(f.getValue()));
        }
        phaseObj.add("fields", fields);
        return phaseObj;
    }

    private static PhaseSpec phaseFromJson(JsonObject phaseObj) {
        UrlMatch url = phaseObj.has("url") ? urlFromJson(phaseObj.getAsJsonObject("url")) : null;
        JsonObject fields = phaseObj.getAsJsonObject("fields");
        Map<Field, FieldLocator> fmap = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> f : fields.entrySet()) {
            fmap.put(Field.valueOf(f.getKey()), fieldLocatorFromJson(f.getValue().getAsJsonObject()));
        }
        return new PhaseSpec(fmap, url);
    }

    // ---- field locator --------------------------------------------------------------------------

    private static JsonObject fieldLocatorToJson(FieldLocator loc) {
        JsonObject o = new JsonObject();
        o.addProperty("kind", loc.kind().name());
        if (loc.kind() == FieldLocator.Kind.REGEX) {
            o.addProperty("regex", loc.regex());
        } else {
            JsonArray paths = new JsonArray();
            for (JsonPath jp : loc.candidates()) {
                paths.add(jp.toString());
            }
            o.add("paths", paths);
        }
        if (loc.encoding() != null) {
            o.add("encoding", encodingToJson(loc.encoding()));
        }
        return o;
    }

    private static FieldLocator fieldLocatorFromJson(JsonObject o) {
        EncodingSpec enc = o.has("encoding") ? encodingFromJson(o.getAsJsonObject("encoding")) : null;
        FieldLocator.Kind kind = o.has("kind")
                ? FieldLocator.Kind.valueOf(o.get("kind").getAsString()) : FieldLocator.Kind.PATH;
        if (kind == FieldLocator.Kind.REGEX) {
            return FieldLocator.regex(o.get("regex").getAsString(), enc);
        }
        JsonArray paths = o.getAsJsonArray("paths");
        String[] ps = new String[paths.size()];
        for (int i = 0; i < ps.length; i++) {
            ps[i] = paths.get(i).getAsString();
        }
        return FieldLocator.of(enc, ps);
    }

    // ---- encoding + url -------------------------------------------------------------------------

    private static JsonObject encodingToJson(EncodingSpec e) {
        JsonObject o = new JsonObject();
        o.addProperty("urlEncoded", e.urlEncoded());
        o.addProperty("base64", e.base64().name());
        o.addProperty("padding", e.padding().name());
        if (e.envelopeKey() != null) {
            o.addProperty("envelopeKey", e.envelopeKey());
        }
        return o;
    }

    private static EncodingSpec encodingFromJson(JsonObject o) {
        boolean url = o.has("urlEncoded") && o.get("urlEncoded").getAsBoolean();
        EncodingSpec.Base64Kind b64 = o.has("base64")
                ? EncodingSpec.Base64Kind.valueOf(o.get("base64").getAsString()) : EncodingSpec.Base64Kind.AUTO;
        WrapSpec.Padding pad = o.has("padding")
                ? WrapSpec.Padding.valueOf(o.get("padding").getAsString()) : WrapSpec.Padding.UNPADDED;
        String env = o.has("envelopeKey") ? o.get("envelopeKey").getAsString() : null;
        return new EncodingSpec(url, b64, pad, env);
    }

    private static JsonObject urlToJson(UrlMatch u) {
        JsonObject o = new JsonObject();
        o.addProperty("kind", u.kind().name());
        o.addProperty("pattern", u.pattern());
        if (u.method() != null) {
            o.addProperty("method", u.method());
        }
        return o;
    }

    private static UrlMatch urlFromJson(JsonObject o) {
        UrlMatch.Kind kind = UrlMatch.Kind.valueOf(getStr(o, "kind", "ANY"));
        return new UrlMatch(kind, getStr(o, "pattern", ""), getStr(o, "method", null));
    }

    // ---- tolerant accessors (a single odd field defaults rather than nuking the whole profile) ---

    private static String getStr(JsonObject o, String key, String def) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : def;
    }

    private static boolean getBool(JsonObject o, String key, boolean def) {
        return o.has(key) && o.get(key).isJsonPrimitive() && o.get(key).getAsJsonPrimitive().isBoolean()
                ? o.get(key).getAsBoolean() : def;
    }

    /** Tolerant int accessor: a present numeric primitive, else {@code def} (a non-number never throws). */
    private static int getInt(JsonObject o, String key, int def) {
        if (o.has(key) && o.get(key).isJsonPrimitive() && o.get(key).getAsJsonPrimitive().isNumber()) {
            try {
                return o.get(key).getAsInt();
            } catch (RuntimeException ignored) {
                // fall through to the default
            }
        }
        return def;
    }

    /** Persist a sample body only when present and within {@link #MAX_SAMPLE_CHARS} (else omit - see cap doc). */
    private static void addSample(JsonObject o, String key, String body) {
        if (body != null && !body.isEmpty() && body.length() <= MAX_SAMPLE_CHARS) {
            o.addProperty(key, body);
        }
    }
}
