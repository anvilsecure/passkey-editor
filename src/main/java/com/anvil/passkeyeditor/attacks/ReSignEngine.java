package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.profile.Encodings;
import com.anvil.passkeyeditor.profile.Field;
import com.anvil.passkeyeditor.profile.FieldLocator;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.PlantAttestation;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * The Burp-free locate → unwrap → forge → re-wrap → splice core of a one-shot re-sign / key-plant on a
 * raw request body. This is the same recipe {@link com.anvil.passkeyeditor.ui.editor.CeremonyRequestEditor}
 * runs manually (its {@code forgeWith} / {@code onSubstitute}), factored out so the AUTO {@code HttpHandler}
 * ({@link com.anvil.passkeyeditor.http.PasskeyAutoHandler}) can perform a pure re-sign / plain plant in-flight
 * without the editor's UI / span / idempotency machinery.
 *
 * Scope. AUTO does a PURE re-sign (no flag/origin/rpId edits - those are manual-only) and a
 * key-plant whose attestation format follows the profile's {@link PlantAttestation}: {@code fmt="none"}
 * (via {@link RegistrationSubstituter#substituteAndEncode}) or a {@code fmt="packed"} self-attestation (via
 * {@link RegistrationSubstituter#substituteSelfAttestedAndEncode}). A multi-edit AUTO would need an explicit
 * edit-spec parameter here.
 *
 * Stateless + thread-safe. Every method constructs its own collaborators per call (all cheap, all
 * Burp-free) and holds no mutable state, so the off-EDT handler may call it concurrently. It never
 * throws: any failure yields an unchanged {@link Result} ({@code changed == false}, original body).
 *
 * Byte-faithfulness to the editor's recipe is pinned by {@code ReSignEngineWireTest} (a deterministic-alg
 * byte-equivalence gate) + a per-algorithm verify oracle.
 */
public final class ReSignEngine {

    /** The outcome of a re-sign / plant attempt. {@code body} is the new wire body, or the original if {@code !changed}. */
    public record Result(byte[] body, boolean changed, String credIdHex, int coseAlg, String detail) {
    }

    private ReSignEngine() {
    }

    /**
     * Pure re-sign of the assertion in {@code body}: locate authenticatorData + clientDataJSON + signature via
     * {@code spec}, unwrap each under its per-field encoding, re-sign {@code authData ‖ SHA-256(clientDataJSON)}
     * with {@code signer}, re-wrap the fresh signature byte-exactly, and splice it back. Only the signature
     * field changes. Returns an unchanged result if any field is missing/undecodable (no-op, never throws).
     */
    public static Result reSignAssertion(byte[] body, PhaseSpec spec, CoseSigner signer) {
        int alg = signer.coseAlg();
        try {
            int[] sigSpan = spec.locate(Field.SIGNATURE, body);
            int[] adSpan = spec.locate(Field.AUTHENTICATOR_DATA, body);
            int[] cdSpan = spec.locate(Field.CLIENT_DATA_JSON, body);
            if (sigSpan == null || adSpan == null || cdSpan == null) {
                return new Result(body, false, credIdHex(body, spec), alg, "no signature/authData/clientData to re-sign");
            }
            WrapperCodec wrapper = new WrapperCodec.Default();
            WrapperCodec.Unwrapped ad = Encodings.decode(wrapper, slice(body, adSpan), encodingOf(spec, Field.AUTHENTICATOR_DATA));
            WrapperCodec.Unwrapped cd = Encodings.decode(wrapper, slice(body, cdSpan), encodingOf(spec, Field.CLIENT_DATA_JSON));
            WrapperCodec.Unwrapped sig = Encodings.decode(wrapper, slice(body, sigSpan), encodingOf(spec, Field.SIGNATURE));

            byte[] forged = new AssertionForger().sign(ad.inner(), cd.inner(), signer);
            byte[] sigWire = wrapper.rewrap(forged, sig.spec());
            byte[] out = JsonValueEditor.spliceAll(body, List.of(sigSpan), List.of(sigWire));
            return new Result(out, true, credIdHex(body, spec), alg, "re-signed assertion");
        } catch (RuntimeException e) {
            return new Result(body, false, credIdHex(body, spec), alg, "re-sign failed: " + e.getMessage());
        }
    }

    /**
     * Plain key-plant on the registration in {@code body} with the default {@code fmt="none"} attestation -
     * delegates to {@link #plantRegistration(byte[], PhaseSpec, CoseSigner, PlantAttestation)} with
     * {@link PlantAttestation#NONE}. Retained so existing callers/tests keep the historical behaviour.
     */
    public static Result plantRegistration(byte[] body, PhaseSpec spec, CoseSigner signer) {
        return plantRegistration(body, spec, signer, PlantAttestation.NONE);
    }

    /**
     * Key-plant on the registration in {@code body}, emitting the chosen {@code attestation} format: locate
     * attestationObject via {@code spec}, unwrap, substitute our credential public key
     * ({@link RegistrationSubstituter}), re-wrap byte-exactly, and splice back.
     *
     *   - {@link PlantAttestation#NONE} forces {@code fmt="none"} (empty {@code attStmt}).
     *   - {@link PlantAttestation#PACKED_SELF} additionally locates + unwraps the registration
     *       {@code clientDataJSON} (needed as the signed input) and emits a packed self-attestation signed by
     *       the planted key. If clientDataJSON is not locatable the plant is a no-op (unchanged body).
     *
     * The mode is orthogonal to {@code signer}'s algorithm - any supported algorithm works with either
     * format. {@link Result#credIdHex} is the registered credential's id (so the caller stores the planted
     * key under it). No-op + never throws on any failure.
     */
    public static Result plantRegistration(byte[] body, PhaseSpec spec, CoseSigner signer,
                                           PlantAttestation attestation) {
        int alg = signer.coseAlg();
        try {
            int[] attSpan = spec.locate(Field.ATTESTATION_OBJECT, body);
            if (attSpan == null) {
                return new Result(body, false, null, alg, "no attestationObject to plant into");
            }
            WrapperCodec wrapper = new WrapperCodec.Default();
            WrapperCodec.Unwrapped att = Encodings.decode(wrapper, slice(body, attSpan), encodingOf(spec, Field.ATTESTATION_OBJECT));
            CborCodec cbor = new Webauthn4jCborCodec();
            AttestationObject ao = cbor.decodeAttestationObject(att.inner());
            if (ao == null || ao.authData() == null) {
                return new Result(body, false, null, alg, "attestationObject did not decode");
            }
            byte[] credId = ao.authData().credentialId();
            String credHex = credId != null ? HexFormat.of().formatHex(credId) : "";
            RegistrationSubstituter substituter = new RegistrationSubstituter(cbor);
            byte[] newInner;
            String detail;
            if (attestation == PlantAttestation.PACKED_SELF) {
                byte[] clientDataJson = clientDataJson(body, spec);
                if (clientDataJson == null) {
                    return new Result(body, false, credHex, alg,
                            "packed self-attestation needs clientDataJSON but none was locatable");
                }
                newInner = substituter.substituteSelfAttestedAndEncode(ao, signer, clientDataJson);
                detail = "planted credential key (packed self-attestation)";
            } else {
                newInner = substituter.substituteAndEncode(ao, signer);
                detail = "planted credential key (fmt=none)";
            }
            byte[] newWire = wrapper.rewrap(newInner, att.spec());
            byte[] out = JsonValueEditor.spliceAll(body, List.of(attSpan), List.of(newWire));
            return new Result(out, true, credHex, alg, detail);
        } catch (RuntimeException e) {
            return new Result(body, false, null, alg, "plant failed: " + e.getMessage());
        }
    }

    /**
     * Locate + unwrap the {@code clientDataJSON} inner wire bytes for {@code body} under {@code spec} (the
     * signed input for a packed self-attestation). {@code null} if it is not locatable / decodable.
     */
    private static byte[] clientDataJson(byte[] body, PhaseSpec spec) {
        try {
            int[] span = spec.locate(Field.CLIENT_DATA_JSON, body);
            if (span == null) {
                return null;
            }
            return Encodings.decode(new WrapperCodec.Default(), slice(body, span),
                    encodingOf(spec, Field.CLIENT_DATA_JSON)).inner();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Hex of the credentialId used to key the stored signer (for the auth re-sign lookup) - the active
     * profile's {@code CREDENTIAL_ID} locator (decoded under its encoding) first, falling back to the first
     * {@code rawId}/{@code id} string member (base64url/base64). {@code null} if none. Mirrors the editor's
     * {@code credIdHexFromAssertion}.
     */
    public static String credIdHex(byte[] body, PhaseSpec spec) {
        if (spec != null) {
            FieldLocator loc = spec.locator(Field.CREDENTIAL_ID);
            if (loc != null) {
                int[] span = loc.locate(body);
                if (span != null) {
                    try {
                        byte[] inner = Encodings.decode(new WrapperCodec.Default(), slice(body, span), loc.encoding()).inner();
                        return HexFormat.of().formatHex(inner);
                    } catch (RuntimeException ignored) {
                        // fall back to the substring scan below
                    }
                }
            }
        }
        int[] span = JsonValueEditor.findStringValueSpan(body, "rawId");
        if (span == null) {
            span = JsonValueEditor.findStringValueSpan(body, "id");
        }
        if (span == null) {
            return null;
        }
        String token = new String(body, span[0], span[1] - span[0], StandardCharsets.US_ASCII);
        for (Base64.Decoder dec : new Base64.Decoder[]{Base64.getUrlDecoder(), Base64.getDecoder()}) {
            try {
                return HexFormat.of().formatHex(dec.decode(token));
            } catch (RuntimeException ignored) {
                // try the next flavour
            }
        }
        return null;
    }

    /**
     * The RP-ID host the key store is keyed on: the host of {@code clientDataJSON.origin}, located + decoded
     * via {@code spec}. Mirrors the editor's {@code rpIdHost()} exactly (same origin string → same
     * {@code URI.getHost()} logic) so a manually-planted key and an AUTO re-sign resolve the SAME
     * {@code KeyId} - even when the WebAuthn origin host differs from the HTTP transport host (split-origin /
     * IdP-sibling). Returns {@code ""} when no origin is locatable (matching the editor's empty default).
     */
    public static String originHost(byte[] body, PhaseSpec spec) {
        String origin = originOf(body, spec);
        if (origin == null) {
            return "";
        }
        try {
            URI u = new URI(origin);
            return u.getHost() != null ? u.getHost() : origin;
        } catch (Exception e) {
            return origin;
        }
    }

    private static String originOf(byte[] body, PhaseSpec spec) {
        byte[] cd = clientDataJson(body, spec); // same locate + unwrap the packed-self signed input uses
        if (cd == null) {
            return null;
        }
        try {
            JsonObject o = JsonParser.parseString(new String(cd, StandardCharsets.UTF_8)).getAsJsonObject();
            return o.has("origin") && o.get("origin").isJsonPrimitive() ? o.get("origin").getAsString() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static byte[] slice(byte[] body, int[] span) {
        return Arrays.copyOfRange(body, span[0], span[1]);
    }

    private static com.anvil.passkeyeditor.profile.EncodingSpec encodingOf(PhaseSpec spec, Field field) {
        FieldLocator loc = spec.locator(field);
        return loc != null ? loc.encoding() : null;
    }
}
