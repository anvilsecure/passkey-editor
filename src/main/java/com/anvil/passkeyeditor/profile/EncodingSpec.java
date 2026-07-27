package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.codec.WrapSpec;
import com.anvil.passkeyeditor.codec.WrapSpec.Flavor;
import com.anvil.passkeyeditor.codec.WrapSpec.Padding;
import com.anvil.passkeyeditor.codec.WrapSpec.WrapFrame;

/**
 * The explicit per-field encoding chain an operator pins for a {@link FieldLocator} - the per-field URL-encoded + Base64/Base64URL toggles:
 *
 *   - {@code urlEncoded} - the field value is percent-encoded (RFC 3986) on the wire (the operator's
 *       tick: percent-encoding is the one layer AUTO does not self-detect, so it is an explicit toggle
 *       that composes with the rest);
 *   - {@code base64} - {@link Base64Kind#AUTO} (self-detect the base64/envelope layers, the default),
 *       {@link Base64Kind#NONE} (raw), {@link Base64Kind#STANDARD} ({@code +/}), or
 *       {@link Base64Kind#URL_SAFE} ({@code -_}), with {@code padding};
 *   - {@code envelopeKey} - the value is a single-member JSON envelope {@code {"<key>":"<inner>"}}
 *       (e.g. Yubico's {@code $base64}); {@code null} when there is none.
 *
 * A {@code null} {@code EncodingSpec} on a {@link FieldLocator} (or one whose {@code base64} is
 * {@link Base64Kind#AUTO}) means defer to {@link com.anvil.passkeyeditor.codec.WrapperCodec#unwrap}'s
 * self-detecting peel for the base64/envelope layers (the lossless default, proven on all eight Step-0
 * fixtures) - with {@code urlEncoded} still applied as an explicit outer percent layer if ticked. A
 * fully-explicit ({@code base64 != AUTO}) spec is the learn-once override, compiled to a {@link WrapSpec}
 * via {@link #toWrapSpec()}. Either way the decode/re-wrap go through {@link Encodings}, so the same
 * byte-exact machinery applies. Layer nesting outermost→inner is {@code url-encode → envelope → base64 → raw}.
 */
public record EncodingSpec(boolean urlEncoded, Base64Kind base64, Padding padding, String envelopeKey) {

    /**
     * Base64 alphabet choice. {@link #AUTO} = self-detect the base64/envelope layers at decode time (the
     * default - {@link #toWrapSpec()} cannot pre-compute it, {@link Encodings#decode} resolves it live);
     * {@link #NONE}/{@link #STANDARD}/{@link #URL_SAFE} are fully-explicit (pinned) choices.
     */
    public enum Base64Kind { AUTO, NONE, STANDARD, URL_SAFE }

    public EncodingSpec {
        if (base64 == null) {
            base64 = Base64Kind.AUTO; // a "blank" spec defers base64/envelope detection to AUTO
        }
        if (padding == null) {
            padding = Padding.UNPADDED; // WebAuthn wire default; only consulted when base64 is STANDARD/URL_SAFE
        }
        if (envelopeKey != null && envelopeKey.isBlank()) {
            envelopeKey = null;
        }
    }

    /** AUTO base64/envelope detection, no URL layer - equivalent to a {@code null} encoding. */
    public static EncodingSpec auto() {
        return new EncodingSpec(false, Base64Kind.AUTO, Padding.UNPADDED, null);
    }

    /** AUTO base64/envelope detection with the URL-encode tick ON (percent layer outermost). */
    public static EncodingSpec autoUrlEncoded() {
        return new EncodingSpec(true, Base64Kind.AUTO, Padding.UNPADDED, null);
    }

    /** Raw / identity (no wrapping). */
    public static EncodingSpec raw() {
        return new EncodingSpec(false, Base64Kind.NONE, Padding.UNPADDED, null);
    }

    /** Unpadded base64url (the WebAuthn wire default - webauthn.io, debugger, Hanko, …). */
    public static EncodingSpec base64Url() {
        return new EncodingSpec(false, Base64Kind.URL_SAFE, Padding.UNPADDED, null);
    }

    /** Padded standard base64 (Yubico, lubu, ctap). */
    public static EncodingSpec base64StandardPadded() {
        return new EncodingSpec(false, Base64Kind.STANDARD, Padding.PADDED, null);
    }

    /** Whether the base64/envelope layer is auto-detected at decode time (vs a pinned, static chain). */
    public boolean isAuto() {
        return base64 == Base64Kind.AUTO;
    }

    /** A copy with the URL-encode tick set (composes with the base64/envelope layers already pinned). */
    public EncodingSpec withUrlEncoded(boolean url) {
        return new EncodingSpec(url, base64, padding, envelopeKey);
    }

    /**
     * Compile a fully-explicit spec to the reversible {@link WrapSpec} (outermost-first), so
     * {@code rewrap} rebuilds the wire and {@code unwrapWith} peels it back. Empty (no frames) iff this spec
     * is raw/identity.
     *
     * @throws IllegalStateException if {@link #isAuto()} - an AUTO spec has no static {@link WrapSpec};
     *     decode it through {@link Encodings#decode} (which resolves the base64/envelope layers live).
     */
    public WrapSpec toWrapSpec() {
        if (isAuto()) {
            throw new IllegalStateException("AUTO encoding has no static WrapSpec; use Encodings.decode");
        }
        WrapSpec spec = new WrapSpec();
        if (urlEncoded) {
            spec.addFrame(WrapFrame.urlEncode());
        }
        if (envelopeKey != null) {
            spec.addFrame(WrapFrame.jsonEnvelope(envelopeKey));
        }
        if (base64 != Base64Kind.NONE) {
            Flavor flavor = base64 == Base64Kind.STANDARD ? Flavor.STANDARD : Flavor.URL_SAFE;
            spec.addFrame(WrapFrame.base64(flavor, padding));
        }
        return spec;
    }

    /**
     * Derive an {@code EncodingSpec} from an AUTO-discovered {@link WrapSpec} (for a "pin what AUTO found"
     * UI action), or {@code null} if the stack is not expressible as a single explicit spec (e.g. a
     * double-base64 layer - keep AUTO for those).
     */
    public static EncodingSpec fromWrapSpec(WrapSpec spec) {
        boolean url = false;
        String envelope = null;
        Base64Kind b64 = Base64Kind.NONE;
        Padding pad = Padding.UNPADDED;
        int base64Layers = 0;
        for (WrapFrame f : spec.frames()) {
            switch (f.codec()) {
                case URL_ENCODE -> url = true;
                case JSON_ENVELOPE -> envelope = f.jsonPath();
                case BASE64 -> {
                    base64Layers++;
                    b64 = f.flavor() == Flavor.STANDARD ? Base64Kind.STANDARD : Base64Kind.URL_SAFE;
                    pad = f.padding();
                }
            }
        }
        if (base64Layers > 1) {
            return null; // double-base64 isn't a single explicit chain - leave it on AUTO
        }
        return new EncodingSpec(url, b64, pad, envelope);
    }

    /** A short human label for the Check panel / summary (e.g. {@code "base64url"}, {@code "url-enc+base64"}). */
    public String label() {
        StringBuilder sb = new StringBuilder();
        if (urlEncoded) {
            sb.append("url-enc+");
        }
        if (envelopeKey != null) {
            sb.append("{").append(envelopeKey).append("}+");
        }
        sb.append(switch (base64) {
            case AUTO -> "auto";
            case NONE -> "raw";
            case STANDARD -> padding == Padding.PADDED ? "base64" : "base64(unpadded)";
            case URL_SAFE -> padding == Padding.PADDED ? "base64url(padded)" : "base64url";
        });
        return sb.toString();
    }
}
