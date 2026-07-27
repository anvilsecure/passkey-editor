package com.anvil.passkeyeditor.codec;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The reversible wrapper stack discovered while unwrapping one ceremony field down to its raw CBOR
 * (or raw JSON for clientDataJSON).
 *
 * A field on the wire may be e.g. {@code double-base64( base64( CBOR ) )} or a JSON envelope
 * around a base64url blob. {@link WrapperCodec#unwrap} peels these layers, recording one
 * {@link WrapFrame} per layer in outermost-first order; {@link WrapperCodec#rewrap} replays
 * the same frames in reverse to reconstruct byte-identical wire bytes from edited inner bytes.
 *
 * The per-frame {@link WrapFrame#flavor()} / {@link WrapFrame#padding()} capture the exact
 * Base64 variant so a re-wrap is lossless across mixed-flavor stacks (outer standard+padded, inner
 * base64url-unpadded - the gate fixture).
 */
public final class WrapSpec {

    /** A single wrapping layer. */
    public enum Codec {
        BASE64,
        /** A JSON envelope; {@link WrapFrame#jsonPath()} names the member holding the inner blob. */
        JSON_ENVELOPE,
        /**
         * Percent-encoding (RFC 3986). Applied only as an explicit per-field encoding layer (an
         * {@code EncodingSpec} the operator pins); {@link WrapperCodec#unwrap} does not auto-detect it, so
         * the proven base64/envelope auto-detection is unchanged.
         */
        URL_ENCODE
    }

    /** Base64 alphabet variant. */
    public enum Flavor {
        STANDARD,  // RFC 4648 §4 (+ /)
        URL_SAFE   // RFC 4648 §5 (- _)
    }

    /** Base64 padding presence on the wire. */
    public enum Padding {
        PADDED,
        UNPADDED
    }

    /**
     * One wrapping layer. {@code flavor}/{@code padding} apply to {@link Codec#BASE64}; {@code jsonPath}
     * applies to {@link Codec#JSON_ENVELOPE} (null otherwise).
     */
    public record WrapFrame(Codec codec, Flavor flavor, Padding padding, String jsonPath) {

        public static WrapFrame base64(Flavor flavor, Padding padding) {
            return new WrapFrame(Codec.BASE64, flavor, padding, null);
        }

        public static WrapFrame jsonEnvelope(String jsonPath) {
            return new WrapFrame(Codec.JSON_ENVELOPE, null, null, jsonPath);
        }

        /** A percent-encoding (RFC 3986) layer - carries no flavor/padding/path. */
        public static WrapFrame urlEncode() {
            return new WrapFrame(Codec.URL_ENCODE, null, null, null);
        }
    }

    /** Outermost-first list of layers; empty == the field was already raw on the wire. */
    private final List<WrapFrame> frames;

    public WrapSpec() {
        this.frames = new ArrayList<>();
    }

    public WrapSpec(List<WrapFrame> frames) {
        this.frames = new ArrayList<>(frames);
    }

    /** Outermost-first; empty means no wrapping. */
    public List<WrapFrame> frames() {
        return Collections.unmodifiableList(frames);
    }

    public void addFrame(WrapFrame frame) {
        frames.add(frame);
    }

    public boolean isEmpty() {
        return frames.isEmpty();
    }
}
