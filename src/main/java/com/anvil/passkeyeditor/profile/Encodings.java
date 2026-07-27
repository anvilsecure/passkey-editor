package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.codec.WrapSpec;
import com.anvil.passkeyeditor.codec.WrapSpec.WrapFrame;
import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.codec.WrapperCodec.Unwrapped;

/**
 * Bridges a profile's {@link EncodingSpec} to the byte-exact {@link WrapperCodec}, composing the operator's
 * URL-encode tick (the one layer AUTO does not self-detect) with either AUTO base64/envelope
 * detection or a fully-pinned chain. Lives in {@code profile} (not {@code codec}) so the codec package
 * stays free of any profile dependency.
 *
 * {@link #decode} returns the inner bytes and the effective {@link WrapSpec} - so the caller
 * rebuilds the exact wire with {@code codec.rewrap(inner, result.spec())}, whether the base64 layer was
 * pinned or discovered live. This is what keeps a re-signed value byte-identical to the captured wrapping.
 */
public final class Encodings {

    private Encodings() {
    }

    /**
     * Decode {@code wire} under {@code enc}:
     *   - {@code enc == null} or {@link EncodingSpec#isAuto()} → self-detect base64/envelope via
     *       {@link WrapperCodec#unwrap}, after percent-decoding first iff the URL tick is on;
     *   - otherwise → peel the pinned chain via {@link WrapperCodec#unwrapWith}.
     *
     * @return the innermost bytes + the effective outermost-first {@link WrapSpec} that reproduces
     *     {@code wire} via {@link WrapperCodec#rewrap}
     * @throws RuntimeException if a pinned layer does not decode (caller renders that as "suspect")
     */
    public static Unwrapped decode(WrapperCodec codec, byte[] wire, EncodingSpec enc) {
        if (enc == null || enc.isAuto()) {
            byte[] current = wire;
            WrapSpec effective = new WrapSpec();
            if (enc != null && enc.urlEncoded()) {
                // Honour the URL tick only if the wire is ACTUALLY percent-encoded under the strict codec -
                // i.e. re-encoding the peeled bytes reproduces the wire. percentDecode is lenient (a token
                // with no '%' decodes to itself), but percentEncode is strict (it escapes base64 specials
                // +,/,=). Recording a URL_ENCODE frame unconditionally would therefore make rewrap re-escape
                // a value that was never url-encoded, corrupting the wire and reporting a false green. Mirror
                // the base64/envelope self-check: only consume the layer + record the frame when it round-trips.
                byte[] peeled = codec.unwrapWith(wire, urlOnly());
                if (java.util.Arrays.equals(codec.rewrap(peeled, urlOnly()), wire)) {
                    current = peeled;
                    effective.addFrame(WrapFrame.urlEncode());
                }
            }
            Unwrapped inner = codec.unwrap(current); // auto base64/envelope on what remains
            for (WrapFrame f : inner.spec().frames()) {
                effective.addFrame(f);
            }
            return new Unwrapped(inner.inner(), effective);
        }
        WrapSpec spec = enc.toWrapSpec();
        return new Unwrapped(codec.unwrapWith(wire, spec), spec);
    }

    /** A single-frame {@link WrapSpec} carrying only a percent-encoding layer. */
    private static WrapSpec urlOnly() {
        WrapSpec s = new WrapSpec();
        s.addFrame(WrapFrame.urlEncode());
        return s;
    }
}
