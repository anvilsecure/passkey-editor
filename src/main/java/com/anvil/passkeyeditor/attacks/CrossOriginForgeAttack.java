package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.nio.charset.StandardCharsets;

/**
 * Framing / clickjacking forge (CWE-1021) - turn a captured same-origin {@code clientDataJSON} into a
 * cross-origin one by setting {@code crossOrigin=true} and a {@code topOrigin} the attacker
 * controls, without touching {@code origin}.
 *
 * The threat. During a genuine ceremony the browser records two framing facts in
 * {@code clientDataJSON}: {@code crossOrigin} (was the ceremony invoked from a cross-origin iframe) and
 * {@code topOrigin} (the origin of the top-level document, present when {@code crossOrigin} is true). An
 * attacker who frames the real relying party inside a hidden iframe on their own page and lures the user
 * into interacting drives a genuine ceremony in which {@code origin} is still the RP's own origin (the
 * framed document is the RP), while {@code crossOrigin} is true and {@code topOrigin} is the
 * attacker's. A relying party that validates {@code origin} but not {@code crossOrigin}/{@code topOrigin}
 * (W3C WebAuthn Level 3 §7.1/§7.2) accepts it - the user has just registered or authenticated a passkey
 * on a site they never meant to. This transform reproduces exactly that ceremony shape for probing.
 *
 * Why {@code origin} is left byte-identical. Every relying party already validates
 * {@code origin} - that is basic WebAuthn. The check RPs miss is specifically the framing pair, so the
 * probe must isolate it: change only {@code crossOrigin} and {@code topOrigin} and leave {@code origin}
 * (and every other byte) exactly as captured. Mutating {@code origin} would exercise a different,
 * already-covered check.
 *
 * Why re-signing is required (and its honest limit). {@code clientDataJSON} is covered by the
 * assertion signature ({@code authenticatorData ‖ SHA-256(clientDataJSON wire bytes)}), so editing it here
 * invalidates the captured signature; the caller re-signs with a key it controls so the RP cannot reject
 * on the signature and the framing check is isolated. Against a live RP holding the genuine user's private
 * key the original signature cannot be regenerated - inherent to WebAuthn, not a limit of this transform -
 * so the meaningful test uses a credential whose key the tester controls.
 *
 * Pure + Burp-free + idempotent: re-running with {@code crossOrigin} already {@code true} and the same
 * {@code topOrigin} is a no-op (returns the original array reference). Never throws on shape; a malformed /
 * non-object body yields an unchanged no-op {@link Result}. Edits are byte-surgical via
 * {@link JsonValueEditor} - never a re-serialization of a parsed view.
 */
public final class CrossOriginForgeAttack {

    /** The WebAuthn {@code clientDataJSON} framing-flag member (a bare boolean). */
    public static final String CROSS_ORIGIN_KEY = "crossOrigin";

    /** The WebAuthn {@code clientDataJSON} top-level-document origin member (a string). */
    public static final String TOP_ORIGIN_KEY = "topOrigin";

    private static final byte[] TRUE = "true".getBytes(StandardCharsets.US_ASCII);

    /**
     * The outcome of a framing forge.
     *
     * @param clientData             the resulting {@code clientDataJSON} bytes (the original array reference
     *                               when unchanged)
     * @param changed                whether any edit was actually applied
     * @param previousCrossOrigin    the {@code crossOrigin} boolean found before the edit, or {@code null}
     *                               if it was absent (or not a bare {@code true}/{@code false})
     * @param previousTopOrigin      the {@code topOrigin} value found before the edit, or {@code null} if it
     *                               was absent
     */
    public record Result(byte[] clientData, boolean changed,
                         Boolean previousCrossOrigin, String previousTopOrigin) {
    }

    /**
     * Forge a cross-origin (framed) {@code clientDataJSON}: set {@code crossOrigin} to {@code true} and
     * {@code topOrigin} to {@code topOrigin}, leaving {@code origin} and every other byte untouched.
     *
     *   - {@code crossOrigin}: replace the bare boolean in place if present; insert {@code "crossOrigin":true}
     *       if absent; a no-op if already {@code true};
     *   - {@code topOrigin} (only when {@code topOrigin != null}): replace the string value if present;
     *       insert {@code "topOrigin":"…"} if absent; a no-op if already equal.
     *
     * Never throws on shape; a {@code null} or malformed / non-object body yields an unchanged no-op.
     *
     * @param clientDataRaw the captured {@code clientDataJSON} wire bytes
     * @param topOrigin     the attacker-controlled top-level-document origin to plant, or {@code null} to
     *                      set only the {@code crossOrigin} flag
     * @return the {@link Result}
     */
    public Result forge(byte[] clientDataRaw, String topOrigin) {
        if (clientDataRaw == null) {
            return new Result(new byte[0], false, null, null);
        }
        byte[] body = clientDataRaw;
        boolean changed = false;

        // --- crossOrigin -> true (leave origin alone) ---
        Boolean previousCrossOrigin = null;
        int[] crossSpan = JsonValueEditor.findPrimitiveValueSpan(body, CROSS_ORIGIN_KEY);
        if (crossSpan != null) {
            String current = new String(body, crossSpan[0], crossSpan[1] - crossSpan[0], StandardCharsets.UTF_8);
            boolean alreadyTrue = "true".equals(current);
            previousCrossOrigin = alreadyTrue ? Boolean.TRUE
                    : "false".equals(current) ? Boolean.FALSE : null;
            if (!alreadyTrue) {
                body = JsonValueEditor.splice(body, crossSpan, TRUE);
                changed = true;
            }
        } else if (JsonValueEditor.findStringValueSpan(body, CROSS_ORIGIN_KEY) == null) {
            // Truly absent (neither a bare literal nor a string value) - insert it. A same-origin ceremony
            // often omits crossOrigin entirely; do not insert if some odd value is already there.
            byte[] inserted = JsonValueEditor.insertMember(body, CROSS_ORIGIN_KEY, TRUE);
            if (inserted != null) {
                body = inserted;
                changed = true;
            }
        }

        // --- topOrigin -> the attacker-controlled top document ---
        String previousTopOrigin = null;
        if (topOrigin != null) {
            int[] topSpan = JsonValueEditor.findStringValueSpan(body, TOP_ORIGIN_KEY);
            if (topSpan != null) {
                previousTopOrigin = new String(body, topSpan[0], topSpan[1] - topSpan[0], StandardCharsets.UTF_8);
                if (!previousTopOrigin.equals(topOrigin)) {
                    body = JsonValueEditor.splice(body, topSpan, topOrigin.getBytes(StandardCharsets.UTF_8));
                    changed = true;
                }
            } else {
                byte[] inserted = JsonValueEditor.insertMember(body, TOP_ORIGIN_KEY, quote(topOrigin));
                if (inserted != null) {
                    body = inserted;
                    changed = true;
                }
            }
        }

        return new Result(body, changed, previousCrossOrigin, previousTopOrigin);
    }

    /** Wrap a string's UTF-8 bytes in JSON double-quotes (origins carry no chars needing escaping). */
    private static byte[] quote(String value) {
        byte[] v = value.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[v.length + 2];
        out[0] = '"';
        System.arraycopy(v, 0, out, 1, v.length);
        out[out.length - 1] = '"';
        return out;
    }
}
