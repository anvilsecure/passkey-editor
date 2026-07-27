package com.anvil.passkeyeditor.detect;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.model.CeremonyType;

import java.util.regex.Matcher;

/**
 * Regex/config-driven detection of a WebAuthn ceremony in an HTTP message body.
 *
 * Detection is the {@code isEnabledFor()} gate: it decides whether the "Passkey Editor" tab
 * appears for a given request. Per the Montoya rules it must be cheap, side-effect-free, compiled
 * once, and input-length-capped (ReDoS guard). The patterns are configurable
 * via {@link com.anvil.passkeyeditor.config.Config}, not hardcoded per vendor; the default set keys on
 * the {@code "webauthn.create"} / {@code "webauthn.get"} clientDataJSON {@code type} markers, with a
 * structural fallback on the always-literal JSON field names ({@code attestationObject} /
 * {@code signature}) for the real wire form, where the {@code type} marker is base64-wrapped.
 *
 * This type is Burp-free; the editor passes {@code request.bodyToString()} (or the full message)
 * as the {@code body} argument.
 */
public final class Detector {

    /** Which WebAuthn options response was recognised (the phase before the verify request). */
    public enum OptionsKind {
        /** {@code generate-registration-options} response (carries {@code pubKeyCredParams}). */
        REGISTRATION,
        /** {@code generate-authentication-options} response (carries {@code allowCredentials}/{@code rpId}). */
        AUTHENTICATION
    }

    private final Config config;

    public Detector(Config config) {
        this.config = config;
    }

    /**
     * The scan cap the detector truncates input to. Exposed so a hot-path caller (the always-on Proxy
     * colour handler) can cheaply skip stringifying a body larger than this: a ceremony/options message is a
     * small JSON document, so an over-cap body cannot be one, and materialising it as a String would only
     * add allocation churn on the proxy thread.
     */
    public int maxScanChars() {
        return config.maxScanChars();
    }

    /**
     * Whether {@code body} contains a detectable WebAuthn ceremony of either kind.
     *
     * @param body the candidate message body (capped to {@link Config#maxScanChars()} before matching)
     * @return true if a CREATE or GET ceremony is recognised
     */
    public boolean isCeremony(String body) {
        return detect(body) != null;
    }

    /**
     * Classify the ceremony in {@code body}.
     *
     * @param body the candidate message body (length-capped before matching)
     * @return the detected {@link CeremonyType}, or {@code null} if none is recognised
     */
    public CeremonyType detect(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        // ReDoS / DoS guard: cap the input the matcher ever sees. The default patterns are quoted
        // literals (linear), and the cap bounds worst-case work for any configured pattern.
        int cap = config.maxScanChars();
        CharSequence scan = body.length() > cap ? body.subSequence(0, cap) : body;

        // (1) Decoded clientDataJSON type markers. Present only when the body carries an UN-encoded
        // clientDataJSON; CREATE takes precedence.
        if (matches(config.createPattern(), scan)) {
            return CeremonyType.CREATE;
        }
        if (matches(config.getPattern(), scan)) {
            return CeremonyType.GET;
        }

        // (2) Structural fallback for the REAL wire form: a browser POSTs clientDataJSON base64-wrapped,
        // so the type markers above never appear literally. Key on the always-literal JSON field names -
        // attestationObject -> registration, signature -> assertion - gated on clientDataJSON so a stray
        // field elsewhere can't false-trigger. CREATE first: a registration body also carries
        // authenticatorData, but only it has attestationObject.
        if (matches(config.clientDataPattern(), scan)) {
            if (matches(config.attestationPattern(), scan)) {
                return CeremonyType.CREATE;
            }
            if (matches(config.signaturePattern(), scan)) {
                return CeremonyType.GET;
            }
        }
        return null;
    }

    /**
     * Whether {@code body} is a WebAuthn {@code generate-*-options} response of either kind. The cheap,
     * side-effect-free gate for the response editor's {@code isEnabledFor()} - same ReDoS discipline as
     * {@link #detect}.
     *
     * @param body the candidate response body
     * @return true if registration or authentication options are recognised
     */
    public boolean isOptions(String body) {
        return detectOptions(body) != null;
    }

    /**
     * Classify a WebAuthn options response.
     *
     * Gated on a {@code challenge} member (so arbitrary JSON that merely mentions one of the
     * structural keys can't false-trigger) and on the absence of {@code clientDataJSON} (which would make
     * it a verify request - handled by {@link #detect}, not the options editor).
     * {@code pubKeyCredParams} is unique to registration options; otherwise {@code allowCredentials} /
     * {@code rpId} mark authentication options.
     *
     * @param body the candidate response body (length-capped before matching)
     * @return the {@link OptionsKind}, or {@code null} if this is not a recognisable options response
     */
    public OptionsKind detectOptions(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        int cap = config.maxScanChars();
        CharSequence scan = body.length() > cap ? body.subSequence(0, cap) : body;

        // A generate-*-options RESPONSE is a JSON object. If the body is not one - e.g. an HTML page such as
        // GitHub's /settings/security that merely MENTIONS "challenge" / "rpId" in its passkey markup - it is
        // not an options response. detectOptions gates isEnabledFor, so a stray mention must never surface the
        // tab. Cheap shape check (first non-space char is '{'); no full parse, so the gate stays fast + ReDoS-free.
        if (!looksLikeJsonObject(scan)) {
            return null;
        }

        // Must carry a challenge, and must not be a verify request (which the request editor owns).
        if (!matches(config.challengePattern(), scan)) {
            return null;
        }
        if (matches(config.clientDataPattern(), scan)) {
            return null;
        }
        // pubKeyCredParams is registration-only (the supported-algorithm list). Check it first.
        if (matches(config.pubKeyCredParamsPattern(), scan)) {
            return OptionsKind.REGISTRATION;
        }
        if (matches(config.allowCredentialsPattern(), scan) || matches(config.rpIdPattern(), scan)) {
            return OptionsKind.AUTHENTICATION;
        }
        return null;
    }

    private static boolean matches(java.util.regex.Pattern pattern, CharSequence input) {
        if (pattern == null) {
            return false;
        }
        Matcher m = pattern.matcher(input);
        return m.find();
    }

    /** XSSI / JSONP anti-hijacking guards some JSON stacks prepend to a response body. Skipped before the
     *  '{' test so a WebAuthn options RESPONSE served through such a stack still detects (a false-negative
     *  the plain gate would otherwise cause). Bounded literal set - no regex, so the hot path stays ReDoS-free. */
    private static final String[] XSSI_GUARDS = {")]}'", "for(;;);", "while(1);"};

    /**
     * Cheap shape gate: the first significant character (after an optional BOM, leading whitespace, and any
     * known XSSI/JSONP guard prefix) is {@code '{'} - i.e. the body is a JSON object, not an HTML/text
     * document that merely contains the marker words. O(leading noise), no allocation, no parse - safe for
     * the {@code isEnabledFor} hot path.
     */
    private static boolean looksLikeJsonObject(CharSequence s) {
        int n = s.length();
        int i = n > 0 && s.charAt(0) == '\uFEFF' ? 1 : 0; // skip a leading BOM if present
        while (i < n) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
                continue;
            }
            int afterGuard = skipXssiGuard(s, i);
            if (afterGuard > i) {
                i = afterGuard; // an XSSI/JSONP guard - skip it and re-test what follows
                continue;
            }
            return c == '{';
        }
        return false; // empty / all-whitespace / a guard with no object after it
    }

    /** If a known XSSI/JSONP guard begins at {@code off}, return the index just past it (and a trailing
     *  comma, as Angular emits {@code )]}',}); otherwise return {@code off} unchanged. */
    private static int skipXssiGuard(CharSequence s, int off) {
        for (String guard : XSSI_GUARDS) {
            if (regionMatches(s, off, guard)) {
                int j = off + guard.length();
                if (j < s.length() && s.charAt(j) == ',') {
                    j++;
                }
                return j;
            }
        }
        return off;
    }

    /** True if the literal {@code lit} occurs at offset {@code off} in {@code s}. */
    private static boolean regionMatches(CharSequence s, int off, String lit) {
        int len = lit.length();
        if (off + len > s.length()) {
            return false;
        }
        for (int k = 0; k < len; k++) {
            if (s.charAt(off + k) != lit.charAt(k)) {
                return false;
            }
        }
        return true;
    }
}
