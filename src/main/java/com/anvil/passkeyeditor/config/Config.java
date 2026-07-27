package com.anvil.passkeyeditor.config;

import java.util.regex.Pattern;

/**
 * Hardcoded default detection configuration for the initial version.
 *
 * The extension ships fixed default detection regexes; a native persisted settings panel
 * ({@code registerSettingsPanel}) is a later follow-up. The patterns are compiled once here and
 * reused by {@link com.anvil.passkeyeditor.detect.Detector} (compile-once + input-cap = ReDoS guard).
 *
 * Markers are intentionally permissive about wrapping/escaping: a ceremony's {@code type} member
 * may appear inside single/double-Base64 or a JSON envelope, so detection keys on the decoded marker
 * tokens, and the matcher input is capped at {@link #maxScanChars()} characters.
 */
public final class Config {

    /** clientDataJSON {@code type} marker for a registration ceremony. */
    public static final String CREATE_MARKER = "webauthn.create";

    /** clientDataJSON {@code type} marker for an authentication ceremony. */
    public static final String GET_MARKER = "webauthn.get";

    /** Default cap on the number of characters (String length, i.e. UTF-16 code units - not bytes) the
     *  detector scans before matching (ReDoS guard). */
    public static final int DEFAULT_MAX_SCAN_CHARS = 1 << 20; // 1,048,576 characters

    /** Default pattern recognising a registration ceremony. */
    public static final Pattern DEFAULT_CREATE_PATTERN =
            Pattern.compile(Pattern.quote(CREATE_MARKER));

    /** Default pattern recognising an authentication ceremony. */
    public static final Pattern DEFAULT_GET_PATTERN =
            Pattern.compile(Pattern.quote(GET_MARKER));

    // --- Structural markers -----------------------------------------------------------------------
    // On the real wire the clientDataJSON 'type' is base64-wrapped, so CREATE_MARKER / GET_MARKER do
    // NOT appear literally in a ceremony request body. These always-literal JSON field names are the
    // structural fallback the Detector keys on: attestationObject -> CREATE, signature -> GET, both
    // gated on clientDataJSON being present so a stray field name elsewhere can't false-trigger.

    /** JSON field name always present (un-encoded) in a ceremony request body. */
    public static final String CLIENT_DATA_MARKER = "clientDataJSON";

    /** JSON field name unique to a registration (CREATE) response. */
    public static final String ATTESTATION_MARKER = "attestationObject";

    /** JSON field name unique to an authentication (GET) response. */
    public static final String SIGNATURE_MARKER = "signature";

    /** Default pattern for the clientDataJSON field-name gate. */
    public static final Pattern DEFAULT_CLIENT_DATA_PATTERN =
            Pattern.compile(Pattern.quote(CLIENT_DATA_MARKER));

    /** Default pattern for the registration (CREATE) structural marker. */
    public static final Pattern DEFAULT_ATTESTATION_PATTERN =
            Pattern.compile(Pattern.quote(ATTESTATION_MARKER));

    /** Default pattern for the authentication (GET) structural marker. */
    public static final Pattern DEFAULT_SIGNATURE_PATTERN =
            Pattern.compile(Pattern.quote(SIGNATURE_MARKER));

    // --- Options-phase markers --------------------------------------------------------------------
    // A WebAuthn ceremony has an earlier phase the verify-request markers above miss: the RP's
    // generate-*-options RESPONSE (server -> client), where the requested policy lives. The UV-downgrade
    // attack edits userVerification there, so the response editor must recognise it. Discriminators:
    //   challenge        - present in both options kinds (gates against arbitrary JSON);
    //   pubKeyCredParams - registration options only (the supported algorithms);
    //   allowCredentials / rpId - authentication options (no pubKeyCredParams, no rp{} object).

    /** JSON field name present in both options kinds; the gate against arbitrary JSON. */
    public static final String CHALLENGE_MARKER = "challenge";

    /** JSON field name unique to registration options (the supported-algorithm list). */
    public static final String PUBKEY_CRED_PARAMS_MARKER = "pubKeyCredParams";

    /** JSON field name characteristic of authentication options. */
    public static final String ALLOW_CREDENTIALS_MARKER = "allowCredentials";

    /** JSON field name (camelCase) characteristic of authentication options. */
    public static final String RP_ID_MARKER = "rpId";

    // The options markers below are matched only in JSON-KEY form - a quoted name then optional whitespace and
    // a colon ("challenge":) - NOT as a bare substring. An HTML/JS page (e.g. GitHub's /settings/security)
    // mentions words like "challenge" / "rpId" in its passkey markup; keying on the quoted-key form (together
    // with the Detector's JSON-object gate) stops such a page from surfacing the options tab.

    /** Compile a pattern matching {@code marker} only as a JSON key: {@code "marker"} + optional space + ':'. */
    private static Pattern jsonKey(String marker) {
        return Pattern.compile("\"" + Pattern.quote(marker) + "\"\\s*:");
    }

    /** Default pattern for the options gate (a {@code "challenge":} member). */
    public static final Pattern DEFAULT_CHALLENGE_PATTERN = jsonKey(CHALLENGE_MARKER);

    /** Default pattern recognising registration options (a {@code "pubKeyCredParams":} member). */
    public static final Pattern DEFAULT_PUBKEY_CRED_PARAMS_PATTERN = jsonKey(PUBKEY_CRED_PARAMS_MARKER);

    /** Default pattern recognising authentication options (an {@code "allowCredentials":} member). */
    public static final Pattern DEFAULT_ALLOW_CREDENTIALS_PATTERN = jsonKey(ALLOW_CREDENTIALS_MARKER);

    /** Default pattern recognising authentication options (an {@code "rpId":} member). */
    public static final Pattern DEFAULT_RP_ID_PATTERN = jsonKey(RP_ID_MARKER);

    private final Pattern createPattern;
    private final Pattern getPattern;
    private final int maxScanChars;

    /** Build a Config with the hardcoded defaults. */
    public Config() {
        this(DEFAULT_CREATE_PATTERN, DEFAULT_GET_PATTERN, DEFAULT_MAX_SCAN_CHARS);
    }

    public Config(Pattern createPattern, Pattern getPattern, int maxScanChars) {
        this.createPattern = createPattern;
        this.getPattern = getPattern;
        this.maxScanChars = maxScanChars;
    }

    /** Compiled pattern detecting a CREATE (registration) ceremony. */
    public Pattern createPattern() {
        return createPattern;
    }

    /** Compiled pattern detecting a GET (authentication) ceremony. */
    public Pattern getPattern() {
        return getPattern;
    }

    /** Structural gate: the clientDataJSON field name (always literal in a ceremony body). */
    public Pattern clientDataPattern() {
        return DEFAULT_CLIENT_DATA_PATTERN;
    }

    /** Structural marker: attestationObject -> registration (CREATE). */
    public Pattern attestationPattern() {
        return DEFAULT_ATTESTATION_PATTERN;
    }

    /** Structural marker: signature -> authentication (GET). */
    public Pattern signaturePattern() {
        return DEFAULT_SIGNATURE_PATTERN;
    }

    /** Options gate: the challenge member (present in both options kinds). */
    public Pattern challengePattern() {
        return DEFAULT_CHALLENGE_PATTERN;
    }

    /** Options marker: pubKeyCredParams -> registration options. */
    public Pattern pubKeyCredParamsPattern() {
        return DEFAULT_PUBKEY_CRED_PARAMS_PATTERN;
    }

    /** Options marker: allowCredentials -> authentication options. */
    public Pattern allowCredentialsPattern() {
        return DEFAULT_ALLOW_CREDENTIALS_PATTERN;
    }

    /** Options marker: rpId -> authentication options. */
    public Pattern rpIdPattern() {
        return DEFAULT_RP_ID_PATTERN;
    }

    /** Maximum number of characters the detector scans before matching. */
    public int maxScanChars() {
        return maxScanChars;
    }
}
