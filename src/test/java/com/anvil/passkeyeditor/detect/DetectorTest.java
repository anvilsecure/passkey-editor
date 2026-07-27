package com.anvil.passkeyeditor.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.model.CeremonyType;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Detection is the {@code isEnabledFor()} gate for the "Passkey Editor" tab. These tests exercise it
 * against real wire-form bodies (clientDataJSON base64-wrapped inside a JSON envelope) - the form
 * a browser actually POSTs. The literal {@code webauthn.create} / {@code webauthn.get} markers are NOT
 * present in that form (base64url has no '.'), so a literal-only detector would miss every real ceremony
 * and the tab would never appear. The structural fallback (field names) is what makes it fire.
 */
class DetectorTest {

    private final Detector detector = new Detector(new Config());

    // ---- the regression that matters: real wire-form bodies ------------------------------------

    @Test
    void detectsRegistrationInWireForm() {
        String body = Fixtures.registrationRequestBody();
        // Guard: the literal type marker must be absent (it's base64-wrapped), so this test really is
        // exercising the real-traffic path the old literal-only detector missed.
        assertFalse(body.contains(Config.CREATE_MARKER),
                "wire-form body must carry clientDataJSON base64-encoded, not as a literal marker");
        assertEquals(CeremonyType.CREATE, detector.detect(body));
        assertTrue(detector.isCeremony(body));
    }

    @Test
    void detectsAuthenticationInWireForm() {
        String body = Fixtures.authenticationRequestBody();
        assertFalse(body.contains(Config.GET_MARKER),
                "wire-form body must carry clientDataJSON base64-encoded, not as a literal marker");
        // An assertion has no attestationObject, so it must not be misclassified as CREATE.
        assertFalse(body.contains(Config.ATTESTATION_MARKER), "assertion body must have no attestationObject");
        assertEquals(CeremonyType.GET, detector.detect(body));
        assertTrue(detector.isCeremony(body));
    }

    // ---- back-compat: an un-encoded clientDataJSON with the literal type marker still classifies ----

    @Test
    void detectsLiteralCreateMarker() {
        String decoded = new String(Fixtures.clientDataJson("webauthn.create"), StandardCharsets.UTF_8);
        assertEquals(CeremonyType.CREATE, detector.detect(decoded));
    }

    @Test
    void detectsLiteralGetMarker() {
        String decoded = new String(Fixtures.clientDataJson("webauthn.get"), StandardCharsets.UTF_8);
        assertEquals(CeremonyType.GET, detector.detect(decoded));
    }

    // ---- negatives -----------------------------------------------------------------------------

    @Test
    void ignoresOptionsResponse() {
        // A /generate-registration-options-style response: challenge + rp, but none of the ceremony
        // request fields (no clientDataJSON / attestationObject / signature).
        String optionsJson = "{\"challenge\":\"abc\",\"rp\":{\"name\":\"x\",\"id\":\"localhost\"},"
                + "\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"}]}";
        assertNull(detector.detect(optionsJson));
        assertFalse(detector.isCeremony(optionsJson));
    }

    @Test
    void ignoresEmptyAndNull() {
        assertNull(detector.detect(null));
        assertNull(detector.detect(""));
        assertFalse(detector.isCeremony(null));
        assertFalse(detector.isCeremony(""));
    }

    // ---- options-phase detection (the response editor's gate) ----------------------------------

    @Test
    void detectsAuthenticationOptions() {
        String body = Fixtures.authenticationOptionsResponse();
        assertEquals(Detector.OptionsKind.AUTHENTICATION, detector.detectOptions(body));
        assertTrue(detector.isOptions(body));
    }

    @Test
    void detectsRegistrationOptions() {
        String body = Fixtures.registrationOptionsResponse();
        assertEquals(Detector.OptionsKind.REGISTRATION, detector.detectOptions(body));
        assertTrue(detector.isOptions(body));
    }

    @Test
    void downgradedOptionsStillDetectAsSameKind() {
        // The UV-downgraded body must still be recognised (so the tab/attack survives re-binding).
        assertEquals(Detector.OptionsKind.AUTHENTICATION,
                detector.detectOptions(Fixtures.authenticationOptionsResponse("discouraged")));
        assertEquals(Detector.OptionsKind.REGISTRATION,
                detector.detectOptions(Fixtures.registrationOptionsResponse("discouraged")));
    }

    @Test
    void verifyRequestsAreNotOptions() {
        // The verify request bodies the request editor owns must never be misread as options.
        assertNull(detector.detectOptions(Fixtures.registrationRequestBody()));
        assertNull(detector.detectOptions(Fixtures.authenticationRequestBody()));
        assertFalse(detector.isOptions(Fixtures.registrationRequestBody()));
        assertFalse(detector.isOptions(Fixtures.authenticationRequestBody()));
    }

    @Test
    void optionsDetectionIsGatedOnChallenge() {
        // pubKeyCredParams / allowCredentials present but NO challenge → not an options response.
        assertNull(detector.detectOptions("{\"pubKeyCredParams\":[{\"alg\":-7}]}"));
        assertNull(detector.detectOptions("{\"allowCredentials\":[],\"rpId\":\"localhost\"}"));
    }

    @Test
    void arbitraryJsonWithChallengeIsNotOptions() {
        // A challenge alone (e.g. some unrelated API) must not trip the options gate.
        assertNull(detector.detectOptions("{\"challenge\":\"abc\",\"foo\":\"bar\"}"));
        assertFalse(detector.isOptions("{\"challenge\":\"abc\"}"));
    }

    @Test
    void htmlPageMentioningMarkersIsNotOptions() {
        // Regression: GitHub's /settings/security is an HTML page that MENTIONS challenge / rpId /
        // allowCredentials in its passkey markup (even embeds a WebAuthn options object in a <script>), but it
        // is not itself a WebAuthn options RESPONSE - the tab must stay hidden. The JSON-object body gate is
        // what catches this: the marker key-form alone would match the embedded <script> JSON.
        String html = "<!DOCTYPE html><html><head><title>Account security</title></head><body>"
                + "<script>const opts={\"challenge\":\"x\",\"rpId\":\"github.com\",\"allowCredentials\":[]};</script>"
                + " passkey challenge rpId pubKeyCredParams allowCredentials</body></html>";
        assertNull(detector.detectOptions(html));
        assertFalse(detector.isOptions(html));
    }

    @Test
    void leadingWhitespaceBeforeJsonStillDetects() {
        // The '{'-shape gate skips leading whitespace, so a pretty-/proxy-indented options body still detects.
        assertEquals(Detector.OptionsKind.REGISTRATION,
                detector.detectOptions("\n  \t" + Fixtures.registrationOptionsResponse()));
    }

    @Test
    void markerAsValueNotKeyIsNotOptions() {
        // "challenge" as a VALUE (not a JSON key) must not gate options on - only the "challenge": key counts.
        assertNull(detector.detectOptions("{\"type\":\"challenge\",\"rpId\":\"x\",\"allowCredentials\":[]}"));
    }

    @Test
    void xssiGuardedOptionsStillDetect() {
        // Some stacks prepend an anti-hijacking guard to JSON: )]}' (Google/Angular, sometimes )]}',),
        // for(;;); (Facebook), while(1); . A generate-*-options RESPONSE behind such a stack is still a real
        // WebAuthn options body - the JSON-object shape gate must skip the guard, not reject the response.
        String auth = Fixtures.authenticationOptionsResponse();
        String reg = Fixtures.registrationOptionsResponse();
        assertEquals(Detector.OptionsKind.AUTHENTICATION, detector.detectOptions(")]}'\n" + auth));
        assertEquals(Detector.OptionsKind.AUTHENTICATION, detector.detectOptions(")]}',\n" + auth));
        assertEquals(Detector.OptionsKind.REGISTRATION, detector.detectOptions("for(;;);" + reg));
        assertEquals(Detector.OptionsKind.REGISTRATION, detector.detectOptions("while(1);" + reg));
        assertTrue(detector.isOptions(")]}'\n" + auth));
        // A guard in front of NON-options (an HTML page) must still be rejected - the guard skip is not a bypass.
        assertNull(detector.detectOptions(")]}'\n<!DOCTYPE html><html>challenge rpId allowCredentials</html>"));
    }

    @Test
    void optionsDetectionIgnoresEmptyAndNull() {
        assertNull(detector.detectOptions(null));
        assertNull(detector.detectOptions(""));
        assertFalse(detector.isOptions(null));
    }
}
