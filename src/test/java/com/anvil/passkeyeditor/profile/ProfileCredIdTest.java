package com.anvil.passkeyeditor.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.anvil.passkeyeditor.codec.WrapperCodec;
import com.anvil.passkeyeditor.util.JsonValueEditor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * Gate for the credId migration: the active profile's {@code CREDENTIAL_ID} locator now keys
 * the stored-signer lookup, replacing the whole-body substring scan. This proves the migration is
 * behaviour-preserving on the named RPs (profile-resolved credId == the scan it replaces) and that
 * the Default keeps NO {@code CREDENTIAL_ID} locator - so the unprofiled path stays byte-identical on
 * the proven scan (freeze-safety by construction).
 */
class ProfileCredIdTest {

    private static final WrapperCodec CODEC = new WrapperCodec.Default();
    private final ProfileRegistry registry = RpFixtureProfiles.seededRegistry();

    private static byte[] load(String fixture) throws IOException {
        try (InputStream in = ProfileCredIdTest.class.getResourceAsStream("/fixtures/" + fixture + ".json")) {
            assertNotNull(in, fixture);
            return in.readAllBytes();
        }
    }

    /** The migrated resolution: the active profile's CREDENTIAL_ID locator, decoded via its encoding. */
    private String profileCredId(String host, byte[] body) {
        PhaseSpec spec = registry.resolve(host, Phase.AUTH_VERIFY);
        FieldLocator loc = spec.locator(Field.CREDENTIAL_ID);
        if (loc == null) {
            return null;
        }
        int[] span = loc.locate(body);
        if (span == null) {
            return null;
        }
        byte[] inner = Encodings.decode(CODEC, Arrays.copyOfRange(body, span[0], span[1]), loc.encoding()).inner();
        return HexFormat.of().formatHex(inner);
    }

    /** The legacy resolution being replaced: first rawId/id substring, base64url or base64 → hex. */
    private static String scanCredId(byte[] body) {
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
                // next flavor
            }
        }
        return null;
    }

    @Test
    void migratedCredIdEqualsScanOnNamedRps() throws Exception {
        String[][] cases = {
                {"webauthn-io-auth", "webauthn.io"},
                {"passkeys-debugger-auth", "www.passkeys-debugger.io"},
                {"passkeys-io-auth", "passkeys.hanko.io"},
        };
        for (String[] c : cases) {
            byte[] body = load(c[0]);
            String viaProfile = profileCredId(c[1], body);
            String viaScan = scanCredId(body);
            assertNotNull(viaProfile, c[0] + ": profile resolves credId");
            assertEquals(viaScan, viaProfile, c[0] + ": migrated credId == the scan it replaces (no regression)");
        }
    }

    @Test
    void migratedCredIdResolvesForYubicoAndLubu() throws Exception {
        // Yubico (credentialId.$base64, standard base64) + lubu (flat id) resolve via the profile; these are
        // exactly the shapes the rawId/id scan handled poorly, so we only assert the profile path is sound.
        assertNotNull(profileCredId("demo.yubico.com", load("yubico-demo-auth")), "yubico credId via $base64 path");
        assertNotNull(profileCredId("webauthn.lubu.ch", load("webauthn-lubu-auth")), "lubu credId via flat id");
    }

    @Test
    void defaultProfileHasNoCredIdLocatorSoUnprofiledStaysOnScan() {
        // Freeze-safety: the Default declares no CREDENTIAL_ID, so the editor falls back to the proven
        // substring scan for any unprofiled host - byte-identical to today's behaviour.
        PhaseSpec def = registry.defaultProfile().phase(Phase.AUTH_VERIFY);
        assertNull(def.locator(Field.CREDENTIAL_ID), "Default has no CREDENTIAL_ID locator (scan fallback)");
    }
}
