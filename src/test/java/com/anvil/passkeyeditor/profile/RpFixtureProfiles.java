package com.anvil.passkeyeditor.profile;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The five mainstream RP recipes captured in {@code src/test/resources/fixtures},
 * kept as test data only.
 *
 * These used to ship as seeded built-ins. They no longer do: a fresh project starts with the Default
 * alone, because a preset for an RP the operator is not testing is clutter, and the profile editor is the
 * supported way to describe a target. They remain here because they are still the best available proof that
 * the locator + encoding engine handles genuinely divergent real-world body shapes, each paired with a
 * captured fixture:
 *
 *   - {@code webauthn.io} - credential double-nested under {@code {username, response}}
 *   - {@code passkeys-debugger.io} - Next.js server action, array root {@code [id, "…", {…}]}
 *   - {@code passkeys.io} (Hanko) - wrapper key differs per ceremony phase
 *   - {@code demo.yubico.com} - per-field {@code {"$base64":"…"}} object wrapper
 *   - {@code webauthn.lubu.ch} - flat top-level fields, standard base64
 *
 * Nothing in {@code src/main} may reference this class.
 */
public final class RpFixtureProfiles {

    private RpFixtureProfiles() {
    }

    /** All five RP recipes, in the order they were seeded historically. */
    public static List<TargetProfile> all() {
        return List.of(webauthnIo(), passkeysDebugger(), hanko(), yubico(), lubu());
    }

    /**
     * A registry holding the shipped Default plus all five RP recipes. This used to be
     * {@code ProfileRegistry.seeded()} in {@code src/main}, but production no longer seeds RP profiles, so
     * keeping it there would have shipped a factory that only tests call.
     */
    public static ProfileRegistry seededRegistry() {
        return new ProfileRegistry(BuiltinProfiles.defaultProfile(), all());
    }

    // ---- webauthn.io (Duo py_webauthn): credential double-nested under {username, response} ----------
    public static TargetProfile webauthnIo() {
        Map<Phase, PhaseSpec> p = new EnumMap<>(Phase.class);
        p.put(Phase.REG_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "response.response.clientDataJSON",
                Field.ATTESTATION_OBJECT, "response.response.attestationObject",
                Field.AUTHENTICATOR_DATA, "response.response.authenticatorData"));
        p.put(Phase.AUTH_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "response.response.clientDataJSON",
                Field.AUTHENTICATOR_DATA, "response.response.authenticatorData",
                Field.SIGNATURE, "response.response.signature",
                Field.USER_HANDLE, "response.response.userHandle",
                Field.CREDENTIAL_ID, "response.rawId"));
        // EdDSA default: webauthn.io (Duo py_webauthn) offers Ed25519 (−8), so the chooser/AUTO plant the
        // algorithm the RP actually accepts here. A plain ES256 re-sign of a captured Ed25519 passkey would
        // never verify (the root cause of the "debugger/webauthn.io AUTH" expectation gap).
        return new TargetProfile("webauthn.io", "webauthn.io (Duo py_webauthn)", HostMatch.exact("webauthn.io"), p)
                .withSigner(SignerSpec.EDDSA);
    }

    // ---- passkeys-debugger.io: Next.js server action, array root [id, "credential_response", {...}] --
    public static TargetProfile passkeysDebugger() {
        Map<Phase, PhaseSpec> p = new EnumMap<>(Phase.class);
        p.put(Phase.REG_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "[2].response.response.clientDataJSON",
                Field.ATTESTATION_OBJECT, "[2].response.response.attestationObject",
                Field.AUTHENTICATOR_DATA, "[2].response.response.authenticatorData"));
        p.put(Phase.AUTH_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "[2].response.response.clientDataJSON",
                Field.AUTHENTICATOR_DATA, "[2].response.response.authenticatorData",
                Field.SIGNATURE, "[2].response.response.signature",
                Field.USER_HANDLE, "[2].response.response.userHandle",
                Field.CREDENTIAL_ID, "[2].response.rawId"));
        return new TargetProfile("passkeys-debugger", "passkeys-debugger.io (Next.js action)",
                HostMatch.exact("www.passkeys-debugger.io"), p)
                .withSigner(SignerSpec.EDDSA); // Ed25519 default (see webauthn.io note)
    }

    // ---- passkeys.io / Hanko: input_data.<wrapper>.response, wrapper name differs per phase ----------
    public static TargetProfile hanko() {
        Map<Phase, PhaseSpec> p = new EnumMap<>(Phase.class);
        p.put(Phase.REG_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "input_data.public_key.response.clientDataJSON",
                Field.ATTESTATION_OBJECT, "input_data.public_key.response.attestationObject"));
        p.put(Phase.AUTH_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "input_data.assertion_response.response.clientDataJSON",
                Field.AUTHENTICATOR_DATA, "input_data.assertion_response.response.authenticatorData",
                Field.SIGNATURE, "input_data.assertion_response.response.signature",
                Field.USER_HANDLE, "input_data.assertion_response.response.userHandle",
                Field.CREDENTIAL_ID, "input_data.assertion_response.rawId"));
        return new TargetProfile("hanko", "passkeys.io (Hanko)", HostMatch.suffix(".hanko.io"), p);
    }

    // ---- demo.yubico.com: per-field {"$base64":"…"} object wrapper, standard base64 -----------------
    public static TargetProfile yubico() {
        Map<Phase, PhaseSpec> p = new EnumMap<>(Phase.class);
        p.put(Phase.REG_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "attestation.clientDataJSON.$base64",
                Field.ATTESTATION_OBJECT, "attestation.attestationObject.$base64"));
        p.put(Phase.AUTH_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "assertion.clientDataJSON.$base64",
                Field.AUTHENTICATOR_DATA, "assertion.authenticatorData.$base64",
                Field.SIGNATURE, "assertion.signature.$base64",
                Field.CREDENTIAL_ID, "assertion.credentialId.$base64"));
        return new TargetProfile("yubico", "demo.yubico.com", HostMatch.exact("demo.yubico.com"), p);
    }

    // ---- webauthn.lubu.ch: flat top-level fields, standard base64 -----------------------------------
    public static TargetProfile lubu() {
        Map<Phase, PhaseSpec> p = new EnumMap<>(Phase.class);
        p.put(Phase.REG_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "clientDataJSON",
                Field.ATTESTATION_OBJECT, "attestationObject"));
        p.put(Phase.AUTH_VERIFY, phase(
                Field.CLIENT_DATA_JSON, "clientDataJSON",
                Field.AUTHENTICATOR_DATA, "authenticatorData",
                Field.SIGNATURE, "signature",
                Field.CREDENTIAL_ID, "id"));
        return new TargetProfile("lubu", "webauthn.lubu.ch", HostMatch.exact("webauthn.lubu.ch"), p)
                .withSigner(SignerSpec.EDDSA); // Ed25519 default (see webauthn.io note)
    }

    /** Build a single-candidate-path {@link PhaseSpec} from interleaved {@code (Field, path)} pairs. */
    private static PhaseSpec phase(Object... fieldThenPath) {
        if (fieldThenPath.length % 2 != 0) {
            throw new IllegalArgumentException("expected (Field, path) pairs");
        }
        Map<Field, FieldLocator> m = new LinkedHashMap<>();
        for (int i = 0; i < fieldThenPath.length; i += 2) {
            m.put((Field) fieldThenPath[i], FieldLocator.of((String) fieldThenPath[i + 1]));
        }
        return new PhaseSpec(m);
    }
}
