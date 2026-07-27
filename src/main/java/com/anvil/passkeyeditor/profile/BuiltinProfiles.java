package com.anvil.passkeyeditor.profile;

import java.util.EnumMap;
import java.util.Map;

/**
 * Built-in seed data: the catch-all Default profile, and nothing else.
 *
 * A fresh Burp project starts with the Default alone. Per-RP recipes are the operator's to create in the
 * profile editor, because a preset for a relying party nobody is testing is clutter, and shipping a handful
 * of them implies a supported-target list this tool does not have. The five RP recipes that used to seed
 * here still exist as test data ({@code RpFixtureProfiles} in {@code src/test}), where they earn their keep
 * proving the locator and encoding engine against genuinely divergent captured body shapes.
 */
public final class BuiltinProfiles {

    private BuiltinProfiles() {
    }

    /**
     * The catch-all Default. Reproduces the baseline extraction (a field is at {@code response.<name>} for the
     * SimpleWebAuthn nested shape, else flat {@code <name>}). Host = ANY, so it applies only when no
     * user-defined profile matches, and an unprofiled ceremony still decodes byte-identically (freeze-safety).
     */
    public static TargetProfile defaultProfile() {
        Map<Phase, PhaseSpec> phases = new EnumMap<>(Phase.class);
        phases.put(Phase.REG_VERIFY, new PhaseSpec(defaultFields(
                Field.CLIENT_DATA_JSON, Field.ATTESTATION_OBJECT, Field.AUTHENTICATOR_DATA)));
        phases.put(Phase.AUTH_VERIFY, new PhaseSpec(defaultFields(
                Field.CLIENT_DATA_JSON, Field.AUTHENTICATOR_DATA, Field.SIGNATURE, Field.USER_HANDLE)));
        return new TargetProfile("default", "Default (SimpleWebAuthn / generic)", HostMatch.any(), phases);
    }

    /** Generic candidate paths {@code [response.<name>, <name>]} for each field. */
    private static Map<Field, FieldLocator> defaultFields(Field... fields) {
        Map<Field, FieldLocator> m = new EnumMap<>(Field.class);
        for (Field f : fields) {
            m.put(f, FieldLocator.of("response." + f.jsonName(), f.jsonName()));
        }
        return m;
    }
}
