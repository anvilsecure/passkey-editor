package com.anvil.passkeyeditor.profile;

/**
 * A WebAuthn field a profile can locate, paired with the canonical JSON member name most RPs use for it.
 * The name seeds the Default profile's generic {@code [response.<name>, <name>]} candidate paths and is
 * the starting point for auto-learn (walk the body for these names at any depth).
 */
public enum Field {
    CLIENT_DATA_JSON("clientDataJSON", true),
    ATTESTATION_OBJECT("attestationObject", true),
    AUTHENTICATOR_DATA("authenticatorData", true),
    SIGNATURE("signature", true),
    /**
     * Optional by specification. {@code userHandle} is the user id an authenticator returns only for a
     * discoverable credential; for a non-discoverable one it is legitimately absent, and plenty of
     * real captures simply do not carry it. Reporting that as a red "not found" told an operator their
     * locator was wrong when nothing was.
     */
    USER_HANDLE("userHandle", false),
    CREDENTIAL_ID("credentialId", true);

    private final String jsonName;
    private final boolean required;

    Field(String jsonName, boolean required) {
        this.jsonName = jsonName;
        this.required = required;
    }

    /** The canonical JSON member name for this field (as most RPs name it on the wire). */
    public String jsonName() {
        return jsonName;
    }

    /**
     * Whether a ceremony that omits this field is malformed. When {@code false}, an absent value is a
     * property of the ceremony, not a mistake in the profile, and the Check panel says so instead of
     * raising an error the operator cannot act on.
     */
    public boolean required() {
        return required;
    }
}
