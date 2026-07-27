package com.anvil.passkeyeditor.model;

/**
 * The two WebAuthn ceremony kinds this tool handles.
 *
 *   - {@link #CREATE} - registration ({@code navigator.credentials.create}, {@code webauthn.create});
 *       the response carries an {@link AttestationObject}.
 *   - {@link #GET} - authentication / assertion ({@code navigator.credentials.get},
 *       {@code webauthn.get}); the response carries a bare {@link AuthenticatorData} + a signature.
 */
public enum CeremonyType {
    CREATE,
    GET
}
