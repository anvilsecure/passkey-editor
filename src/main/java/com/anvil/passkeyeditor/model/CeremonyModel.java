package com.anvil.passkeyeditor.model;

import com.anvil.passkeyeditor.codec.WrapSpec;

/**
 * The decoded, editable in-memory representation of one WebAuthn ceremony - the hub the editor and
 * the attacks operate on. Pure data; Burp-free (no Montoya types), so the whole core is
 * JUnit-testable. The editor owns the {@code HttpRequestResponse} and the field locators; this model
 * owns the decoded structures + the per-field wrapper stacks needed to re-encode them.
 *
 *   - {@link CeremonyType#CREATE}: {@link #attestationObject()} is populated (its authData carries
 *       the attested credential data + COSE key).
 *   - {@link CeremonyType#GET}: {@link #authenticatorData()} (bare, 37 bytes) and
 *       {@link #signature()} are populated.
 *
 * Each {@code *Wrap} {@link WrapSpec} records the wrapper layers ({@code WrapperCodec}) that were
 * peeled off the corresponding field so it can be re-wrapped byte-identically on write-back.
 */
public final class CeremonyModel {

    private CeremonyType type;

    // Per-field wrapper stacks (outermost-first), captured at decode time for lossless re-wrap.
    private WrapSpec clientDataWrap;
    private WrapSpec attestationObjectWrap; // CREATE
    private WrapSpec authenticatorDataWrap; // GET
    private WrapSpec signatureWrap;         // GET

    private ClientData clientData;                 // both ceremonies
    private AttestationObject attestationObject;   // CREATE
    private AuthenticatorData authenticatorData;   // GET
    private byte[] signature;                       // GET (raw, DER ECDSA-Sig-Value for ES256)

    public CeremonyModel() {
    }

    public CeremonyModel(CeremonyType type) {
        this.type = type;
    }

    public CeremonyType type() {
        return type;
    }

    public void setType(CeremonyType type) {
        this.type = type;
    }

    public WrapSpec clientDataWrap() {
        return clientDataWrap;
    }

    public void setClientDataWrap(WrapSpec clientDataWrap) {
        this.clientDataWrap = clientDataWrap;
    }

    public WrapSpec attestationObjectWrap() {
        return attestationObjectWrap;
    }

    public void setAttestationObjectWrap(WrapSpec attestationObjectWrap) {
        this.attestationObjectWrap = attestationObjectWrap;
    }

    public WrapSpec authenticatorDataWrap() {
        return authenticatorDataWrap;
    }

    public void setAuthenticatorDataWrap(WrapSpec authenticatorDataWrap) {
        this.authenticatorDataWrap = authenticatorDataWrap;
    }

    public WrapSpec signatureWrap() {
        return signatureWrap;
    }

    public void setSignatureWrap(WrapSpec signatureWrap) {
        this.signatureWrap = signatureWrap;
    }

    public ClientData clientData() {
        return clientData;
    }

    public void setClientData(ClientData clientData) {
        this.clientData = clientData;
    }

    public AttestationObject attestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }

    public AuthenticatorData authenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(AuthenticatorData authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public byte[] signature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
