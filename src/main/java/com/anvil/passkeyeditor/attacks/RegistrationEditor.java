package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.profile.PlantAttestation;

/**
 * Composes the registration-tab edits onto a decoded CREATE {@link AttestationObject} and
 * re-encodes it to its new wire CBOR - the CREATE-side counterpart of the GET tab's forge path.
 *
 * Registration fields (flags, {@code credentialId}, the embedded credential key) live inside the
 * attestation object's CBOR, so editing them is a decode → modify → re-encode, not a surgical byte
 * splice. The attestation format the plant emits is selectable ({@link PlantAttestation}): a
 * {@code fmt="none"} plant (empty {@code attStmt}, dropping any real attestation - the format ~all consumer
 * RPs accept), or a {@code fmt="packed"} self-attestation that our planted key signs over the
 * authenticator data (for an RP that requires attestation but does not pin a trusted root). A field-only
 * edit (no plant) always emits {@code fmt="none"}. The RP then takes our fields at face value, which is
 * exactly what these RP-policy conformance edits probe (a well-behaved RP rejects bad flags / a
 * colliding credentialId; the finding is when one does not).
 *
 * Composes with the key-substitution plant ({@link RegistrationSubstituter}): pass a {@code plant} signer
 * to embed our key (the ATO primitive), and/or a new {@code credentialId} (credential collision /
 * overwrite), and/or new {@code flags} (UP/UV/BE/BS policy conformance) in a single re-encode. Any
 * {@code null} argument leaves that field unchanged. Mutates {@code attObj} in place - the caller passes a
 * FRESH decode so the editor's on-screen display model is never disturbed.
 *
 * Burp-free; the byte mechanics - a plant-only edit is byte-identical to {@link
 * RegistrationSubstituter#substituteAndEncode}, a swapped credentialId / edited flags round-trips, and an
 * unedited {@code fmt="none"} registration re-encodes byte-identically - are gated by
 * {@code RegistrationEditorTest}.
 */
public final class RegistrationEditor {

    private final CborCodec codec;

    public RegistrationEditor(CborCodec codec) {
        this.codec = codec;
    }

    /**
     * Apply the armed CREATE edits to {@code attObj} and re-encode it to {@code fmt="none"} wire CBOR.
     *
     * @param attObj       a decoded registration attestation object (authData carries attested credential data)
     * @param plant        our signer to substitute as the credential key, or {@code null} to keep the original
     * @param credentialId a replacement credentialId (collision / overwrite), or {@code null} to keep it
     * @param flags        the replacement authData flags byte (low 8 bits used), or {@code null} to keep them
     * @return the rebuilt {@code attestationObject} CBOR ({@code fmt="none"})
     * @throws IllegalArgumentException if {@code attObj} is not a registration (no attested credential data)
     * @throws IllegalStateException    if the authData carries extension data (ED) - not re-encodable from fields
     */
    public byte[] edit(AttestationObject attObj, CoseSigner plant, byte[] credentialId, Integer flags) {
        return edit(attObj, plant, credentialId, flags, PlantAttestation.NONE, null);
    }

    /**
     * Apply the armed CREATE edits to {@code attObj} and re-encode it, emitting the chosen
     * {@code attestation} format for the plant.
     *
     * {@link PlantAttestation#NONE} keeps the historical behaviour (every edit forces {@code fmt="none"}).
     * {@link PlantAttestation#PACKED_SELF} emits a packed self-attestation signed by the planted key over
     * {@code authData ‖ SHA-256(clientDataJSON)}: because that signature covers the authData, any
     * {@code credentialId}/{@code flags} edit is applied first so the signature is over the FINAL
     * authData. Self-attestation therefore requires both a {@code plant} signer and the registration's
     * {@code clientDataJson}; a field-only edit (no plant) always emits {@code fmt="none"}.
     *
     * @param attObj         a decoded registration attestation object (authData carries attested credential data)
     * @param plant          our signer to substitute as the credential key, or {@code null} to keep the original
     * @param credentialId   a replacement credentialId (collision / overwrite), or {@code null} to keep it
     * @param flags          the replacement authData flags byte (low 8 bits used), or {@code null} to keep them
     * @param attestation    the attestation format the plant emits ({@link PlantAttestation})
     * @param clientDataJson the registration's inner clientDataJSON wire bytes (required for PACKED_SELF)
     * @return the rebuilt {@code attestationObject} CBOR
     * @throws IllegalArgumentException if {@code attObj} is not a registration (no attested credential data)
     * @throws IllegalStateException    if the authData carries extension data (ED), or PACKED_SELF is requested
     *                                  without a plant signer / clientDataJSON
     */
    public byte[] edit(AttestationObject attObj, CoseSigner plant, byte[] credentialId, Integer flags,
                       PlantAttestation attestation, byte[] clientDataJson) {
        if (attObj == null) {
            throw new IllegalArgumentException("attestationObject is required");
        }
        AuthenticatorData ad = attObj.authData();
        if (ad == null || !ad.hasFlag(AuthenticatorData.FLAG_AT)) {
            throw new IllegalArgumentException(
                    "not a registration attestationObject (no attested credential data to edit)");
        }
        // Extension data is carried verbatim only in the authData raw shadow (decode does not model it); an
        // edit must drop that shadow to rebuild from fields, which would silently lose the extensions. Refuse
        // up front (reading the ORIGINAL flags) rather than emit a registration that drops them. The same
        // limitation applies to the plant - but webauthn.io et al. send ED=0, so this is a rarely-hit guard.
        if (ad.hasFlag(AuthenticatorData.FLAG_ED)) {
            throw new IllegalStateException(
                    "registration carries extension data (ED); editing it is not supported");
        }

        // Packed self-attestation signs over the authData, so it needs the clientDataJSON up front - refuse
        // BEFORE mutating anything (no mutate-then-throw).
        boolean packedSelf = plant != null && attestation == PlantAttestation.PACKED_SELF;
        if (packedSelf && clientDataJson == null) {
            throw new IllegalStateException(
                    "packed self-attestation requires the registration clientDataJSON to sign over");
        }
        // Apply the credentialId / flags edits ONCE, before the plant. They are order-independent w.r.t. the
        // plant (neither substitute nor substituteSelfAttested touches credentialId/flags) and compose into a
        // single re-encode either way; for packed self-attestation this crucially means the signature covers
        // the FINAL (edited) authData.
        if (credentialId != null) {
            ad.setCredentialId(credentialId);
        }
        if (flags != null) {
            ad.setFlags(flags & 0xFF);
        }

        if (packedSelf) {
            // The substituter embeds our key, zeroes the AAGUID, encodes the (already field-edited) authData
            // once, and signs THOSE bytes.
            return new RegistrationSubstituter(codec)
                    .substituteSelfAttestedAndEncode(attObj, plant, clientDataJson);
        }

        // fmt="none" path (the default, and every field-only edit). The plant embeds our credential key and
        // forces fmt="none" + empty attStmt; the final re-encode below rebuilds the edited credId / flags / key
        // from fields. The embedded COSE key keeps its own verbatim shadow when not planted, so an unedited key
        // survives byte-for-byte.
        if (plant != null) {
            RegistrationSubstituter.substitute(attObj, plant);
        }
        attObj.setFmt("none");
        attObj.setAttStmtRaw(null);
        attObj.setRaw(null);
        ad.setRaw(null);
        return codec.encodeAttestationObject(attObj);
    }
}
