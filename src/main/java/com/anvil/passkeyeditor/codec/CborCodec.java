package com.anvil.passkeyeditor.codec;

import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;

/**
 * CBOR/COSE decode + encode boundary for WebAuthn structures.
 *
 * This is the seam behind which the CBOR implementation lives ({@link Webauthn4jCborCodec} on
 * webauthn4j today; swappable for RAT #97 later). It maps between raw CBOR bytes and the tool's
 * Burp-free {@code model.*} types - webauthn4j's own types never cross this interface.
 *
 * Decode-for-display must never throw on shape: EC2/RSA/OKP keys and every attestation
 * format must decode (a decode exception inside {@code setRequestResponse} makes the tab vanish).
 * The implementation uses webauthn4j's low-level converters, never the validating
 * {@code WebAuthnManager}, which rejects the deliberately-malformed structures this tool must emit.
 *
 * Decode methods accept raw CBOR (already unwrapped by {@link WrapperCodec}); encode methods emit
 * raw CBOR (re-wrapped afterwards by {@link WrapperCodec}).
 */
public interface CborCodec {

    /** Decode an attestation object (registration) from raw CBOR. */
    AttestationObject decodeAttestationObject(byte[] cbor);

    /** Encode an attestation object back to raw CBOR. */
    byte[] encodeAttestationObject(AttestationObject attestationObject);

    /** Decode authenticator data (the raw authData byte string) into the model. */
    AuthenticatorData decodeAuthData(byte[] authData);

    /** Encode authenticator data back to its raw wire bytes. */
    byte[] encodeAuthData(AuthenticatorData authenticatorData);

    /** Decode a COSE_Key (e.g. a credential public key) from raw CBOR. */
    CoseKey decodeCoseKey(byte[] cbor);

    /** Encode a COSE_Key back to raw CBOR. */
    byte[] encodeCoseKey(CoseKey coseKey);

    /**
     * Encode a WebAuthn packed self-attestation statement - the CBOR map {@code { "alg": coseAlg,
     * "sig": sig }} with no x5c chain - to raw CBOR, for embedding as an attestation object's
     * {@code attStmt} ({@code fmt="packed"}). Algorithm-agnostic: {@code coseAlg} is whatever the planting
     * signer produces and {@code sig} its already-wire-form signature; this method only frames the map.
     *
     * @param coseAlg the COSE algorithm id of the signature (e.g. {@code -7} ES256, {@code -8} EdDSA)
     * @param sig     the signature bytes in their per-algorithm wire form (ECDSA = DER, EdDSA/RSA = raw)
     * @return the {@code attStmt} CBOR bytes
     */
    byte[] encodePackedSelfAttStmt(int coseAlg, byte[] sig);
}
