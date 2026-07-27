package com.anvil.passkeyeditor.crypto;

import com.anvil.passkeyeditor.model.CoseKey;

import java.security.KeyPair;

/**
 * A COSE-algorithm signer used to forge / re-sign WebAuthn assertions and to substitute a credential
 * public key at registration.
 *
 * One seam over every supported COSE algorithm - ES256/384/512, RS256/384/512/RS1, EdDSA, PS256/384/512;
 * the catalog and per-algorithm factories live in {@link SignerAlgorithm}.
 *
 * The signed input for an assertion is {@code authenticatorData ‖ SHA-256(clientDataJSON wire bytes)}.
 * The returned signature is already in WebAuthn wire form per algorithm: ECDSA = ASN.1 DER
 * {@code Ecdsa-Sig-Value} (assert DER-parseable / {@code len > 64}, never {@code == 72}); EdDSA = raw
 * 64-byte {@code R‖S}; RSA (PKCS#1 v1.5 and PSS) = raw modulus-length.
 */
public interface CoseSigner {

    /** The COSE algorithm identifier this signer produces (e.g. {@code -7} for ES256). */
    int coseAlg();

    /** The public key, as a COSE_Key, to substitute into a registration's attested credential data. */
    CoseKey publicCoseKey();

    /**
     * The signer's keypair (public + private). Exposed so the tool can persist a substituted key and
     * reconstruct the signer later to re-sign (see {@link KeyStoreService}); the private half never leaves
     * the tool and is never placed on the wire - only {@link #publicCoseKey()} is.
     */
    KeyPair keyPair();

    /**
     * Sign the already-assembled signed input.
     *
     * @param signedData {@code authenticatorData ‖ SHA-256(clientDataJSON wire bytes)}
     * @return the signature bytes to place on the wire (DER {@code Ecdsa-Sig-Value} for ES256)
     */
    byte[] sign(byte[] signedData);
}
