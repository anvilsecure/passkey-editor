package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.crypto.CoseSigner;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Re-signs (forges) a WebAuthn assertion with a {@link CoseSigner} the tool controls - the assertion-forgery
 * engine for {@code webauthn.get} ceremonies.
 *
 * The signed input is the canonical assertion input
 * {@code authenticatorData ‖ SHA-256(clientDataJSON wire bytes)} (W3C WebAuthn-2 §6.3.3). Both inputs
 * are the inner (unwrapped) bytes - the exact bytes a relying party reconstructs and verifies,
 * never a re-serialisation: the caller passes whatever {@code authData} / {@code clientDataJSON} it
 * means to put on the wire (possibly already edited byte-surgically), and we sign precisely those.
 *
 * Because we sign the exact bytes handed in, an edit to {@code clientDataJSON} (e.g. a different
 * {@code origin}) or to {@code authData} (e.g. a flipped UV flag) is honoured losslessly with no
 * re-encode risk - the signature simply covers the edited bytes, and a relying party that stored our
 * substituted public key (see {@link RegistrationSubstituter}) accepts it. ES256 returns a DER
 * {@code Ecdsa-Sig-Value} straight to the wire.
 *
 * Burp-free + stateless, so it is unit-testable against an independent verifier (the re-sign oracle).
 */
public final class AssertionForger {

    /**
     * Forge the assertion signature over {@code authData ‖ SHA-256(clientDataJSON)} using {@code signer}.
     *
     * @param authData       the (possibly edited) inner authenticator data bytes
     * @param clientDataJson the (possibly edited) inner clientDataJSON wire bytes
     * @param signer         the signer holding the private key matching the RP-stored credential key
     * @return the signature bytes to place on the wire (DER {@code Ecdsa-Sig-Value} for ES256)
     */
    public byte[] sign(byte[] authData, byte[] clientDataJson, CoseSigner signer) {
        return signer.sign(signedInput(authData, clientDataJson));
    }

    /**
     * Assemble the canonical assertion signed input {@code authData ‖ SHA-256(clientDataJSON)}.
     *
     * @param authData       the inner authenticator data bytes
     * @param clientDataJson the inner clientDataJSON wire bytes
     * @return the bytes a relying party signs/verifies
     */
    public static byte[] signedInput(byte[] authData, byte[] clientDataJson) {
        if (authData == null || clientDataJson == null) {
            throw new IllegalArgumentException("authData and clientDataJSON are required to forge an assertion");
        }
        byte[] cdHash = sha256(clientDataJson);
        ByteArrayOutputStream out = new ByteArrayOutputStream(authData.length + cdHash.length);
        out.writeBytes(authData);
        out.writeBytes(cdHash);
        return out.toByteArray();
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every supported JDK; failure is non-recoverable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
