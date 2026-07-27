package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.codec.CborCodec;
import com.anvil.passkeyeditor.codec.Webauthn4jCborCodec;
import com.anvil.passkeyeditor.crypto.Es256Signer;
import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;

import java.security.KeyPair;

import org.junit.jupiter.api.Test;

/**
 * registration key substitution. After embedding our key and forcing {@code fmt="none"}, the
 * rebuilt attestation object must (a) re-decode to our EC2/ES256 credential key, (b) preserve the
 * victim credential's identity bytes (credentialId / signCount), and (c) refuse anything that is not a
 * registration. The end-to-end "the RP then accepts our forged assertion" property is in
 * {@link ForgeryOracleTest}.
 */
class RegistrationSubstituterTest {

    private final CborCodec cbor = new Webauthn4jCborCodec();
    private final RegistrationSubstituter substituter = new RegistrationSubstituter(cbor);

    @Test
    void substitutedRegistrationDecodesToOurKeyAndKeepsCredentialIdentity() {
        // A victim registration produced with an authenticator key we do NOT control.
        KeyPair victimKey = Fixtures.generateP256();
        AttestationObject victimReg = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(victimKey));
        byte[] originalCredId = victimReg.authData().credentialId().clone();
        byte[] originalAaguid = victimReg.authData().aaguid().clone();
        long originalSignCount = victimReg.authData().signCount();

        Es256Signer attacker = Es256Signer.generate();
        byte[] rebuilt = substituter.substituteAndEncode(victimReg, attacker);

        AttestationObject reDecoded = cbor.decodeAttestationObject(rebuilt);
        assertEquals("none", reDecoded.fmt(), "attestation forced to none");
        AuthenticatorData ad = reDecoded.authData();
        assertNotNull(ad);
        assertTrue(ad.hasFlag(AuthenticatorData.FLAG_AT), "attested credential data still present");

        CoseKey embedded = ad.credentialPublicKey();
        assertNotNull(embedded);
        assertEquals(2, embedded.kty(), "EC2 kty=2");
        assertEquals(-7, embedded.alg(), "ES256 alg=-7");
        // The embedded key is OUR key, byte-for-byte (the canonical COSE encoding of our point).
        assertArrayEquals(attacker.publicCoseKey().raw(), embedded.raw(),
                "the substituted credential key is the attacker's public key");

        // Victim credential identity is preserved so the victim's later assertions still resolve here.
        assertArrayEquals(originalCredId, ad.credentialId(), "credentialId preserved");
        assertArrayEquals(originalAaguid, ad.aaguid(), "aaguid preserved");
        assertEquals(originalSignCount, ad.signCount(), "signCount preserved");
    }

    @Test
    void reSubstitutingIsIdempotentAndUsesTheLatestKey() {
        // The operator may re-click "Register with our key" (e.g. a re-take): re-decode + re-substitute.
        AttestationObject victimReg = cbor.decodeAttestationObject(
                Fixtures.registrationAttestationObject(Fixtures.generateP256()));
        byte[] originalCredId = victimReg.authData().credentialId().clone();

        Es256Signer first = Es256Signer.generate();
        byte[] firstWire = substituter.substituteAndEncode(victimReg, first);

        AttestationObject reDecoded = cbor.decodeAttestationObject(firstWire);
        Es256Signer second = Es256Signer.generate();
        byte[] secondWire = substituter.substituteAndEncode(reDecoded, second);

        AttestationObject out = cbor.decodeAttestationObject(secondWire);
        assertEquals("none", out.fmt(), "still fmt=none after re-substitution");
        assertTrue(out.authData().hasFlag(AuthenticatorData.FLAG_AT), "AT preserved across re-substitution");
        assertArrayEquals(second.publicCoseKey().raw(), out.authData().credentialPublicKey().raw(),
                "the latest substituted key wins");
        assertArrayEquals(originalCredId, out.authData().credentialId(), "credentialId still preserved");
    }

    @Test
    void substitutingAnAssertionIsRejected() {
        // A GET assertion has no attested credential data - there is no key to substitute.
        AttestationObject notARegistration = new AttestationObject();
        AuthenticatorData bare = cbor.decodeAuthData(Fixtures.assertionAuthData());
        notARegistration.setAuthData(bare);

        assertThrows(IllegalArgumentException.class,
                () -> RegistrationSubstituter.substitute(notARegistration, Es256Signer.generate()),
                "substitution requires a registration (AT-flagged authData)");
    }
}
