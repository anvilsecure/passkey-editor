package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.anvil.passkeyeditor.crypto.KeyStoreService.KeyId;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * End-to-end gate for the multi-algorithm key store - the baseline the algorithm chooser and AUTO mode
 * sit on: plant → store → retrieve → re-sign for every supported algorithm. For each
 * {@link SignerAlgorithm} a fresh signer is stored via {@link KeyStoreService#storeSigner}, retrieved via
 * {@link KeyStoreService#retrieveSigner}, and a signature from the reconstructed signer is verified under
 * the reconstructed public key - proving the private key (and so re-signing) survives the round-trip,
 * including the public keys that cannot be re-derived from the private key alone (Ed25519).
 */
class KeyStoreServiceMultiAlgTest {

    private static final byte[] INPUT = "multi-alg signed input".getBytes(StandardCharsets.UTF_8);

    /** An independent JCA verifier for an algorithm (PS needs its PSS parameters). */
    private static Signature verifierFor(SignerAlgorithm alg) throws GeneralSecurityException {
        switch (alg) {
            case ES256:
                return Signature.getInstance("SHA256withECDSA");
            case ES384:
                return Signature.getInstance("SHA384withECDSA");
            case ES512:
                return Signature.getInstance("SHA512withECDSA");
            case EDDSA:
                return Signature.getInstance("Ed25519");
            case RS256:
                return Signature.getInstance("SHA256withRSA");
            case RS384:
                return Signature.getInstance("SHA384withRSA");
            case RS512:
                return Signature.getInstance("SHA512withRSA");
            case RS1:
                return Signature.getInstance("SHA1withRSA");
            case PS256:
                return pss("SHA-256", MGF1ParameterSpec.SHA256, 32);
            case PS384:
                return pss("SHA-384", MGF1ParameterSpec.SHA384, 48);
            case PS512:
                return pss("SHA-512", MGF1ParameterSpec.SHA512, 64);
            default:
                throw new IllegalArgumentException(alg.name());
        }
    }

    private static Signature pss(String hash, MGF1ParameterSpec mgf1, int saltLength) throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec(hash, "MGF1", mgf1, saltLength, 1));
        return s;
    }

    @Test
    void plantStoreRetrieveResignRoundTripsForEveryAlgorithm() throws Exception {
        KeyStoreService keyStore = new KeyStoreService();

        for (SignerAlgorithm alg : SignerAlgorithm.values()) {
            CoseSigner planted = alg.generate();
            KeyId id = new KeyId("rp.example", "user", "cred-" + alg.name());
            keyStore.storeSigner(id, planted);

            CoseSigner reconstructed = keyStore.retrieveSigner(id);
            assertNotNull(reconstructed, () -> "retrieveSigner for " + alg);
            assertEquals(alg.coseId(), reconstructed.coseAlg(), () -> "reconstructed alg for " + alg);
            assertArrayEquals(planted.publicCoseKey().raw(), reconstructed.publicCoseKey().raw(),
                    () -> "the same public COSE key comes back for " + alg);

            // The reconstructed signer can sign, and its signature verifies under its reconstructed public
            // key - the private key (and so re-signing) survived store→retrieve.
            byte[] sig = reconstructed.sign(INPUT);
            Signature verifier = verifierFor(alg);
            verifier.initVerify(reconstructed.keyPair().getPublic());
            verifier.update(INPUT);
            assertTrue(verifier.verify(sig), () -> "reconstructed signer re-signs validly for " + alg);
        }
    }

    @Test
    void retrieveMostRecentSignerReturnsTheLastPlanted() {
        KeyStoreService keyStore = new KeyStoreService();
        keyStore.storeSigner(new KeyId("rp", "u", "a"), SignerAlgorithm.ES256.generate());
        CoseSigner lastPlanted = SignerAlgorithm.EDDSA.generate();
        keyStore.storeSigner(new KeyId("rp", "u", "b"), lastPlanted);

        CoseSigner mostRecent = keyStore.retrieveMostRecentSigner();
        assertNotNull(mostRecent);
        assertEquals(SignerAlgorithm.EDDSA.coseId(), mostRecent.coseAlg(),
                "the cross-message fallback returns the last-planted signer's algorithm");
    }
}
