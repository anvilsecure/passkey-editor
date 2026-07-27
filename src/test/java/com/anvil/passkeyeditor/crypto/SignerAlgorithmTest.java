package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the {@link SignerAlgorithm} catalog - the model the algorithm chooser binds to and the
 * key store reconstructs through. Verifies the catalog's metadata is internally consistent, that
 * {@link SignerAlgorithm#generate()} produces a signer of the right algorithm, and that
 * {@link SignerAlgorithm#wrap(java.security.KeyPair)} faithfully reconstructs a signer from an existing
 * keypair (same public key bytes back out).
 */
class SignerAlgorithmTest {

    @Test
    void catalogCoversElevenAlgorithmsWithUniqueIds() {
        assertEquals(11, SignerAlgorithm.values().length, "11 algorithms (8 classical + the PS family)");
        Set<Integer> ids = new HashSet<>();
        for (SignerAlgorithm a : SignerAlgorithm.values()) {
            assertTrue(ids.add(a.coseId()), "duplicate COSE id: " + a.coseId());
            assertEquals(a, SignerAlgorithm.forCoseId(a.coseId()), "forCoseId must round-trip " + a);
        }
        assertThrows(IllegalArgumentException.class, () -> SignerAlgorithm.forCoseId(0),
                "an unsupported COSE id must be rejected");
    }

    @Test
    void metadataIsConsistent() {
        for (SignerAlgorithm a : SignerAlgorithm.values()) {
            assertNotNull(a.label(), () -> "label for " + a);
            assertTrue(a.displayName().contains(String.valueOf(a.coseId())), "displayName carries the id");
            String expectedKeyFactory = switch (a.keyType()) {
                case EC2 -> "EC";
                case OKP -> "Ed25519";
                case RSA -> "RSA";
            };
            assertEquals(expectedKeyFactory, a.jcaKeyAlgorithm(), () -> "key-factory algorithm for " + a);
        }
    }

    @Test
    void generateProducesASignerOfThatAlgorithm() {
        for (SignerAlgorithm a : SignerAlgorithm.values()) {
            CoseSigner signer = a.generate();
            assertEquals(a.coseId(), signer.coseAlg(), () -> "generated signer's coseAlg for " + a);
            assertEquals(a.coseId(), signer.publicCoseKey().alg(), () -> "COSE key carries the alg for " + a);
            assertNotNull(signer.keyPair(), () -> "generated signer exposes its keypair for " + a);
        }
    }

    @Test
    void wrapReconstructsASignerWithTheSamePublicKey() {
        for (SignerAlgorithm a : SignerAlgorithm.values()) {
            CoseSigner generated = a.generate();
            CoseSigner wrapped = a.wrap(generated.keyPair());
            assertEquals(a.coseId(), wrapped.coseAlg(), () -> "wrapped signer's coseAlg for " + a);
            // Same keypair in → byte-identical public COSE key out (the reconstruction is faithful).
            assertArrayEquals(generated.publicCoseKey().raw(), wrapped.publicCoseKey().raw(),
                    () -> "wrap must reconstruct the identical public COSE key for " + a);
        }
    }
}
