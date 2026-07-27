package com.anvil.passkeyeditor.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores and retrieves the tool's substituted keypairs, keyed by {@code (rpId, userHandle, credId)} so the
 * right key is served per account (never one account's key served for another). {@link #storeSigner} keeps
 * each keypair's PKCS#8 private + X.509 public bytes tagged with its COSE {@link SignerAlgorithm}, and
 * {@link #retrieveSigner} / {@link #retrieveMostRecentSigner} reconstruct a ready {@link CoseSigner} of that
 * algorithm - so any supported alg (including Ed25519, whose public key cannot be cheaply re-derived from the
 * private key) round-trips.
 *
 * In-memory only. The backing map lives for the current extension session and is wiped by
 * {@link #clear()} on unload, so no planted private key lingers in the JVM after a reload; it is not
 * persisted to the Burp project file. The surface is Burp-free (plain {@code byte[]} + {@link KeyPair}) so
 * the core stays JUnit-testable.
 */
public final class KeyStoreService {

    /** Composite identity under which a substituted keypair is stored. */
    public record KeyId(String rpId, String userHandle, String credId) {
    }

    /** What is kept per credential: the algorithm, the PKCS#8 private key, and the X.509 public key. */
    private record StoredKey(SignerAlgorithm algorithm, byte[] pkcs8, byte[] spkiPublic) {
    }

    // ConcurrentHashMap + volatile mostRecentId: the store is shared between the editor (EDT) and the AUTO
    // HttpHandler (off-EDT) - see PasskeyAutoHandler. No null keys/values are ever put (store(id,null) does a
    // remove). The (put + mostRecentId write) pair is not atomic, but the worst case is a momentarily-stale
    // most-recent fallback during a concurrent manual + auto plant - never corruption.
    private final Map<KeyId, StoredKey> store = new ConcurrentHashMap<>();

    /**
     * The most recently stored identity - the single-account demo fallback. Cross-message keying
     * (register on one request, forge on another) reconstructs the {@link KeyId} from each message's
     * fields, which can legitimately differ (e.g. a registration carries no {@code userHandle}); keeping
     * the last-stored id lets the forge path fall back to "the key we just registered" when an exact
     * match misses. Null once nothing is stored.
     */
    private volatile KeyId mostRecentId;

    public KeyStoreService() {
    }

    /** The most recently stored identity, or {@code null} if the store is empty. */
    public KeyId mostRecentId() {
        return mostRecentId;
    }

    /** The number of stored credentials - lets the AUTO handler bound its most-recent fallback to the
     * unambiguous (single-key) case rather than risk re-signing under the wrong account's key. */
    public int size() {
        return store.size();
    }

    /** Drop every stored keypair - called on extension unload so no planted private key lingers in the JVM. */
    public void clear() {
        store.clear();
        mostRecentId = null;
    }

    /**
     * Store {@code signer}'s keypair under {@code id}, tagged with its COSE algorithm so the right signer
     * type is reconstructed on retrieval. Keeps the PKCS#8 private + X.509 public, so non-EC public keys
     * (e.g. Ed25519, which cannot be cheaply re-derived from the private key) round-trip.
     *
     * @param id     the {@code (rpId, userHandle, credId)} identity
     * @param signer the signer whose keypair to persist
     */
    public void storeSigner(KeyId id, CoseSigner signer) {
        SignerAlgorithm algorithm = SignerAlgorithm.forCoseId(signer.coseAlg());
        KeyPair keyPair = signer.keyPair();
        store.put(id, new StoredKey(algorithm,
                keyPair.getPrivate().getEncoded(), keyPair.getPublic().getEncoded()));
        mostRecentId = id;
    }

    /**
     * Reconstruct the signer stored under {@code id}, of whatever algorithm it was stored with.
     *
     * @return the reconstructed {@link CoseSigner}, or {@code null} if none is stored
     */
    public CoseSigner retrieveSigner(KeyId id) {
        StoredKey stored = store.get(id);
        return stored == null ? null : stored.algorithm().wrap(reconstruct(stored));
    }

    /**
     * Reconstruct the most recently stored signer, regardless of identity - the single-account fallback for
     * the re-sign path when an exact {@code (rpId, credId)} lookup misses (cross-message keying).
     *
     * @return the most recently stored {@link CoseSigner}, or {@code null} if nothing is stored
     */
    public CoseSigner retrieveMostRecentSigner() {
        KeyId id = mostRecentId; // snapshot the volatile once - no null-key TOCTOU between the check + the read
        return id == null ? null : retrieveSigner(id);
    }

    /**
     * Reconstruct the keypair for a stored credential: the private key from its PKCS#8 encoding and the
     * public key from the stored X.509 bytes (both always kept by {@link #storeSigner}).
     */
    private KeyPair reconstruct(StoredKey stored) {
        try {
            KeyFactory kf = KeyFactory.getInstance(stored.algorithm().jcaKeyAlgorithm());
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(stored.pkcs8()));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(stored.spkiPublic()));
            return new KeyPair(pub, priv);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "stored key is not a usable " + stored.algorithm().label() + " key", e);
        }
    }
}
