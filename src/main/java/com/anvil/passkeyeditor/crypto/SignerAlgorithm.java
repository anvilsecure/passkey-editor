package com.anvil.passkeyeditor.crypto;

import java.security.KeyPair;

/**
 * The catalog of COSE signature algorithms the tool can produce - the single source of truth behind the
 * algorithm chooser (a {@code values()} list of selectable algorithms) and the key store (reconstructing
 * the right {@link CoseSigner} for a stored key).
 *
 * Each constant knows its COSE algorithm id, a display label, its COSE key type, the JCA key-factory
 * algorithm used to reconstitute a stored keypair, and how to {@link #generate()} a fresh signer or
 * {@link #wrap(KeyPair)} an existing keypair. This is the seam the (deferred) UI and the AUTO mode bind to:
 * radio buttons over {@code values()}, "Generate" → {@link #generate()} then {@link CoseSigner#publicCoseKey()}
 * for the preview, and re-sign → look up by {@link #forCoseId(int)} and {@code wrap} the stored key.
 *
 * Note the asymmetry that {@link EdDsaSigner} / {@link Es256Signer} take a public {@code KeyPair}
 * constructor while the larger ECDSA / RSA families expose {@code wrap}-style factories; both routes are
 * exercised here so a stored key of any algorithm reconstitutes into a working signer.
 */
public enum SignerAlgorithm {

    ES256(-7, "ES256", KeyType.EC2, "EC"),
    ES384(-35, "ES384", KeyType.EC2, "EC"),
    ES512(-36, "ES512", KeyType.EC2, "EC"),
    EDDSA(-8, "EdDSA", KeyType.OKP, "Ed25519"),
    RS256(-257, "RS256", KeyType.RSA, "RSA"),
    RS384(-258, "RS384", KeyType.RSA, "RSA"),
    RS512(-259, "RS512", KeyType.RSA, "RSA"),
    RS1(-65535, "RS1", KeyType.RSA, "RSA"),
    PS256(-37, "PS256", KeyType.RSA, "RSA"),
    PS384(-38, "PS384", KeyType.RSA, "RSA"),
    PS512(-39, "PS512", KeyType.RSA, "RSA");

    /** The COSE key type a constant's keys carry (for display / key-store routing). */
    public enum KeyType {
        EC2, OKP, RSA
    }

    private final int coseId;
    private final String label;
    private final KeyType keyType;
    private final String jcaKeyAlgorithm;

    SignerAlgorithm(int coseId, String label, KeyType keyType, String jcaKeyAlgorithm) {
        this.coseId = coseId;
        this.label = label;
        this.keyType = keyType;
        this.jcaKeyAlgorithm = jcaKeyAlgorithm;
    }

    /** The COSE algorithm identifier (e.g. {@code -7} for ES256). */
    public int coseId() {
        return coseId;
    }

    /** A short display label (e.g. {@code "ES256"}). */
    public String label() {
        return label;
    }

    /** A label with the COSE id, ctap.dev-style (e.g. {@code "ES256 (-7)"}). */
    public String displayName() {
        return label + " (" + coseId + ")";
    }

    /** The COSE key type these keys carry. */
    public KeyType keyType() {
        return keyType;
    }

    /** The JCA {@code KeyFactory} algorithm used to reconstitute a stored keypair ({@code EC}/{@code RSA}/{@code Ed25519}). */
    public String jcaKeyAlgorithm() {
        return jcaKeyAlgorithm;
    }

    /** Generate a fresh signer for this algorithm (a new keypair). */
    public CoseSigner generate() {
        return switch (this) {
            case ES256 -> Es256Signer.generate();
            case ES384 -> EcdsaSigner.es384();
            case ES512 -> EcdsaSigner.es512();
            case EDDSA -> EdDsaSigner.generate();
            case RS256 -> RsaSigner.rs256();
            case RS384 -> RsaSigner.rs384();
            case RS512 -> RsaSigner.rs512();
            case RS1 -> RsaSigner.rs1();
            case PS256 -> PsSigner.ps256();
            case PS384 -> PsSigner.ps384();
            case PS512 -> PsSigner.ps512();
        };
    }

    /**
     * Wrap an existing keypair as a signer for this algorithm - used to reconstruct a stored credential key
     * so its assertions can be re-signed. The keypair must match this algorithm's key type.
     */
    public CoseSigner wrap(KeyPair keyPair) {
        return switch (this) {
            case ES256 -> new Es256Signer(keyPair);
            case ES384 -> EcdsaSigner.es384(keyPair);
            case ES512 -> EcdsaSigner.es512(keyPair);
            case EDDSA -> new EdDsaSigner(keyPair);
            case RS256 -> RsaSigner.rs256(keyPair);
            case RS384 -> RsaSigner.rs384(keyPair);
            case RS512 -> RsaSigner.rs512(keyPair);
            case RS1 -> RsaSigner.rs1(keyPair);
            case PS256 -> PsSigner.ps256(keyPair);
            case PS384 -> PsSigner.ps384(keyPair);
            case PS512 -> PsSigner.ps512(keyPair);
        };
    }

    /**
     * The catalog entry for a COSE algorithm id.
     *
     * @throws IllegalArgumentException if no supported algorithm has that id
     */
    public static SignerAlgorithm forCoseId(int coseId) {
        SignerAlgorithm a = forCoseIdOrDefault(coseId, null);
        if (a == null) {
            throw new IllegalArgumentException("unsupported COSE algorithm id: " + coseId);
        }
        return a;
    }

    /**
     * The catalog entry for {@code coseId}, or {@code fallback} if no supported algorithm has that id - the
     * never-throws variant for UI / profile boundaries where an unknown persisted id must degrade safely
     * (the chooser's profile-default pre-select, the Profile-Editor dropdown) rather than break the tab.
     */
    public static SignerAlgorithm forCoseIdOrDefault(int coseId, SignerAlgorithm fallback) {
        for (SignerAlgorithm a : values()) {
            if (a.coseId == coseId) {
                return a;
            }
        }
        return fallback;
    }
}
