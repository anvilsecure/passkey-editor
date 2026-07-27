package com.anvil.passkeyeditor.codec;

import com.anvil.passkeyeditor.model.AttestationObject;
import com.anvil.passkeyeditor.model.AuthenticatorData;
import com.anvil.passkeyeditor.model.CoseKey;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.jackson.deserializer.cbor.COSEKeyEnvelope;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.authenticator.EdDSACOSEKey;
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;

/**
 * webauthn4j-backed {@link CborCodec} (pinned 0.28.3.RELEASE).
 *
 * Discipline (LOCKED): only the low-level converters wired here - {@link ObjectConverter},
 * {@link AttestationObjectConverter}, {@link AuthenticatorDataConverter}, and the COSE key types
 * ({@code EC2COSEKey}/{@code RSACOSEKey}/{@code EdDSACOSEKey}) for COSE_Key (de)serialization. The
 * validating {@code WebAuthnManager} / {@code WebAuthnRegistrationManager} is never used - it rejects
 * the deliberately-malformed structures this tool must emit and decode.
 *
 * The converters are constructed once (thread-safe, reusable) and shared.
 *
 * Raw-bytes shadow (losslessness): every decoded structure retains its verbatim wire bytes.
 * Encode returns that shadow when the structure is unedited - so a foreign producer's CBOR map order /
 * integer width survives the round-trip byte-identically (byte-identity gate), independent of
 * how Jackson would re-serialise. The from-fields encode path is used only when no shadow exists (a
 * freshly built structure, e.g. a re-signed bare assertion or a substituted COSE key).
 *
 * Never throws on shape during decode of an attestation object: a malformed/unknown
 * attestation statement degrades to {@code fmt=null} + raw bytes rather than throwing (a decode
 * exception inside {@code setRequestResponse} would vanish the tab).
 */
public final class Webauthn4jCborCodec implements CborCodec {

    /** Length of the big-endian credIdLen field that follows the AAGUID. */
    private static final int CRED_ID_LEN_LEN = 2;

    private final ObjectConverter objectConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final CborConverter cborConverter;

    public Webauthn4jCborCodec() {
        this.objectConverter = new ObjectConverter();
        this.attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        this.authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        this.cborConverter = objectConverter.getCborConverter();
    }

    // ---- AttestationObject (registration) ------------------------------------------------------

    @Override
    public AttestationObject decodeAttestationObject(byte[] cbor) {
        AttestationObject out = new AttestationObject();
        out.setRaw(cbor);

        // Verbatim sub-structure bytes straight off the CBOR map - these are the lossless shadows and
        // never go through a re-serialiser.
        byte[] authDataBytes = null;
        try {
            authDataBytes = attestationObjectConverter.extractAuthenticatorData(cbor);
        } catch (RuntimeException ignored) {
            // leave null; handled below
        }
        try {
            out.setAttStmtRaw(attestationObjectConverter.extractAttestationStatement(cbor));
        } catch (RuntimeException ignored) {
            // attStmt is opaque to us anyway; tolerate a weird/unknown statement
        }
        try {
            out.setFmt(attestationObjectConverter.convert(cbor).getFormat());
        } catch (RuntimeException ignored) {
            // Unknown/odd attestation format: degrade to null fmt, keep raw + authData usable.
        }

        if (authDataBytes != null) {
            try {
                out.setAuthData(decodeAuthData(authDataBytes));
            } catch (RuntimeException ignored) {
                // A COSE key / attested-cred-data webauthn4j chokes on must not vanish the tab: keep the
                // attestation object's raw + fmt; authData stays null (caller renders what it has).
            }
        }
        return out;
    }

    @Override
    public byte[] encodeAttestationObject(AttestationObject attestationObject) {
        // Lossless shadow first: an unedited attestation object (incl. a foreign producer's CBOR map
        // order / int width) round-trips byte-identically.
        byte[] raw = attestationObject.raw();
        if (raw != null) {
            return raw;
        }
        // From-fields rebuild, scoped to the formats the tool actually emits: fmt="none" (registration
        // key-substitution) and fmt="packed" (packed SELF-attestation - a caller-supplied attStmt). The
        // CBOR map is assembled in the CTAP2-canonical key order { "fmt", "attStmt", "authData" } that real
        // RPs (SimpleWebAuthn, platform authenticators) put on the wire, so rebuilding an UNEDITED structure
        // reproduces it byte-identically (from-fields byte-identity re-gate). The authData is rebuilt via
        // encodeAuthData (which keeps the embedded COSE key verbatim unless it was substituted).
        AuthenticatorData authData = attestationObject.authData();
        if (authData == null) {
            throw new IllegalArgumentException(
                    "encodeAttestationObject from fields requires authData");
        }
        String fmt = attestationObject.fmt();
        boolean none = "none".equals(fmt);
        boolean packed = "packed".equals(fmt);
        if (!none && !packed) {
            // Recommended-depth scope: only fmt="none" / fmt="packed" are rebuilt from fields. Any other
            // (signed, x5c-bearing) attestation must round-trip via its raw shadow - re-encoding its attStmt
            // from fields is out of scope and would silently corrupt the attestation.
            throw new UnsupportedOperationException(
                    "encodeAttestationObject from fields supports fmt=\"none\"/\"packed\" only (got " + fmt + ")");
        }
        byte[] authDataBytes = encodeAuthData(authData);
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        writeCborTypeHeader(bo, CBOR_MAJOR_MAP, 3);
        writeCborTextString(bo, "fmt");
        writeCborTextString(bo, fmt);
        writeCborTextString(bo, "attStmt");
        if (none) {
            // fmt="none" carries an EMPTY attestation statement. Emit it as the DEFINITE-length empty map
            // (0xA0) - the form real RPs (SimpleWebAuthn, platform authenticators) put on the wire and verify,
            // and the form a key-substitution forgery must therefore carry. NB: do NOT reuse
            // attestationObject.attStmtRaw() here - webauthn4j's extractAttestationStatement RE-SERIALISES the
            // none attStmt as an INDEFINITE-length map (0xBF…0xFF, 2 bytes), so that shadow is not the verbatim
            // wire form and rebuilding from it would mismatch the original by one byte. (Unedited objects still
            // round-trip via the whole-object raw shadow above; this canonical emit is only the rebuild path.)
            bo.write(0xA0);
        } else {
            // fmt="packed": EMIT THE PROVIDED attStmt bytes verbatim. The self-attestation assembly builds the
            // { "alg", "sig" } map (no x5c) via encodePackedSelfAttStmt and stores it as attStmtRaw; here we
            // splice exactly those bytes so the emitted attStmt is byte-identical to what was signed against.
            byte[] attStmt = attestationObject.attStmtRaw();
            if (attStmt == null || attStmt.length == 0) {
                throw new IllegalArgumentException(
                        "encodeAttestationObject fmt=\"packed\" requires a non-empty attStmt (attStmtRaw)");
            }
            bo.write(attStmt, 0, attStmt.length);
        }
        writeCborTextString(bo, "authData");
        writeCborByteString(bo, authDataBytes);
        return bo.toByteArray();
    }

    @Override
    public byte[] encodePackedSelfAttStmt(int coseAlg, byte[] sig) {
        if (sig == null || sig.length == 0) {
            throw new IllegalArgumentException("packed self-attestation requires a signature");
        }
        // A 2-entry map { "alg": <int>, "sig": <bstr> }, NO x5c (self-attestation). Emitted with the same
        // minimal DEFINITE-length CBOR writer used for the from-fields attestation object, so the bytes are
        // deterministic and framing-stable - a strict RP CBOR parser (e.g. a PHP/openssl verifier) reads a
        // definite-length map without ambiguity. Keys are in CTAP2-canonical order (both length 3, "alg" <
        // "sig" bytewise); order is not signed over (the RP parses the map), so this is only for cleanliness.
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        writeCborTypeHeader(bo, CBOR_MAJOR_MAP, 2);
        writeCborTextString(bo, "alg");
        writeCborInt(bo, coseAlg);
        writeCborTextString(bo, "sig");
        writeCborByteString(bo, sig);
        return bo.toByteArray();
    }

    // ---- AuthenticatorData ---------------------------------------------------------------------

    @Override
    public AuthenticatorData decodeAuthData(byte[] authData) {
        AuthenticatorData out = new AuthenticatorData();
        out.setRaw(authData);

        try {
            com.webauthn4j.data.attestation.authenticator.AuthenticatorData<?> parsed =
                    authenticatorDataConverter.convert(authData);

            out.setRpIdHash(parsed.getRpIdHash());
            out.setFlags(parsed.getFlags() & 0xFF);
            out.setSignCount(parsed.getSignCount());

            try {
                AttestedCredentialData acd = parsed.getAttestedCredentialData();
                if (acd != null) {
                    out.setAaguid(acd.getAaguid().getBytes());
                    out.setCredentialId(acd.getCredentialId());
                    CoseKey coseKey = mapCoseKey(acd.getCOSEKey());
                    // Override mapCoseKey's CANONICAL shadow with the VERBATIM wire slice of the embedded
                    // COSE key, so a foreign producer's map order/int width survives byte-identically
                    // (matching every other sub-structure shadow). Without this, a key-splice that
                    // re-encodes an unedited credentialPublicKey().raw() would silently reorder the COSE
                    // map and break the RP signature.
                    byte[] coseSlice = extractEmbeddedCoseKeyBytes(authData);
                    if (coseSlice != null) {
                        coseKey.setRaw(coseSlice);
                    }
                    out.setCredentialPublicKey(coseKey);
                }
            } catch (RuntimeException attestedCredFailure) {
                // A malformed attested-credential-data tail (e.g. a COSE key webauthn4j chokes on) must
                // not lose the header we already parsed: keep rpIdHash/flags/signCount, drop the AT block.
            }
        } catch (RuntimeException parseFailure) {
            // Decode-for-display must NEVER throw on shape (CborCodec contract) - a truncated/garbage
            // authData fed straight to this method (the GET assertion path) must still render, not vanish
            // the tab. Recover the fixed 37-byte header by hand when it is present; otherwise the verbatim
            // raw shadow is all we can honestly show.
            decodeAuthDataHeaderBestEffort(authData, out);
        }
        // Extensions (ED) are carried verbatim inside out.raw initially; not separately modelled.
        return out;
    }

    /**
     * Best-effort recovery of the fixed authData header - {@code rpIdHash(32) | flags(1) | signCount(4
     * BE)} - when webauthn4j's structural parse failed (e.g. a malformed attested-credential tail or a
     * truncated body) but the 37-byte prefix is intact. Populates only what the length guarantees; the
     * attested-credential-data / extension tail is deliberately not guessed (the CBOR was unreadable, so
     * those bytes can't be trusted). Never throws - the raw shadow remains authoritative for round-trip.
     */
    private void decodeAuthDataHeaderBestEffort(byte[] authData, AuthenticatorData out) {
        if (authData == null || authData.length < AuthenticatorData.ASSERTION_LENGTH) {
            return; // too short to trust any field; expose raw only
        }
        // Mark the value as header-recovered: webauthn4j could NOT structurally parse it, so the rpIdHash/
        // flags/signCount below are taken on faith from the first 37 bytes. The Check validator keys on this
        // to avoid a false-green on a mis-located field (any ≥37-byte blob lands here).
        out.setHeaderRecovered(true);
        out.setRpIdHash(java.util.Arrays.copyOfRange(authData, 0, AuthenticatorData.RP_ID_HASH_LENGTH));
        out.setFlags(authData[32] & 0xFF);
        long signCount = ((authData[33] & 0xFFL) << 24)
                | ((authData[34] & 0xFFL) << 16)
                | ((authData[35] & 0xFFL) << 8)
                | (authData[36] & 0xFFL);
        out.setSignCount(signCount);
    }

    /**
     * Slice the verbatim embedded COSE public-key bytes out of a registration {@code authData} tail.
     *
     * The attested-credential-data block is {@code aaguid(16) | credIdLen(2 BE) | credId | COSE key};
     * webauthn4j's {@link AuthenticatorDataConverter#extractAttestedCredentialData(byte[])} returns that
     * whole block. Stripping the fixed-length prefix ({@code 16 + 2 + credIdLen}) leaves exactly the COSE
     * key on the wire, with no re-serialisation. Returns {@code null} if AT is not set or the layout is
     * too short to parse (caller then falls back to the canonical shadow rather than throwing).
     */
    private byte[] extractEmbeddedCoseKeyBytes(byte[] authData) {
        try {
            byte[] acdBytes = authenticatorDataConverter.extractAttestedCredentialData(authData);
            if (acdBytes == null || acdBytes.length < AuthenticatorData.AAGUID_LENGTH + CRED_ID_LEN_LEN) {
                return null;
            }
            int credIdLen = ((acdBytes[AuthenticatorData.AAGUID_LENGTH] & 0xFF) << 8)
                    | (acdBytes[AuthenticatorData.AAGUID_LENGTH + 1] & 0xFF);
            int coseStart = AuthenticatorData.AAGUID_LENGTH + CRED_ID_LEN_LEN + credIdLen;
            if (coseStart > acdBytes.length) {
                return null;
            }
            return java.util.Arrays.copyOfRange(acdBytes, coseStart, acdBytes.length);
        } catch (RuntimeException e) {
            // A degenerate/unknown attested-cred layout falls back to the canonical shadow; never throw.
            return null;
        }
    }

    @Override
    public byte[] encodeAuthData(AuthenticatorData authenticatorData) {
        // Lossless shadow first: unedited authData (incl. a registration's attested-cred block + a
        // foreign COSE map order) round-trips byte-identically.
        byte[] raw = authenticatorData.raw();
        if (raw != null) {
            return raw;
        }
        byte[] rpIdHash = authenticatorData.rpIdHash();
        if (rpIdHash == null || rpIdHash.length != AuthenticatorData.RP_ID_HASH_LENGTH) {
            throw new IllegalArgumentException("authData rpIdHash must be 32 bytes to encode from fields");
        }
        byte flags = (byte) (authenticatorData.flags() & 0xFF);
        long signCount = authenticatorData.signCount();
        boolean at = (authenticatorData.flags() & AuthenticatorData.FLAG_AT) != 0;
        boolean ed = (authenticatorData.flags() & AuthenticatorData.FLAG_ED) != 0;

        if (!at) {
            // Bare assertion authData (AT=0, no extensions) - exactly 37 bytes. This is the re-sign case;
            // the COSE key is intentionally NOT appended.
            if (ed) {
                throw new UnsupportedOperationException(
                        "from-fields authData with ED set but AT clear is not modelled");
            }
            // Explicit type argument (not diamond): the assignment target below is a concrete parameterised
            // type so the generic AuthenticatorDataConverter#convert(AuthenticatorData<T>) resolves cleanly.
            com.webauthn4j.data.attestation.authenticator.AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> w4j =
                    new com.webauthn4j.data.attestation.authenticator.AuthenticatorData<>(rpIdHash, flags, signCount);
            return authenticatorDataConverter.convert(w4j);
        }

        // Registration authData (AT=1): rpIdHash(32) | flags(1) | signCount(4 BE) | aaguid(16) |
        // credIdLen(2 BE) | credId | COSE pubkey [ | extensions ]. Hand-assembled rather than routed
        // through webauthn4j's converter precisely so the embedded COSE key survives VERBATIM - the
        // converter would canonicalise (reorder/rewidth) the map and invalidate the RP's signature on an
        // unedited key. The COSE key is the verbatim wire shadow when unedited, else the from-fields
        // re-encode (a substituted attack key).
        byte[] aaguid = authenticatorData.aaguid();
        byte[] credentialId = authenticatorData.credentialId();
        CoseKey publicKey = authenticatorData.credentialPublicKey();
        if (aaguid == null || aaguid.length != AuthenticatorData.AAGUID_LENGTH) {
            throw new IllegalArgumentException("registration authData aaguid must be 16 bytes");
        }
        if (credentialId == null) {
            throw new IllegalArgumentException("registration authData requires a credentialId");
        }
        if (credentialId.length > 0xFFFF) {
            throw new IllegalArgumentException("credentialId too long for a 2-byte length prefix");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("registration authData requires a credential public key");
        }
        byte[] coseBytes = publicKey.raw() != null ? publicKey.raw() : encodeCoseKey(publicKey);

        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        bo.write(rpIdHash, 0, rpIdHash.length);
        bo.write(flags & 0xFF);
        writeUint32BE(bo, signCount);
        bo.write(aaguid, 0, aaguid.length);
        bo.write((credentialId.length >>> 8) & 0xFF);
        bo.write(credentialId.length & 0xFF);
        bo.write(credentialId, 0, credentialId.length);
        bo.write(coseBytes, 0, coseBytes.length);
        if (ed) {
            // ED extension bytes are never modelled from fields: decode keeps them only inside the whole-authData
            // raw shadow (see decodeAuthData), and nothing populates a separate extensions field. An unedited
            // ED-set authData therefore round-trips via the raw shadow at the top of this method; a from-fields
            // rebuild of one is unsupported rather than silently dropping the extension map.
            throw new UnsupportedOperationException(
                    "from-fields registration authData with ED set is not modelled");
        }
        return bo.toByteArray();
    }

    // ---- COSE_Key ------------------------------------------------------------------------------

    @Override
    public CoseKey decodeCoseKey(byte[] cbor) {
        CoseKey out;
        try {
            // webauthn4j registers its COSE deserializer on COSEKeyEnvelope (the COSEKey interface itself
            // carries @JsonTypeInfo and is not directly readable from a raw CBOR map). Read the envelope
            // and unwrap.
            COSEKey parsed = cborConverter.readValue(cbor, COSEKeyEnvelope.class).getCOSEKey();
            out = mapCoseKey(parsed);
        } catch (RuntimeException parseFailure) {
            // Never throw on shape (CborCodec contract): an unreadable COSE_Key degrades to raw-only.
            out = new CoseKey();
        }
        // For a standalone COSE_Key decode the input *is* the verbatim shadow.
        out.setRaw(cbor);
        return out;
    }

    @Override
    public byte[] encodeCoseKey(CoseKey coseKey) {
        byte[] raw = coseKey.raw();
        if (raw != null) {
            return raw;
        }
        // From-fields (no verbatim raw): emit an EC2 (ES256/P-256) key. In practice every planted key carries
        // a verbatim `raw` shadow set by its signer's publicCoseKey(), so EC2/OKP(EdDSA)/RSA plants return at
        // the `raw != null` guard above and never reach here; this is the EC2-only from-fields fallback.
        // x/y are expected pre-normalised to 32 bytes by the crypto layer.
        if (coseKey.kty() != COSEKeyType.EC2.getValue()) {
            throw new UnsupportedOperationException(
                    "encodeCoseKey from fields supports EC2 only (got kty=" + coseKey.kty() + ")");
        }
        EC2COSEKey ec2 = new EC2COSEKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                Curve.SECP256R1,
                coseKey.x(),
                coseKey.y());
        return cborConverter.writeValueAsBytes(ec2);
    }

    // ---- mapping -------------------------------------------------------------------------------

    /**
     * Map a webauthn4j {@link COSEKey} onto the tool's {@link CoseKey}. EC2 keys get x/y/curve; OKP (Ed25519)
     * keys get crv + x; RSA keys decode-for-display with {@code kty}/{@code alg} set and the coordinate fields
     * left null (their verbatim bytes still round-trip via the raw shadow). Never throws on key type.
     *
     * The {@code raw} shadow set here is a canonical re-serialisation - a safe default for the
     * standalone {@link #decodeCoseKey} path (which immediately overwrites it with the verbatim input)
     * and for the embedded path (which overwrites it with the exact wire slice via
     * {@link #extractEmbeddedCoseKeyBytes}). It is only the fallback when no verbatim bytes are available.
     */
    private CoseKey mapCoseKey(COSEKey parsed) {
        CoseKey out = new CoseKey();
        if (parsed == null) {
            return out;
        }
        // Canonical re-serialisation as a FALLBACK shadow. Callers with the verbatim wire bytes (the
        // standalone decode + the embedded-key slice) overwrite this, which is what guarantees a foreign
        // producer's COSE map order survives the round-trip byte-identically.
        try {
            out.setRaw(cborConverter.writeValueAsBytes(parsed));
        } catch (RuntimeException ignored) {
            // display-only; tolerate
        }

        COSEAlgorithmIdentifier alg = parsed.getAlgorithm();
        if (alg != null) {
            out.setAlg((int) alg.getValue());
        }

        if (parsed instanceof EC2COSEKey ec2) {
            out.setKty(COSEKeyType.EC2.getValue());
            Curve curve = ec2.getCurve();
            if (curve != null) {
                out.setCrv(curve.getValue());
            }
            out.setX(ec2.getX());
            out.setY(ec2.getY());
        } else if (parsed instanceof EdDSACOSEKey eddsa) {
            // OKP (Ed25519): one coordinate (x = the public key), no y. Decode crv + x so the display shows
            // both (curve + x) instead of dropping them - the EdDSA plant is a first-class path.
            out.setKty(COSEKeyType.OKP.getValue());
            Curve curve = eddsa.getCurve();
            if (curve != null) {
                out.setCrv(curve.getValue());
            }
            out.setX(eddsa.getX());
        } else if (parsed instanceof RSACOSEKey rsa) {
            // Decode n/e for DISPLAY only, so an RSA plant reads as a key instead of a hex blob. Nothing
            // re-encodes them (encodeCoseKey returns the verbatim raw, and its from-fields path is EC2-only),
            // so this cannot move a byte on the wire.
            out.setKty(COSEKeyType.RSA.getValue());
            out.setN(rsa.getN());
            out.setE(rsa.getE());
        } else {
            // symmetric / unknown - best-effort kty from the concrete key when available.
            try {
                out.setKty(parsed.getKeyType().getValue());
            } catch (RuntimeException ignored) {
                // leave kty unset
            }
        }
        return out;
    }

    // ---- minimal CBOR writer (from-fields encode) ----------------------------------------------
    // A surgical, definite-length CBOR emitter for the two structures the tool rebuilds from fields:
    // the attestationObject map and a registration authData's embedded byte/text strings. It is NOT a
    // general CBOR library - only the major types and length encodings these structures use are handled,
    // and map keys are emitted in a caller-fixed (CTAP2-canonical) order. The webauthn4j converters stay
    // the decode authority; this exists solely so a from-fields rebuild preserves verbatim sub-bytes.

    private static final int CBOR_MAJOR_UNSIGNED_INT = 0;
    private static final int CBOR_MAJOR_NEGATIVE_INT = 1;
    private static final int CBOR_MAJOR_BYTE_STRING = 2;
    private static final int CBOR_MAJOR_TEXT_STRING = 3;
    private static final int CBOR_MAJOR_MAP = 5;

    /**
     * Emit a CBOR integer (RFC 8949 major type 0 for non-negative, 1 for negative) - needed only for the
     * COSE algorithm id in a packed {@code attStmt} (a negative id like {@code -7}). A CBOR negative int
     * encodes the argument {@code -1 - value}, so the shared type-header writer produces the shortest form
     * (matching how real producers frame COSE algorithm ids, e.g. {@code -7} → {@code 0x26}).
     */
    private static void writeCborInt(java.io.ByteArrayOutputStream bo, int value) {
        if (value >= 0) {
            writeCborTypeHeader(bo, CBOR_MAJOR_UNSIGNED_INT, value);
        } else {
            writeCborTypeHeader(bo, CBOR_MAJOR_NEGATIVE_INT, -1 - value);
        }
    }

    private static void writeCborTextString(java.io.ByteArrayOutputStream bo, String s) {
        byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeCborTypeHeader(bo, CBOR_MAJOR_TEXT_STRING, b.length);
        bo.write(b, 0, b.length);
    }

    private static void writeCborByteString(java.io.ByteArrayOutputStream bo, byte[] b) {
        writeCborTypeHeader(bo, CBOR_MAJOR_BYTE_STRING, b.length);
        bo.write(b, 0, b.length);
    }

    /**
     * Emit a CBOR major-type header with a definite length argument, using the shortest applicable
     * encoding (matching how real producers - and webauthn4j - frame these fields, which is what keeps a
     * from-fields rebuild byte-identical). Lengths beyond 32 bits are rejected (never reached here).
     */
    private static void writeCborTypeHeader(java.io.ByteArrayOutputStream bo, int majorType, int length) {
        int high = majorType << 5;
        if (length < 0) {
            throw new IllegalArgumentException("negative CBOR length");
        }
        if (length < 24) {
            bo.write(high | length);
        } else if (length < 0x100) {
            bo.write(high | 24); // 1-byte length follows
            bo.write(length & 0xFF);
        } else if (length < 0x10000) {
            bo.write(high | 25); // 2-byte length follows
            bo.write((length >>> 8) & 0xFF);
            bo.write(length & 0xFF);
        } else {
            bo.write(high | 26); // 4-byte length follows
            bo.write((length >>> 24) & 0xFF);
            bo.write((length >>> 16) & 0xFF);
            bo.write((length >>> 8) & 0xFF);
            bo.write(length & 0xFF);
        }
    }

    private static void writeUint32BE(java.io.ByteArrayOutputStream bo, long value) {
        bo.write((int) ((value >>> 24) & 0xFF));
        bo.write((int) ((value >>> 16) & 0xFF));
        bo.write((int) ((value >>> 8) & 0xFF));
        bo.write((int) (value & 0xFF));
    }
}
