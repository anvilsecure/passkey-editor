package com.anvil.passkeyeditor;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.authenticator.EdDSACOSEKey;
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

/**
 * Programmatic, zero-PII WebAuthn fixtures for the headless tests.
 *
 * Everything here is minted fresh from JDK SunEC + webauthn4j's low-level converters (the
 * same converters the tool uses), so a fixture is a genuine, spec-shaped WebAuthn vector rather than a
 * hand-rolled byte blob - and is fully attributable to us (no captured RP traffic, no PII).
 *
 *   - {@link #assertionAuthData()} - a bare 37-byte assertion authData (AT=0, no extensions).
 *   - {@link #registrationAttestationObject(KeyPair)} - a {@code fmt="none"} registration attestation
 *       object whose authData carries the attested credential data + an EC2/P-256 COSE public key
 *       (AT flag set), i.e. a real {@code webauthn.create} attestationObject.
 *   - {@link #clientDataJson(String)} - a real {@code clientDataJSON} wire-byte blob.
 */
public final class Fixtures {

    /** A stable, obviously-synthetic AAGUID (all 0x11) so fixtures are attributable to us. */
    public static final UUID FIXTURE_AAGUID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();
    private static final AuthenticatorDataConverter AUTH_DATA_CONVERTER =
            new AuthenticatorDataConverter(OBJECT_CONVERTER);
    private static final AttestationObjectConverter ATTESTATION_OBJECT_CONVERTER =
            new AttestationObjectConverter(OBJECT_CONVERTER);

    private Fixtures() {
    }

    /** Generate a fresh secp256r1 keypair (JDK SunEC). */
    public static KeyPair generateP256() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("P-256 keygen unavailable", e);
        }
    }

    /**
     * A bare assertion authData: {@code rpIdHash(32) | flags(1) | signCount(4 BE)}, exactly 37 bytes,
     * AT=0 and ED=0. Built through webauthn4j's converter so it is byte-for-byte what the lib emits.
     *
     * @param rpId      the RP id whose SHA-256 becomes the rpIdHash
     * @param flags     the flags byte (e.g. UP|UV = 0x05)
     * @param signCount the signature counter
     */
    public static byte[] assertionAuthData(String rpId, byte flags, long signCount) {
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> ad =
                new AuthenticatorData<>(sha256(rpId), flags, signCount);
        return AUTH_DATA_CONVERTER.convert(ad);
    }

    /** A default UP|UV assertion authData for "example.org", signCount 1. */
    public static byte[] assertionAuthData() {
        return assertionAuthData("example.org", (byte) 0x05, 1L);
    }

    /**
     * A {@code fmt="none"} registration attestation object: a CBOR map
     * {@code {"fmt":"none","attStmt":{},"authData": <authData with AT set + EC2 COSE key>}}.
     * This is a genuine {@code webauthn.create} attestationObject built via the converters.
     *
     * @param credentialKeyPair the credential keypair whose public key is embedded as the COSE key
     */
    public static byte[] registrationAttestationObject(KeyPair credentialKeyPair) {
        EC2COSEKey coseKey = EC2COSEKey.create(credentialKeyPair, COSEAlgorithmIdentifier.ES256);
        byte[] credentialId = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        AttestedCredentialData acd =
                new AttestedCredentialData(new AAGUID(FIXTURE_AAGUID), credentialId, coseKey);

        // flags: UP(0x01) | UV(0x04) | AT(0x40) = 0x45
        byte flags = (byte) (0x01 | 0x04 | 0x40);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> ad =
                new AuthenticatorData<>(sha256("example.org"), flags, 0L, acd);

        AttestationObject att = new AttestationObject(ad, new NoneAttestationStatement());
        return ATTESTATION_OBJECT_CONVERTER.convertToBytes(att);
    }

    // ---- decode-robustness fixtures ------------------------------------------------------
    // Real RPs send key types and attestation formats the baseline never emits (it is EC2/none only). These
    // mint genuine, spec-shaped registration objects with an RSA / Ed25519 (OKP) credential public key,
    // a non-none (packed) attestation statement, and an unknown vendor fmt, so decode-for-display can be
    // proven to never throw and to degrade gracefully on all of them.

    /** Generate a fresh 2048-bit RSA keypair (JDK). */
    public static KeyPair generateRsa2048() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA keygen unavailable", e);
        }
    }

    /** Generate a fresh Ed25519 keypair (JDK SunEC, EdDSA). */
    public static KeyPair generateEd25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 keygen unavailable", e);
        }
    }

    /**
     * A {@code fmt="none"} registration attestation object whose embedded credential public key is an
     * RSA (RS256) COSE key - a key type the EC2-only baseline never produces.
     */
    public static byte[] rsaRegistrationAttestationObject() {
        RSACOSEKey key = RSACOSEKey.create(
                (RSAPublicKey) generateRsa2048().getPublic(), COSEAlgorithmIdentifier.RS256);
        return registrationAttestationObject(key, new NoneAttestationStatement());
    }

    /**
     * A {@code fmt="none"} registration attestation object whose embedded credential public key is an
     * Ed25519 (OKP / EdDSA) COSE key.
     */
    public static byte[] ed25519RegistrationAttestationObject() {
        EdDSACOSEKey key = EdDSACOSEKey.create(
                (EdECPublicKey) generateEd25519().getPublic(), COSEAlgorithmIdentifier.EdDSA);
        return registrationAttestationObject(key, new NoneAttestationStatement());
    }

    /**
     * A registration attestation object with a non-none ({@code packed}) attestation statement
     * (EC2 credential key). The packed sig is a well-formed-but-meaningless DER blob and x5c is null
     * (self-attestation shape): decode-for-display reads structure only, never the crypto.
     */
    public static byte[] packedRegistrationAttestationObject() {
        EC2COSEKey key = EC2COSEKey.create(generateP256(), COSEAlgorithmIdentifier.ES256);
        byte[] dummySig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}; // valid DER framing, no meaning
        PackedAttestationStatement stmt =
                new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, dummySig, null);
        return registrationAttestationObject(key, stmt);
    }

    /**
     * Build a {@code webauthn.create} attestation object from an arbitrary COSE credential key + an
     * arbitrary attestation statement, via webauthn4j's converters (UP|UV|AT flags, signCount 0).
     */
    private static byte[] registrationAttestationObject(COSEKey credentialKey, AttestationStatement stmt) {
        byte[] credentialId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        AttestedCredentialData acd =
                new AttestedCredentialData(new AAGUID(FIXTURE_AAGUID), credentialId, credentialKey);
        byte flags = (byte) (0x01 | 0x04 | 0x40); // UP|UV|AT
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> ad =
                new AuthenticatorData<>(sha256("example.org"), flags, 0L, acd);
        return ATTESTATION_OBJECT_CONVERTER.convertToBytes(new AttestationObject(ad, stmt));
    }

    /**
     * Hand-assemble an attestation object {@code { "fmt": <fmt>, "attStmt": <attStmt>, "authData": <ad> }}
     * in CTAP2-canonical key order - used both to mint an unknown-fmt fixture (which webauthn4j's
     * typed builder cannot represent) and as an independent oracle for the from-fields encoder.
     */
    public static byte[] attestationObjectWithFmt(String fmt, byte[] attStmtCbor, byte[] authData) {
        try {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            bo.write(0xA3);                  // map(3)
            writeCborText(bo, "fmt");
            writeCborText(bo, fmt);
            writeCborText(bo, "attStmt");
            bo.write(attStmtCbor);           // verbatim attStmt CBOR
            writeCborText(bo, "authData");
            writeCborBytes(bo, authData);
            return bo.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An attestation object whose {@code fmt} is an unknown vendor string (must degrade to null fmt). */
    public static byte[] unknownFmtAttestationObject() {
        byte[] authData = registrationAuthDataWithRawCoseKey(
                foreignOrderEc2CoseKey(generateP256()), new byte[]{0x01, 0x02, 0x03, 0x04});
        return attestationObjectWithFmt("vendor-unknown-fmt", new byte[]{(byte) 0xA0}, authData);
    }

    /** Write a CBOR text string (major type 3) with a short (&lt;24) or 1-byte length. */
    private static void writeCborText(java.io.ByteArrayOutputStream bo, String s) {
        byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (b.length < 24) {
            bo.write(0x60 | b.length);
        } else {
            bo.write(0x78);
            bo.write(b.length & 0xFF);
        }
        bo.write(b, 0, b.length);
    }

    /** Write a CBOR byte string (major type 2) with the shortest applicable length encoding. */
    private static void writeCborBytes(java.io.ByteArrayOutputStream bo, byte[] b) {
        if (b.length < 24) {
            bo.write(0x40 | b.length);
        } else if (b.length < 0x100) {
            bo.write(0x58);
            bo.write(b.length & 0xFF);
        } else {
            bo.write(0x59);
            bo.write((b.length >>> 8) & 0xFF);
            bo.write(b.length & 0xFF);
        }
        bo.write(b, 0, b.length);
    }

    /** A real {@code clientDataJSON} blob for the given ceremony type. */
    public static byte[] clientDataJson(String type) {
        // A normal, well-formed clientDataJSON. base64url challenge, https origin, crossOrigin flag.
        String json = "{\"type\":\"" + type + "\","
                + "\"challenge\":\"" + "Y2hhbGxlbmdlLTEyMzQ1Njc4OTA" + "\","
                + "\"origin\":\"https://example.org\","
                + "\"crossOrigin\":false}";
        return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** base64url (no padding) - the on-the-wire encoding the WebAuthn JS API uses for these fields. */
    public static String b64url(byte[] raw) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * A realistic registration ({@code webauthn.create}) request body in wire form: a JSON
     * envelope nesting base64url-encoded {@code clientDataJSON} + {@code attestationObject} under
     * {@code "response"} - exactly what a browser POSTs to a {@code /verify-registration} endpoint. The
     * clientDataJSON {@code type} marker is therefore base64-wrapped (base64url has no '.', so the
     * literal "webauthn.create" cannot appear) - which is the whole point: detection must recognise this
     * without the literal marker.
     */
    public static String registrationRequestBody() {
        String cdj = b64url(clientDataJson("webauthn.create"));
        String att = b64url(registrationAttestationObject(generateP256()));
        return "{\"id\":\"Y3JlZA\",\"rawId\":\"Y3JlZA\",\"type\":\"public-key\","
                + "\"response\":{\"clientDataJSON\":\"" + cdj + "\","
                + "\"attestationObject\":\"" + att + "\","
                + "\"transports\":[\"internal\"]}}";
    }

    /**
     * A realistic authentication ({@code webauthn.get}) request body in wire form: base64url
     * {@code clientDataJSON} + {@code authenticatorData} + {@code signature} nested under
     * {@code "response"} - what a browser POSTs to {@code /verify-authentication}.
     */
    public static String authenticationRequestBody() {
        String cdj = b64url(clientDataJson("webauthn.get"));
        String ad = b64url(assertionAuthData());
        String sig = b64url(new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01});
        return "{\"id\":\"Y3JlZA\",\"rawId\":\"Y3JlZA\",\"type\":\"public-key\","
                + "\"response\":{\"clientDataJSON\":\"" + cdj + "\","
                + "\"authenticatorData\":\"" + ad + "\","
                + "\"signature\":\"" + sig + "\"}}";
    }

    // ---- options-phase fixtures ----------------------------------------------------------
    // The generate-*-options RESPONSE (server -> client) where the UV policy lives. Modeled on the
    // SimpleWebAuthn output: authenticatorSelection {residentKey: discouraged, userVerification:
    // preferred}, supportedAlgorithmIDs [-7,-257], attestation none. The UV-downgrade attack edits the
    // single userVerification member (top-level for auth, nested under authenticatorSelection for reg).

    /** A base64url challenge of realistic length (no padding), distinct per phase string. */
    private static String optionsChallenge(String salt) {
        return b64url(sha256("challenge-" + salt)); // 43 chars, base64url
    }

    /**
     * A {@code generate-authentication-options} response with the given {@code userVerification} policy
     * at the top level (the auth-options location).
     */
    public static String authenticationOptionsResponse(String userVerification) {
        return "{\"challenge\":\"" + optionsChallenge("auth") + "\","
                + "\"timeout\":60000,"
                + "\"rpId\":\"localhost\","
                + "\"allowCredentials\":[{\"id\":\"Y3JlZA\",\"type\":\"public-key\"}],"
                + "\"userVerification\":\"" + userVerification + "\"}";
    }

    /** A {@code generate-authentication-options} response with the default {@code "preferred"} policy. */
    public static String authenticationOptionsResponse() {
        return authenticationOptionsResponse("preferred");
    }

    /**
     * A {@code generate-registration-options} response with the given {@code userVerification} policy
     * nested under {@code authenticatorSelection} (the reg-options location).
     */
    public static String registrationOptionsResponse(String userVerification) {
        return "{\"challenge\":\"" + optionsChallenge("reg") + "\","
                + "\"rp\":{\"name\":\"Passkey Editor Lab\",\"id\":\"localhost\"},"
                + "\"user\":{\"id\":\"aW50ZXJuYWxVc2VySWQ\",\"name\":\"user@localhost\",\"displayName\":\"\"},"
                + "\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}],"
                + "\"timeout\":60000,"
                + "\"attestation\":\"none\","
                + "\"excludeCredentials\":[],"
                + "\"authenticatorSelection\":{\"residentKey\":\"discouraged\",\"userVerification\":\""
                + userVerification + "\"},"
                + "\"extensions\":{\"credProps\":true}}";
    }

    /** A {@code generate-registration-options} response with the default {@code "preferred"} policy. */
    public static String registrationOptionsResponse() {
        return registrationOptionsResponse("preferred");
    }

    /**
     * A COSE EC2/P-256 public key encoded in deliberately foreign map order
     * {@code (alg(3), kty(1), x(-2), crv(-1), y(-3))} - i.e. NOT webauthn4j's canonical
     * {@code (kty, alg, crv, x, y)} order. Used to prove the codec preserves the verbatim wire order of
     * an embedded credential public key rather than canonicalising it.
     *
     * @param keyPair the P-256 keypair whose public point is encoded
     * @return CBOR bytes of a 5-entry COSE_Key map in non-canonical label order
     */
    public static byte[] foreignOrderEc2CoseKey(KeyPair keyPair) {
        java.security.interfaces.ECPublicKey pub =
                (java.security.interfaces.ECPublicKey) keyPair.getPublic();
        byte[] x = fixed32(pub.getW().getAffineX().toByteArray());
        byte[] y = fixed32(pub.getW().getAffineY().toByteArray());
        try {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            bo.write(0xA5);                              // map(5)
            bo.write(0x03); bo.write(0x26);              // alg(3)  = -7 (ES256)   -- foreign: alg first
            bo.write(0x01); bo.write(0x02);              // kty(1)  = 2  (EC2)
            bo.write(0x21); bo.write(0x58); bo.write(0x20); bo.write(x); // x(-2) = bstr(32)
            bo.write(0x20); bo.write(0x01);              // crv(-1) = 1  (P-256)
            bo.write(0x22); bo.write(0x58); bo.write(0x20); bo.write(y); // y(-3) = bstr(32)
            return bo.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Assemble a registration {@code authData} (AT set) directly from raw bytes, embedding the given
     * verbatim COSE key bytes unchanged: {@code rpIdHash(32) | flags(0x45) | signCount(4 BE=0) |
     * aaguid(16) | credIdLen(2 BE) | credId | coseKey}. Bypasses webauthn4j's encoder so the embedded
     * COSE bytes survive byte-for-byte (the encoder would canonicalise them).
     */
    public static byte[] registrationAuthDataWithRawCoseKey(byte[] coseKey, byte[] credId) {
        try {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            bo.write(sha256("example.org"));             // rpIdHash(32)
            bo.write(0x01 | 0x04 | 0x40);                // flags: UP|UV|AT = 0x45
            bo.write(new byte[]{0x00, 0x00, 0x00, 0x00}); // signCount(4 BE) = 0
            bo.write(new byte[16]);                       // aaguid(16) = all-zero (synthetic)
            bo.write((credId.length >> 8) & 0xFF);        // credIdLen high
            bo.write(credId.length & 0xFF);               // credIdLen low
            bo.write(credId);                             // credId
            bo.write(coseKey);                            // verbatim COSE key
            return bo.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Left-pad/strip a BigInteger#toByteArray() result to a fixed 32-byte big-endian coordinate. */
    private static byte[] fixed32(byte[] b) {
        if (b.length == 32) {
            return b;
        }
        if (b.length == 33 && b[0] == 0x00) {
            return java.util.Arrays.copyOfRange(b, 1, 33);
        }
        if (b.length < 32) {
            byte[] out = new byte[32];
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
            return out;
        }
        throw new IllegalArgumentException("coordinate too wide: " + b.length);
    }

    /** Decode a COSE_Key CBOR back into a webauthn4j {@link COSEKey} (the independent decode path). */
    public static COSEKey decodeCoseKey(byte[] cbor) {
        return OBJECT_CONVERTER.getCborConverter()
                .readValue(cbor, com.webauthn4j.converter.jackson.deserializer.cbor.COSEKeyEnvelope.class)
                .getCOSEKey();
    }

    static byte[] sha256(String s) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256")
                    .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
