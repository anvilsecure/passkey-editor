package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.anvil.passkeyeditor.model.CoseKey;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CoseKeyWriter} - the shared COSE_Key CBOR emitter. Two kinds of check: (1) the EC2
 * path is byte-identical to the proven, independently-written {@link Es256Signer#coseKeyBytes} encoder
 * (so the generalisation didn't drift from the encoding ES256 has shipped with), and (2) every COSE
 * algorithm label this tool emits encodes to the exact canonical CBOR negative-integer bytes.
 */
class CoseKeyWriterTest {

    private static byte[] enc(int value) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        CoseKeyWriter.writeInt(bo, value);
        return bo.toByteArray();
    }

    private static byte[] bstr(byte[] b) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        CoseKeyWriter.writeByteString(bo, b);
        return bo.toByteArray();
    }

    @Test
    void ec2WithEs256ParamsMatchesProvenEs256SignerEncoding() {
        CoseKey es256 = Es256Signer.generate().publicCoseKey();
        byte[] x = es256.x();
        byte[] y = es256.y();
        // The shared writer must reproduce, byte-for-byte, the hand-rolled 77-byte encoding Es256Signer has
        // shipped with on main - the cross-check that the generalisation is faithful.
        assertArrayEquals(Es256Signer.coseKeyBytes(x, y), CoseKeyWriter.ec2(-7, 1, x, y),
                "CoseKeyWriter.ec2 must match Es256Signer.coseKeyBytes for ES256/P-256");
    }

    @Test
    void negativeAlgorithmLabelsEncodeToCanonicalCbor() {
        assertArrayEquals(new byte[]{(byte) 0x26}, enc(-7), "ES256 (-7)");
        assertArrayEquals(new byte[]{(byte) 0x27}, enc(-8), "EdDSA (-8)");
        assertArrayEquals(new byte[]{(byte) 0x38, (byte) 0x22}, enc(-35), "ES384 (-35)");
        assertArrayEquals(new byte[]{(byte) 0x38, (byte) 0x23}, enc(-36), "ES512 (-36)");
        assertArrayEquals(new byte[]{(byte) 0x38, (byte) 0x24}, enc(-37), "PS256 (-37)");
        assertArrayEquals(new byte[]{(byte) 0x38, (byte) 0x25}, enc(-38), "PS384 (-38)");
        assertArrayEquals(new byte[]{(byte) 0x38, (byte) 0x26}, enc(-39), "PS512 (-39)");
        assertArrayEquals(new byte[]{(byte) 0x39, (byte) 0x01, (byte) 0x00}, enc(-257), "RS256 (-257)");
        assertArrayEquals(new byte[]{(byte) 0x39, (byte) 0x01, (byte) 0x01}, enc(-258), "RS384 (-258)");
        assertArrayEquals(new byte[]{(byte) 0x39, (byte) 0x01, (byte) 0x02}, enc(-259), "RS512 (-259)");
        assertArrayEquals(new byte[]{(byte) 0x39, (byte) 0xFF, (byte) 0xFE}, enc(-65535), "RS1 (-65535)");
    }

    @Test
    void positiveLabelsAndValuesAreSingleByteSmallInts() {
        assertArrayEquals(new byte[]{0x01}, enc(1), "kty/crv label 1");
        assertArrayEquals(new byte[]{0x02}, enc(2), "EC2 kty value 2");
        assertArrayEquals(new byte[]{0x03}, enc(3), "RSA kty value / alg label 3");
        assertArrayEquals(new byte[]{0x06}, enc(6), "Ed25519 crv value 6");
    }

    @Test
    void byteStringHeadersUseShortestLength() {
        // 32-byte coord -> 0x58 0x20; 3-byte exponent -> 0x43; 256-byte modulus -> 0x59 0x01 0x00.
        assertArrayEquals(new byte[]{(byte) 0x58, (byte) 0x20}, Arrays.copyOf(bstr(new byte[32]), 2), "bstr(32)");
        assertEquals((byte) 0x43, bstr(new byte[3])[0], "bstr(3) header");
        assertArrayEquals(new byte[]{(byte) 0x59, (byte) 0x01, (byte) 0x00}, Arrays.copyOf(bstr(new byte[256]), 3),
                "bstr(256) header");
    }
}
