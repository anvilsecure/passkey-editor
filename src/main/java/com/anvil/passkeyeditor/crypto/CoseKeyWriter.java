package com.anvil.passkeyeditor.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Minimal, dependency-free writer for public COSE_Key CBOR (RFC 9052 / 9053 / 8812) - the single source
 * of truth for the byte layout every {@link CoseSigner} puts on the wire as its substitute public key.
 *
 * It emits definite-length maps with labels in canonical order (RFC 8949 §4.2.1: encoded label bytes
 * ascending - positive labels {@code 1,3} before negative {@code -1,-2,-3}) using the shortest length
 * encoding, which is what real authenticators and webauthn4j produce. This is not a general CBOR
 * library: only the three key shapes (EC2 / OKP / RSA) and the integer / byte-string major types they use
 * are handled. The webauthn4j converters stay the decode authority; this exists so a from-scratch attacker
 * key is emitted byte-for-byte the way an RP expects (gated by decoding every shape back under webauthn4j).
 */
final class CoseKeyWriter {

    private static final int MAJOR_UINT = 0;
    private static final int MAJOR_NEGINT = 1;
    private static final int MAJOR_BYTE_STRING = 2;
    private static final int MAJOR_MAP = 5;

    private CoseKeyWriter() {
    }

    /**
     * EC2 public key (RFC 9053 §7.1.1): {@code {1:2(kty), 3:alg, -1:crv, -2:x, -3:y}}.
     *
     * @param coseAlg the COSE algorithm id (e.g. {@code -7} ES256, {@code -35} ES384, {@code -36} ES512)
     * @param coseCrv the COSE curve id (1 P-256, 2 P-384, 3 P-521)
     * @param x       the fixed-width big-endian x-coordinate
     * @param y       the fixed-width big-endian y-coordinate
     */
    static byte[] ec2(int coseAlg, int coseCrv, byte[] x, byte[] y) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        writeArg(bo, MAJOR_MAP, 5);
        writeInt(bo, 1);
        writeInt(bo, 2);            // kty = EC2
        writeInt(bo, 3);
        writeInt(bo, coseAlg);      // alg
        writeInt(bo, -1);
        writeInt(bo, coseCrv);      // crv
        writeInt(bo, -2);
        writeByteString(bo, x);     // x
        writeInt(bo, -3);
        writeByteString(bo, y);     // y
        return bo.toByteArray();
    }

    /**
     * OKP public key (RFC 8812 §2): {@code {1:1(kty), 3:alg, -1:crv, -2:x}}.
     *
     * @param coseAlg the COSE algorithm id ({@code -8} EdDSA)
     * @param coseCrv the COSE curve id (6 Ed25519)
     * @param x       the raw public key bytes
     */
    static byte[] okp(int coseAlg, int coseCrv, byte[] x) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        writeArg(bo, MAJOR_MAP, 4);
        writeInt(bo, 1);
        writeInt(bo, 1);            // kty = OKP
        writeInt(bo, 3);
        writeInt(bo, coseAlg);      // alg
        writeInt(bo, -1);
        writeInt(bo, coseCrv);      // crv
        writeInt(bo, -2);
        writeByteString(bo, x);     // x
        return bo.toByteArray();
    }

    /**
     * RSA public key (RFC 8812 §2): {@code {1:3(kty), 3:alg, -1:n, -2:e}}.
     *
     * @param coseAlg the COSE algorithm id ({@code -257} RS256, {@code -258} RS384, {@code -259} RS512,
     *                {@code -65535} RS1)
     * @param n       the modulus, minimal unsigned big-endian
     * @param e       the public exponent, minimal unsigned big-endian
     */
    static byte[] rsa(int coseAlg, byte[] n, byte[] e) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        writeArg(bo, MAJOR_MAP, 4);
        writeInt(bo, 1);
        writeInt(bo, 3);            // kty = RSA
        writeInt(bo, 3);
        writeInt(bo, coseAlg);      // alg
        writeInt(bo, -1);
        writeByteString(bo, n);     // n
        writeInt(bo, -2);
        writeByteString(bo, e);     // e
        return bo.toByteArray();
    }

    /**
     * The minimal unsigned big-endian encoding of a positive integer (RFC 8230 §4: minimum octets) - the
     * RSA bignum form for COSE {@code n}/{@code e}. Drops the leading {@code 0x00} sign byte
     * {@link BigInteger#toByteArray()} prepends when the top magnitude bit is set, and any other redundant
     * leading zeros, keeping at least one octet.
     */
    static byte[] minimalUnsigned(BigInteger value) {
        byte[] b = value.toByteArray();
        int start = 0;
        while (start < b.length - 1 && b[start] == 0x00) {
            start++;
        }
        if (start == 0) {
            return b;
        }
        byte[] out = new byte[b.length - start];
        System.arraycopy(b, start, out, 0, out.length);
        return out;
    }

    /**
     * Left-pad / normalise a big-endian unsigned integer to exactly {@code len} bytes for a COSE EC2 field
     * element (RFC 9053). COSE coordinates only - never DER signature r/s. Handles the three shapes
     * {@link BigInteger#toByteArray()} produces for a non-negative value: an exact {@code len}-byte value
     * (as-is), a {@code len+1}-byte value with a {@code 0x00} two's-complement sign byte (stripped), and a
     * short value (left-padded with zeros to fill {@code len}, preserving leading zeros). Anything wider
     * cannot be a coordinate of this curve. Shared by every EC2 signer so the normalisation cannot diverge.
     */
    static byte[] toFixed(byte[] coordinate, int len) {
        int n = coordinate.length;
        if (n == len) {
            return coordinate;
        }
        if (n == len + 1 && coordinate[0] == 0x00) {
            return Arrays.copyOfRange(coordinate, 1, n);
        }
        if (n < len) {
            byte[] out = new byte[len];
            System.arraycopy(coordinate, 0, out, len - n, n);
            return out;
        }
        throw new IllegalArgumentException(
                "coordinate does not fit a " + len + "-byte COSE EC2 field element (length=" + n + ")");
    }

    /** Write a CBOR integer (a map label or small value), encoding negatives as major type 1. */
    static void writeInt(ByteArrayOutputStream bo, int value) {
        if (value >= 0) {
            writeArg(bo, MAJOR_UINT, value);
        } else {
            // CBOR negative integer: the encoded argument is (-1 - value), e.g. -7 -> 6, -257 -> 256.
            writeArg(bo, MAJOR_NEGINT, -1L - value);
        }
    }

    /** Write a CBOR byte string (major type 2) with the shortest definite-length header. */
    static void writeByteString(ByteArrayOutputStream bo, byte[] b) {
        writeArg(bo, MAJOR_BYTE_STRING, b.length);
        bo.write(b, 0, b.length);
    }

    /** Emit {@code majorType} with {@code arg} using the shortest definite-length encoding (RFC 8949 §3). */
    private static void writeArg(ByteArrayOutputStream bo, int majorType, long arg) {
        if (arg < 0) {
            throw new IllegalArgumentException("negative CBOR argument");
        }
        int h = majorType << 5;
        if (arg < 24) {
            bo.write(h | (int) arg);
        } else if (arg < 0x100L) {
            bo.write(h | 24);
            bo.write((int) (arg & 0xFF));
        } else if (arg < 0x10000L) {
            bo.write(h | 25);
            bo.write((int) ((arg >>> 8) & 0xFF));
            bo.write((int) (arg & 0xFF));
        } else if (arg < 0x100000000L) {
            bo.write(h | 26);
            bo.write((int) ((arg >>> 24) & 0xFF));
            bo.write((int) ((arg >>> 16) & 0xFF));
            bo.write((int) ((arg >>> 8) & 0xFF));
            bo.write((int) (arg & 0xFF));
        } else {
            bo.write(h | 27);
            for (int shift = 56; shift >= 0; shift -= 8) {
                bo.write((int) ((arg >>> shift) & 0xFF));
            }
        }
    }
}
