package com.anvil.passkeyeditor.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * toFixed32.
 *
 * COSE EC2 coordinates are fixed 32 bytes. {@link Es256Signer#toFixed32(byte[])} normalises a
 * big-endian magnitude to exactly 32 bytes: {@code len==32} as-is; {@code len==33 && b[0]==0} strip the
 * two's-complement sign byte; {@code len<32} left-pad with zeros to fill 32; else throw. (For COSE
 * coordinates only - never DER signature r/s.)
 *
 * The headline gate: a coordinate whose top bytes are zero must left-pad so the 32-byte result keeps
 * those leading zeros (a naive {@code BigInteger.toByteArray()} would drop them and yield a short array,
 * corrupting the COSE key / breaking the 77-byte template).
 */
class ToFixed32Test {

    private static final int LEN = 32;

    /**
     * Headline: a 30-byte magnitude (so the 32-byte form has two leading zero bytes) left-pads to
     * exactly 32 bytes, preserving the leading zeros and the numeric value.
     */
    @Test
    void twoLeadingZeroCoordinateLeftPadsToFill32() {
        // 30 significant bytes => value < 2^240 => its 32-byte big-endian form starts 00 00 ...
        byte[] thirty = new byte[30];
        thirty[0] = 0x12; // non-zero MSB of the magnitude so it really is 30 bytes wide
        for (int i = 1; i < thirty.length; i++) {
            thirty[i] = (byte) (i * 7 + 1);
        }

        byte[] fixed = Es256Signer.toFixed32(thirty);

        assertEquals(LEN, fixed.length, "must fill exactly 32 bytes");
        assertEquals(0x00, fixed[0] & 0xFF, "byte 0 must be a padded leading zero");
        assertEquals(0x00, fixed[1] & 0xFF, "byte 1 must be a padded leading zero");
        assertEquals(0x12, fixed[2] & 0xFF, "the original MSB must sit at offset 2 after two-zero pad");
        // numeric value preserved
        assertEquals(new BigInteger(1, thirty), new BigInteger(1, fixed), "left-pad must preserve the value");
        // the tail bytes are the original magnitude verbatim
        byte[] tail = new byte[30];
        System.arraycopy(fixed, 2, tail, 0, 30);
        assertArrayEquals(thirty, tail, "the 30 magnitude bytes must be copied verbatim into the low end");
    }

    /**
     * A real-world trigger: {@code BigInteger.toByteArray()} of a value whose high byte has the top bit
     * clear and that is one byte short still left-pads correctly.
     */
    @Test
    void shortBigIntegerMagnitudeLeftPads() {
        // A 31-byte value (top bit of MSB clear): BigInteger#toByteArray returns 31 bytes; pad to 32.
        BigInteger v = BigInteger.ONE.shiftLeft(240).subtract(BigInteger.ONE); // 2^240 - 1 => 31 bytes
        byte[] raw = v.toByteArray();
        // Guard the premise of the test.
        org.junit.jupiter.api.Assertions.assertEquals(31, raw.length, "premise: this value is 31 bytes");

        byte[] fixed = Es256Signer.toFixed32(raw);
        assertEquals(LEN, fixed.length);
        assertEquals(0x00, fixed[0] & 0xFF, "the single missing high byte is zero-padded");
        assertEquals(v, new BigInteger(1, fixed));
    }

    /** An exact 32-byte coordinate is returned unchanged. */
    @Test
    void exact32ReturnedAsIs() {
        byte[] thirtyTwo = new byte[LEN];
        for (int i = 0; i < LEN; i++) {
            thirtyTwo[i] = (byte) (0x80 + i); // high top bit, full width
        }
        byte[] fixed = Es256Signer.toFixed32(thirtyTwo);
        assertEquals(LEN, fixed.length);
        assertArrayEquals(thirtyTwo, fixed);
    }

    /**
     * A 33-byte {@code BigInteger.toByteArray()} output with a leading {@code 0x00} sign byte (the value's
     * MSB has its top bit set) drops the sign byte to land on 32.
     */
    @Test
    void thirtyThreeWithLeadingZeroSignByteIsStripped() {
        // value with top bit of byte set => BigInteger prepends 0x00 => 33 bytes
        byte[] magnitude = new byte[LEN];
        magnitude[0] = (byte) 0xFF;
        for (int i = 1; i < LEN; i++) {
            magnitude[i] = (byte) i;
        }
        BigInteger v = new BigInteger(1, magnitude);
        byte[] raw = v.toByteArray();
        assertEquals(LEN + 1, raw.length, "premise: BigInteger prepends a 0x00 sign byte => 33 bytes");
        assertEquals(0x00, raw[0] & 0xFF);

        byte[] fixed = Es256Signer.toFixed32(raw);
        assertEquals(LEN, fixed.length);
        assertArrayEquals(magnitude, fixed, "stripping the sign byte recovers the 32-byte magnitude");
    }

    /** A genuine 33-byte magnitude (non-zero leading byte) cannot be a P-256 coordinate → throws. */
    @Test
    void oversize33NonZeroLeadingByteRejected() {
        byte[] tooBig = new byte[LEN + 1];
        tooBig[0] = 0x01; // non-zero leading byte, not a sign byte
        assertThrows(IllegalArgumentException.class, () -> Es256Signer.toFixed32(tooBig));
    }

    /** Anything wider than 33 bytes is rejected. */
    @Test
    void wayOversizeRejected() {
        assertThrows(IllegalArgumentException.class, () -> Es256Signer.toFixed32(new byte[40]));
    }

    /**
     * End-to-end: the COSE key template embeds the fixed coordinates so the encoded key is the canonical
     * 77 bytes even when a coordinate was short - proves toFixed32 plugs into the real encode path.
     */
    @Test
    void fixedCoordsProduceCanonical77ByteCoseKey() {
        byte[] x = Es256Signer.toFixed32(new byte[]{0x12, 0x34}); // tiny => left-padded to 32
        byte[] y = Es256Signer.toFixed32(new byte[]{0x56, 0x78});
        byte[] cose = Es256Signer.coseKeyBytes(x, y);
        assertEquals(77, cose.length, "canonical EC2 COSE_Key is 77 bytes");
        // header A5 01 02 03 26 20 01 21 58 20 ...
        String hexHead = HexFormat.of().formatHex(cose, 0, 10);
        assertEquals("a501020326200121" + "5820", hexHead, "canonical COSE_Key header");
    }
}
