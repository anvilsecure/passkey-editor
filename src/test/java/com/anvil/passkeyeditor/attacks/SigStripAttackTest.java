package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.anvil.passkeyeditor.model.CeremonyModel;
import com.anvil.passkeyeditor.model.CeremonyType;

import org.junit.jupiter.api.Test;

class SigStripAttackTest {

    /** A minimal valid-shaped DER ECDSA signature: SEQUENCE { INTEGER 0x11, INTEGER 0x334455 }. */
    private static byte[] sampleDerSig() {
        return new byte[]{0x30, 0x08, 0x02, 0x01, 0x11, 0x02, 0x03, 0x33, 0x44, 0x55};
    }

    private static CeremonyModel getWithSig(byte[] sig) {
        CeremonyModel m = new CeremonyModel(CeremonyType.GET);
        m.setSignature(sig);
        return m;
    }

    @Test
    void defaultModeIsFlip() {
        assertEquals(SigStripAttack.Mode.FLIP, new SigStripAttack().mode());
    }

    @Test
    void flipPreservesLengthAndDerFramingButInvalidatesTrailingByte() {
        byte[] orig = sampleDerSig();
        CeremonyModel m = getWithSig(orig.clone());
        new SigStripAttack().apply(m); // default = FLIP
        byte[] out = m.signature();
        assertEquals(orig.length, out.length, "FLIP must preserve length (stay well-formed)");
        assertEquals(0x30, out[0] & 0xFF, "DER SEQUENCE tag must be untouched (still parseable)");
        assertEquals((byte) (orig[orig.length - 1] ^ 0xFF), out[out.length - 1], "trailing byte flipped");
        assertNotEquals(orig[orig.length - 1], out[out.length - 1]);
    }

    @Test
    void emptyZeroesLength() {
        CeremonyModel m = getWithSig(sampleDerSig());
        new SigStripAttack(SigStripAttack.Mode.EMPTY).apply(m);
        assertEquals(0, m.signature().length);
    }

    @Test
    void zeroedPreservesLengthAllZero() {
        byte[] orig = sampleDerSig();
        CeremonyModel m = getWithSig(orig.clone());
        new SigStripAttack(SigStripAttack.Mode.ZEROED).apply(m);
        assertEquals(orig.length, m.signature().length);
        for (byte b : m.signature()) {
            assertEquals(0, b);
        }
    }

    @Test
    void garbagePreservesLength() {
        byte[] orig = sampleDerSig();
        CeremonyModel m = getWithSig(orig.clone());
        new SigStripAttack(SigStripAttack.Mode.GARBAGE).apply(m);
        assertEquals(orig.length, m.signature().length);
    }

    @Test
    void noOpOnCreate() {
        CeremonyModel m = new CeremonyModel(CeremonyType.CREATE);
        m.setSignature(sampleDerSig());
        new SigStripAttack().apply(m);
        assertArrayEquals(sampleDerSig(), m.signature(), "CREATE has no detached signature - must be untouched");
    }

    @Test
    void noOpOnNullSignature() {
        CeremonyModel m = new CeremonyModel(CeremonyType.GET);
        new SigStripAttack().apply(m); // null signature → no throw, no-op
        assertNull(m.signature());
    }
}
