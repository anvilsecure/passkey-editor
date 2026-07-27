package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.anvil.passkeyeditor.Fixtures;
import com.anvil.passkeyeditor.model.AuthenticatorData;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * the byte-surgical {@code authData} edits the editable view exposes (flag checkboxes, signCount,
 * RP-ID). Each must change exactly its field, leave every other byte untouched, and never mutate the
 * caller's array - so the result can be re-signed over the edited bytes with no re-encode drift.
 */
class AuthDataEditorTest {

    /** A bare UP|UV assertion authData (flags 0x05, signCount 1). */
    private static byte[] assertion() {
        return Fixtures.assertionAuthData("localhost", (byte) 0x05, 1L);
    }

    @Test
    void withFlagsReplacesOnlyTheFlagsByte() {
        byte[] in = assertion();
        byte[] original = in.clone();
        byte[] out = AuthDataEditor.withFlags(in, AuthenticatorData.FLAG_UP); // clear UV: 0x05 -> 0x01

        assertEquals(in.length, out.length, "length preserved");
        assertEquals((byte) 0x01, out[32], "flags byte set to UP only");
        assertArrayEquals(original, in, "input array not mutated (defensive copy)");
        // Every byte except offset 32 is identical.
        for (int i = 0; i < out.length; i++) {
            if (i != 32) {
                assertEquals(in[i], out[i], "byte " + i + " unchanged");
            }
        }
    }

    @Test
    void withSignCountReplacesTheFourBigEndianBytes() {
        byte[] in = assertion();
        byte[] out = AuthDataEditor.withSignCount(in, 0x01020304L);

        assertArrayEquals(new byte[]{0x01, 0x02, 0x03, 0x04}, Arrays.copyOfRange(out, 33, 37),
                "signCount written big-endian at offsets 33-36");
        assertArrayEquals(Arrays.copyOfRange(in, 0, 33), Arrays.copyOfRange(out, 0, 33),
                "rpIdHash + flags untouched");
    }

    @Test
    void withRpIdHashReplacesTheLeading32Bytes() {
        byte[] in = assertion();
        byte[] newHash = new byte[32]; // a distinct 32-byte rpIdHash (SHA-256(new_rpId) on the wire)
        Arrays.fill(newHash, (byte) 0xAB);
        byte[] out = AuthDataEditor.withRpIdHash(in, newHash);

        assertArrayEquals(newHash, Arrays.copyOfRange(out, 0, 32), "rpIdHash replaced");
        assertArrayEquals(Arrays.copyOfRange(in, 32, 37), Arrays.copyOfRange(out, 32, 37),
                "flags + signCount untouched");
    }

    @Test
    void withSignCountAndWithRpIdHashDoNotMutateInput() {
        // The defensive-copy contract is load-bearing: a chained forge re-reads the model's raw authData,
        // so a non-cloning edit would corrupt the next signature. (withFlags is covered above.)
        byte[] in1 = assertion();
        byte[] snap1 = in1.clone();
        AuthDataEditor.withSignCount(in1, 0x09080706L);
        assertArrayEquals(snap1, in1, "withSignCount must not mutate the caller's array");

        byte[] in2 = assertion();
        byte[] snap2 = in2.clone();
        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0x5A);
        AuthDataEditor.withRpIdHash(in2, hash);
        assertArrayEquals(snap2, in2, "withRpIdHash must not mutate the caller's array");
    }

    @Test
    void rejectsTooShortOrBadRpIdHash() {
        assertThrows(IllegalArgumentException.class, () -> AuthDataEditor.withFlags(new byte[10], 0x05),
                "below the 37-byte header cannot be edited");
        assertThrows(IllegalArgumentException.class, () -> AuthDataEditor.withRpIdHash(assertion(), new byte[31]),
                "rpIdHash must be exactly 32 bytes");
    }
}
