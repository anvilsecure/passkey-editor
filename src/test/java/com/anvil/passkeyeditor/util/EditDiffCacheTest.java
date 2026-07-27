package com.anvil.passkeyeditor.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Pins the {@link EditDiffCache} contract that the persistent Proxy-history amber diff relies on: an edited
 * body recorded against its original is retrievable by the edited bytes (the key a read-only history view
 * has), defensively copied, and the obvious no-ops/null-safety hold. Unique bodies per test keep the shared
 * static map from cross-contaminating cases.
 */
final class EditDiffCacheTest {

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void recordThenRetrieveByEditedBody() {
        byte[] original = b("{\"signature\":\"AAAA\"}-rt1");
        byte[] edited = b("{\"signature\":\"BBBB\"}-rt1");
        EditDiffCache.record(edited, original);
        assertArrayEquals(original, EditDiffCache.originalFor(edited));
    }

    @Test
    void originalForReturnsDefensiveCopy() {
        byte[] original = b("orig-copy-2");
        byte[] edited = b("edited-copy-2");
        EditDiffCache.record(edited, original);
        byte[] got = EditDiffCache.originalFor(edited);
        got[0] = (byte) 0xFF; // mutate the returned array
        assertArrayEquals(original, EditDiffCache.originalFor(edited)); // cache stays intact
        assertNotSame(original, EditDiffCache.originalFor(edited));
    }

    @Test
    void unrecordedEditedReturnsNull() {
        assertNull(EditDiffCache.originalFor(b("never-recorded-3")));
    }

    @Test
    void equalBodiesAreNotRecorded() {
        byte[] same = b("identical-4");
        EditDiffCache.record(same, same); // nothing changed → nothing to diff
        assertNull(EditDiffCache.originalFor(same));
    }

    @Test
    void nullArgumentsAreSafeNoOps() {
        assertDoesNotThrow(() -> EditDiffCache.record(null, b("x-5")));
        assertDoesNotThrow(() -> EditDiffCache.record(b("y-5"), null));
        assertNull(EditDiffCache.originalFor(null));
        assertNull(EditDiffCache.originalFor(b("y-5"))); // record(y,null) must not have stored anything
    }
}
