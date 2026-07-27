package com.anvil.passkeyeditor.util;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Process-wide, bounded cache mapping SHA-256(edited request body) → the pristine ORIGINAL body,
 * recorded at edit time by everything that produces an edited ceremony request: the manual Ceremony editor
 * (on send) and the AUTO handler (at its Proxy rewrite).
 *
 * Why it exists: a read-only editor instance (the Passkey Editor tab opened on a Proxy-history
 * row) is brand-new and holds no original of its own, and Burp's {@code ProxyHttpRequestResponse.request()}
 * returns the already-edited body for extension-modified rows (so it cannot supply the pre-edit original).
 * The read-only view therefore looks up the edited body it is bound to here to recover the original and
 * paint the persistent amber diff - no Original/Edited toggling. The key is exact: the history row binds to
 * the same bytes that were sent, which is the same body keyed here at edit time.
 *
 * Burp-free + thread-safe (writers may run off the EDT). Bounded LRU; cleared when the extension's
 * classloader is unloaded (so only edits made since the current load are diffable - an accepted limit).
 */
public final class EditDiffCache {

    private static final int MAX_ENTRIES = 512;

    private static final Map<String, byte[]> ORIGINAL_BY_EDITED = Collections.synchronizedMap(
            new LinkedHashMap<>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private EditDiffCache() {
    }

    /** Record {@code edited → original}. No-op when either is null or they are equal (nothing to diff). */
    public static void record(byte[] editedBody, byte[] originalBody) {
        if (editedBody == null || originalBody == null || Arrays.equals(editedBody, originalBody)) {
            return;
        }
        ORIGINAL_BY_EDITED.put(sha256Hex(editedBody), originalBody.clone());
    }

    /** The original body recorded for {@code editedBody}, or {@code null} if none is cached. */
    public static byte[] originalFor(byte[] editedBody) {
        if (editedBody == null) {
            return null;
        }
        byte[] original = ORIGINAL_BY_EDITED.get(sha256Hex(editedBody));
        return original != null ? original.clone() : null;
    }

    /** Drop every cached mapping - called on extension unload so no ceremony body material lingers in the JVM. */
    public static void clear() {
        ORIGINAL_BY_EDITED.clear();
    }

    private static String sha256Hex(byte[] b) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
