package com.anvil.passkeyeditor.profile;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.persistence.Persistence;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The seeding contract, which changed when the five RP presets stopped shipping.
 *
 * Previously the caller re-seeded whenever the loaded list was {@code null} or empty. With only the
 * Default seeding, an empty list is the ordinary steady state for a project whose operator has not added a
 * target yet, and it is also exactly what deleting every profile leaves behind. Keying "first run" on
 * emptiness would therefore re-announce a seed on every load and resurrect deliberately-deleted profiles, so
 * the signal is now "has this project ever written the key at all".
 */
class ProfileStoreTest {

    @Test
    void freshProjectIsFirstRun() {
        ProfileStore store = new ProfileStore(apiBackedBy(new HashMap<>()));
        assertFalse(store.hasStoredProfiles(), "nothing written yet → first run");
        assertNull(store.load());
    }

    @Test
    void writingAnEmptyListEndsFirstRun() {
        Map<String, ByteArray> backing = new HashMap<>();
        ProfileStore store = new ProfileStore(apiBackedBy(backing));

        store.save(List.of()); // what initialize() does on a fresh project

        assertTrue(store.hasStoredProfiles(), "an empty list is still a stored list");
        assertNotNull(store.load(), "load() returns the stored (empty) list, not null");
        assertEquals(0, store.load().size());
    }

    /**
     * The regression this contract exists for: an operator deletes every profile they added. The next load
     * must keep the list empty rather than treating "empty" as "never seeded" and re-populating it.
     */
    @Test
    void deletingEveryProfileSticksAcrossReload() {
        Map<String, ByteArray> backing = new HashMap<>();
        ProfileStore store = new ProfileStore(apiBackedBy(backing));
        store.save(List.of(RpFixtureProfiles.webauthnIo()));
        assertEquals(1, store.load().size());

        store.save(List.of()); // the operator deletes it

        ProfileStore reopened = new ProfileStore(apiBackedBy(backing)); // simulate a reload
        assertTrue(reopened.hasStoredProfiles(), "still a stored list → NOT a first run");
        assertEquals(0, reopened.load().size(), "deleted profiles must stay deleted");
    }

    @Test
    void defaultProfileRoundTripsInItsOwnSlot() {
        Map<String, ByteArray> backing = new HashMap<>();
        ProfileStore store = new ProfileStore(apiBackedBy(backing));
        assertNull(store.loadDefault());

        store.saveDefault(BuiltinProfiles.defaultProfile());

        assertEquals("default", store.loadDefault().id());
        assertFalse(store.hasStoredProfiles(), "the Default slot is separate from the profile list");
    }

    // ---- Burp runtime stand-ins --------------------------------------------------------------------------

    /**
     * {@code ByteArray.byteArray(byte[])} is a static factory that delegates to
     * {@code ObjectFactoryLocator.FACTORY}, which only Burp populates at runtime - which is why
     * {@link ProfileStore} had no test before. Installing a minimal factory here makes the whole adapter
     * headlessly testable; only {@code byteArray(byte[])} is ever reached, so the rest stays unimplemented.
     */
    @BeforeAll
    static void installByteArrayFactory() {
        if (ObjectFactoryLocator.FACTORY != null) {
            return;
        }
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                ProfileStoreTest.class.getClassLoader(), new Class<?>[]{MontoyaObjectFactory.class},
                (proxy, method, args) -> {
                    if ("byteArray".equals(method.getName()) && args[0] instanceof byte[] raw) {
                        return simpleByteArray(raw);
                    }
                    throw new UnsupportedOperationException("unstubbed factory call: " + method.getName());
                });
    }

    /** A {@link ByteArray} whose only live method is {@code getBytes()} - all ProfileStore reads back. */
    private static ByteArray simpleByteArray(byte[] raw) {
        return (ByteArray) Proxy.newProxyInstance(
                ProfileStoreTest.class.getClassLoader(), new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getBytes" -> raw;
                    case "length" -> raw.length;
                    case "toString" -> new String(raw, java.nio.charset.StandardCharsets.UTF_8);
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> throw new UnsupportedOperationException(
                            "ProfileStore must not call ByteArray." + method.getName());
                });
    }

    // ---- a PersistedObject double backed by a plain map; only the ByteArray accessors are live -----------

    private static MontoyaApi apiBackedBy(Map<String, ByteArray> backing) {
        PersistedObject data = (PersistedObject) Proxy.newProxyInstance(
                ProfileStoreTest.class.getClassLoader(), new Class<?>[]{PersistedObject.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getByteArray" -> backing.get((String) args[0]);
                    case "setByteArray" -> {
                        backing.put((String) args[0], (ByteArray) args[1]);
                        yield null;
                    }
                    default -> throw new UnsupportedOperationException(
                            "ProfileStore must not call PersistedObject." + method.getName());
                });
        Persistence persistence = (Persistence) Proxy.newProxyInstance(
                ProfileStoreTest.class.getClassLoader(), new Class<?>[]{Persistence.class},
                (proxy, method, args) -> "extensionData".equals(method.getName()) ? data
                        : throwForbidden(method.getName()));
        return (MontoyaApi) Proxy.newProxyInstance(
                ProfileStoreTest.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> "persistence".equals(method.getName()) ? persistence
                        : throwForbidden(method.getName()));
    }

    private static Object throwForbidden(String name) {
        throw new UnsupportedOperationException("ProfileStore must not call " + name + "()");
    }
}
