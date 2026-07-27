package com.anvil.passkeyeditor.profile;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.persistence.PersistedObject;

import java.util.List;

/**
 * PersistedObject-backed store for the user's profile list. Montoya rule: persist a {@link ByteArray},
 * not a raw {@code byte[]}. The (de)serialisation is the Burp-free {@link ProfileJson}; this is the thin
 * Montoya adapter - so under Burp Pro a profile the user adds/edits in the settings tab survives an
 * extension reload / project re-open.
 */
public final class ProfileStore {

    private static final String KEY = "passkey-editor.profiles.v1";
    /** Separate slot for the editable Default profile (it lives outside the listed-profile set). */
    private static final String DEFAULT_KEY = "passkey-editor.default.v1";

    private final PersistedObject data;

    public ProfileStore(MontoyaApi api) {
        this.data = api.persistence().extensionData();
    }

    /** The persisted profiles, or {@code null} if nothing has been stored yet (first run). */
    public List<TargetProfile> load() {
        ByteArray stored = data.getByteArray(KEY);
        return stored == null ? null : ProfileJson.fromJson(stored.getBytes());
    }

    /**
     * Whether this project has ever written a profile list, regardless of whether that list is empty.
     *
     * This is deliberately NOT "is the loaded list non-empty": now that only the Default seeds, an empty
     * list is the normal steady state for a project whose operator has not added a target yet, and it is
     * also what an operator gets after deleting the profiles they added. Keying "first run" on emptiness
     * would report a fresh seed on every load, and would resurrect deliberately-deleted profiles.
     */
    public boolean hasStoredProfiles() {
        return data.getByteArray(KEY) != null;
    }

    /** Persist the given profile list (typically {@code registry.profiles()} after an edit). */
    public void save(List<TargetProfile> profiles) {
        data.setByteArray(KEY, ByteArray.byteArray(ProfileJson.toJson(profiles)));
    }

    /**
     * The persisted Default profile (its enabled flag / edits survive a reload), or {@code null} if never
     * stored - in which case the caller seeds {@link com.anvil.passkeyeditor.profile.BuiltinProfiles#defaultProfile()}.
     * Reuses the {@link ProfileJson} list format as a single-element list.
     */
    public TargetProfile loadDefault() {
        ByteArray stored = data.getByteArray(DEFAULT_KEY);
        if (stored == null) {
            return null;
        }
        List<TargetProfile> list = ProfileJson.fromJson(stored.getBytes());
        return list != null && !list.isEmpty() ? list.get(0) : null;
    }

    /** Persist the (edited / enable-toggled) Default profile. */
    public void saveDefault(TargetProfile profile) {
        data.setByteArray(DEFAULT_KEY, ByteArray.byteArray(ProfileJson.toJson(List.of(profile))));
    }
}
