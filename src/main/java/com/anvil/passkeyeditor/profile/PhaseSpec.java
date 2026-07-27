package com.anvil.passkeyeditor.profile;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * The per-field locators for one ceremony phase of one RP, plus an optional {@link UrlMatch} pinning the
 * phase's verify endpoint. {@code url == null} (or ANY) means the phase is not URL-scoped -
 * today's host-only behaviour.
 */
public record PhaseSpec(Map<Field, FieldLocator> fields, UrlMatch url) {

    public PhaseSpec {
        // EnumMap, not Map.copyOf: Map.copyOf iterates in a per-JVM-run randomised order (enum identity
        // hashCode + ImmutableCollections salt), which would make checkAll's field order and the exported
        // profile JSON's key order differ across sessions. An EnumMap iterates in Field-declaration (ordinal)
        // order deterministically. (EnumMap's map ctor rejects an empty non-EnumMap, so guard the empty case.)
        fields = fields.isEmpty() ? Map.of() : Collections.unmodifiableMap(new EnumMap<>(fields));
    }

    /** Back-compat: a phase with no URL scoping. */
    public PhaseSpec(Map<Field, FieldLocator> fields) {
        this(fields, null);
    }

    public FieldLocator locator(Field field) {
        return fields.get(field);
    }

    /**
     * Locate {@code field}'s value span in {@code body}, or {@code null} if this phase does not define the
     * field or no candidate path resolves.
     */
    public int[] locate(Field field, byte[] body) {
        FieldLocator loc = fields.get(field);
        return loc == null ? null : loc.locate(body);
    }
}
