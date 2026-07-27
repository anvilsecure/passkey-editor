package com.anvil.passkeyeditor.profile;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The set of known {@link TargetProfile}s plus the catch-all Default - the single source both editor
 * providers consult (today each builds its own {@code Config}; with profiles they share one registry).
 *
 * The first profile whose {@link HostMatch} matches the request host wins; on no match the
 * {@link #defaultProfile() Default} (host = ANY) handles it. Because an unprofiled host
 * never matches a learned profile, it always falls to the Default - whose extraction is byte-identical
 * to today's (proven by {@code ProfileRegistryTest}), so the default path is never destabilised.
 *
 * Built-ins are seeded on init; the settings UI (next) adds/edits/removes entries - they are config,
 * not code.
 *
 * Thread-safety. The registry is read on the EDT (the ceremony editor) AND off the EDT (the AUTO
 * {@code HttpHandler} + the Proxy-colour handler, which run on Burp's networking threads), while the settings
 * UI mutates it on the EDT. The backing list is a {@link CopyOnWriteArrayList} so a reader ({@link #match} /
 * {@link #matchAuto} / {@link #urlScopeAllows}) always iterates a consistent snapshot and never throws
 * {@code ConcurrentModificationException} against a concurrent add/remove/replace; {@link TargetProfile} is
 * immutable so a snapshotted element is safe to read. Per-operation atomicity (not transactional across a
 * multi-step {@link #replace}) is sufficient: the worst case is a momentary mis-match during a live edit.
 */
public final class ProfileRegistry {

    private final List<TargetProfile> profiles = new CopyOnWriteArrayList<>();
    /**
     * The catch-all Default. It is a real, editable profile the operator can disable like any other
     * (it just isn't stored in {@link #profiles} - it is the always-present fallback slot). {@code volatile}
     * so the off-EDT handlers see an edit made on the EDT atomically (a reference swap, like the
     * {@link CopyOnWriteArrayList} backing {@link #profiles}).
     */
    private volatile TargetProfile defaultProfile;

    public ProfileRegistry(TargetProfile defaultProfile, List<TargetProfile> profiles) {
        this.defaultProfile = defaultProfile;
        this.profiles.addAll(profiles);
    }

    /**
     * The first enabled profile whose host matches {@code host}, or the Default if none do. Never null
     * - this is the extraction driver (the ceremony editor always needs a {@link PhaseSpec}), so it
     * returns the Default as the fallback regardless of the Default's own enabled flag. Tab visibility,
     * colouring and AUTO are gated separately ({@link #tabVisibleFor} / {@link #isTracked} / {@link
     * #matchAuto}) - those DO honour the Default's switch and the silenced-host rule.
     */
    public TargetProfile match(String host) {
        TargetProfile m = firstEnabledListMatch(host);
        return m != null ? m : defaultProfile;
    }

    /** The first enabled <i>listed</i> profile matching {@code host} (the Default is NOT considered), or null. */
    private TargetProfile firstEnabledListMatch(String host) {
        for (TargetProfile p : profiles) {
            if (p.enabled() && p.host().matches(host)) {
                return p;
            }
        }
        return null;
    }

    /** Whether any <i>listed</i> profile (enabled or disabled) matches {@code host}. */
    private boolean hasListProfileFor(String host) {
        for (TargetProfile p : profiles) {
            if (p.host().matches(host)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether {@code host} is a tracked target: a specific (non-Default) enabled profile claims
     * it. This is the gate for Proxy-history colouring - the Default (even when enabled) is the generic
     * fallback, not a target the operator is tracking, so it is never coloured.
     */
    public boolean isTracked(String host) {
        return firstEnabledListMatch(host) != null;
    }

    /**
     * Whether the "Passkey Editor" request tab should appear for {@code (host, phase, url, method)} - the
     * enabled-aware gate that {@code isEnabledFor} consults (callers still detect the ceremony
     * structurally first). Three dispositions:
     *   - TRACKED - a specific enabled profile matches the host → show iff its pinned verify-URL
     *       scope admits the request (the operator's panel is authoritative).
     *   - SILENCED - a profile matches the host but is disabled (and none enabled) → hide:
     *       disabling a host's profile silences the extension for that host, even though an enabled Default
     *       exists.
     *   - UNPROFILED - no profile matches the host at all (e.g. localhost) → fall to the
     *       Default, honouring its own enabled switch. So with the Default enabled an unprofiled host still
     *       shows the tab structurally; disable every profile (incl. the Default) and nothing matches.
     */
    public boolean tabVisibleFor(String host, Phase phase, String url, String method) {
        if (firstEnabledListMatch(host) != null) {
            return urlScopeAllows(host, phase, url, method); // TRACKED - honour the pinned verify URL
        }
        if (hasListProfileFor(host)) {
            return false; // SILENCED - a disabled profile claims this host
        }
        return defaultProfile.enabled(); // UNPROFILED - the Default's own switch (freeze-safe when enabled)
    }

    /**
     * The host-only counterpart of {@link #tabVisibleFor} for the options response tab (a
     * {@code generate-*-options} response carries no verify-URL to scope on). Same TRACKED / SILENCED /
     * UNPROFILED dispositions, sans the URL gate.
     */
    public boolean tabVisibleForHost(String host) {
        if (firstEnabledListMatch(host) != null) {
            return true; // TRACKED
        }
        if (hasListProfileFor(host)) {
            return false; // SILENCED
        }
        return defaultProfile.enabled(); // UNPROFILED
    }

    /**
     * The first profile armed for AUTO on {@code phase} (auto-plant on {@code REG_VERIFY} / auto-re-sign
     * on {@code AUTH_VERIFY}) whose host matches {@code host} and whose phase verify-URL scope (if active)
     * admits {@code (url, method)} - or {@code null} if none. This is the gate for the in-flight AUTO handler,
     * independent of {@link #match} and of {@code enabled} (AUTO is gated solely by the per-profile auto
     * flags, not by manual tab visibility). The Default carries no auto flags and is not in this list, so it is
     * structurally never returned - an unprofiled host can never be auto-rewritten even in
     * principle (freeze-safe). First-match-wins over the insertion-ordered list, evaluated per phase.
     */
    public TargetProfile matchAuto(String host, Phase phase, String url, String method) {
        for (TargetProfile p : profiles) {
            if (!p.autoActsFor(phase) || !p.host().matches(host)) {
                continue;
            }
            PhaseSpec spec = p.phase(phase);
            if (spec == null) {
                continue; // armed but this phase has no locators - skip so a later COMPLETE profile can match
                          // (the handler needs the spec to act; returning this one would shadow + then no-op)
            }
            if (spec.url() != null && spec.url().isActive() && !spec.url().matches(url, method)) {
                continue; // the profile pins a verify URL this request does not satisfy - not its endpoint.
                          // Deliberately STRICTER than urlScopeAllows: an unknown (null) url fails to match
                          // here and skips the profile. AUTO rewrites live traffic, so "can't prove this is
                          // the pinned endpoint" must mean "don't act"; only tab VISIBILITY falls back to
                          // host + enabled when the URL is unknowable.
            }
            return p;
        }
        return null;
    }

    /**
     * Resolve the {@link PhaseSpec} for {@code host} + {@code phase}: from the matched profile, falling
     * back to the Default's spec if a non-Default match doesn't define that phase.
     */
    public PhaseSpec resolve(String host, Phase phase) {
        TargetProfile matched = match(host);
        PhaseSpec spec = matched.phase(phase);
        if (spec == null && matched != defaultProfile) {
            spec = defaultProfile.phase(phase);
        }
        return spec;
    }

    /**
     * Whether a request to {@code (host, url, method)} is allowed for {@code phase} by the matched profile's
     * URL scope - the gate for both tab visibility and extraction. True when the matched profile has
     * no active verify-URL for the phase (today's structural behaviour); false only when the profile pins a
     * URL the request demonstrably fails. This is what makes the operator's panel authoritative: set a
     * verify URL and the tab appears only on that endpoint, instead of on every structurally-detected
     * ceremony.
     *
     * An UNKNOWN url ({@code null}) is not a mismatch. Burp hands an editor request objects whose
     * URL it cannot resolve - {@code HttpRequest.url()} throws {@code MalformedRequestException} whenever the
     * message carries no {@code HttpService}, which is exactly what a Proxy-history pane produces when it
     * (re)binds a message from raw bytes. The caller then passes {@code null}. Treating that as "wrong
     * endpoint" made the ceremony tab silently vanish on a correctly-detected verify request (seen live on the
     * first history row selected after the editor pane is created; re-selecting the row - or switching the
     * Original/Edited sub-view - re-bound it with a resolvable URL and the tab reappeared). Visibility
     * therefore falls back to host + enabled when the URL is unknowable. The {@code enabled} master switch and
     * the SILENCED/UNPROFILED dispositions above are untouched, and AUTO stays fail-closed
     * ({@link #matchAuto} still requires a URL it can actually match - it rewrites live traffic).
     */
    public boolean urlScopeAllows(String host, Phase phase, String url, String method) {
        TargetProfile matched = match(host);
        // The Default is never URL-scoped (mirrors decodeBestEffort's `!= defaultProfile` guard), so the two
        // gates can't desync even if the Default ever became editable. Unreachable today (the Default carries
        // no URL), but keeps the visibility gate and the extraction gate defined over the identical condition.
        if (matched == defaultProfile) {
            return true;
        }
        PhaseSpec spec = matched.phase(phase);
        if (spec == null || spec.url() == null || !spec.url().isActive()) {
            return true;
        }
        if (url == null) {
            return true; // URL unknowable for this message - scope can't be evaluated, so it can't exclude
        }
        return spec.url().matches(url, method);
    }

    /**
     * Whether any listed profile is armed for AUTO ({@code autoPlant} or {@code autoResign}). The AUTO
     * handler uses this to suppress its "no armed profile matched this ceremony" diagnostic when the operator
     * isn't using AUTO at all (e.g. a pure-manual session), so the log isn't noisy on every ceremony.
     */
    public boolean hasArmedProfile() {
        for (TargetProfile p : profiles) {
            if (p.autoPlant() || p.autoResign()) {
                return true;
            }
        }
        return false;
    }

    public TargetProfile defaultProfile() {
        return defaultProfile;
    }

    /**
     * Replace the Default profile (an edit / enable-toggle from the settings UI). The Default lives in its
     * own slot rather than {@link #profiles}, so it is updated through here, not {@link #replace}. The field
     * is {@code volatile}, so an off-EDT reader ({@link #match} / {@link #tabVisibleFor} / {@link #matchAuto})
     * sees the new reference atomically.
     */
    public void setDefaultProfile(TargetProfile profile) {
        this.defaultProfile = profile;
    }

    public List<TargetProfile> profiles() {
        return Collections.unmodifiableList(profiles);
    }

    public void add(TargetProfile profile) {
        profiles.add(profile);
    }

    public boolean remove(String id) {
        return profiles.removeIf(p -> p.id().equals(id));
    }

    /**
     * Replace the profile {@code oldId} with {@code profile} in place, preserving its position (and
     * therefore its first-match-wins precedence) across an edit/save. If the (possibly renamed) new id
     * already exists at a different slot, that other holder is removed first; if {@code oldId} is absent the
     * profile is appended. A plain remove+add would move an edited profile to the tail and silently change
     * host-match routing for overlapping hosts.
     */
    public void replace(String oldId, TargetProfile profile) {
        int idx = indexOf(oldId);
        // Drop any OTHER slot already holding the new id (a rename onto an existing id), without disturbing
        // the editing slot's index.
        for (int i = profiles.size() - 1; i >= 0; i--) {
            if (i != idx && profiles.get(i).id().equals(profile.id())) {
                profiles.remove(i);
                if (i < idx) {
                    idx--;
                }
            }
        }
        if (idx >= 0) {
            profiles.set(idx, profile);
        } else {
            profiles.add(profile);
        }
    }

    private int indexOf(String id) {
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).id().equals(id)) {
                return i;
            }
        }
        return -1;
    }
}
