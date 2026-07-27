package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.util.SafeRegex;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * How a profile recognises the host of an RP's verify traffic - which may be cross-origin from the demo
 * site (Hanko ceremonies hit a {@code *.hanko.io} tenant; Descope hits {@code api.descope.com}), so the
 * match is on the actual request host, not the page.
 */
public record HostMatch(Kind kind, String pattern) {

    public enum Kind { ANY, EXACT, SUFFIX, REGEX }

    /**
     * Compile-once cache for REGEX patterns. {@link #matches} runs per request on Burp's UI thread, so a
     * record can't hold a per-instance compiled {@link Pattern} - this shared, thread-safe cache avoids
     * recompiling the same pattern on every decode (and the future home for a backtracking watchdog).
     */
    private static final Map<String, Pattern> REGEX_CACHE = new ConcurrentHashMap<>();

    /** Matches any host - the Default profile's catch-all (always last to win, by registry order). */
    public static HostMatch any() {
        return new HostMatch(Kind.ANY, "");
    }

    public static HostMatch exact(String host) {
        return new HostMatch(Kind.EXACT, host);
    }

    /** Matches a host ending with {@code suffix} (e.g. {@code ".hanko.io"} for any tenant subdomain). */
    public static HostMatch suffix(String suffix) {
        return new HostMatch(Kind.SUFFIX, suffix);
    }

    public static HostMatch regex(String regex) {
        return new HostMatch(Kind.REGEX, regex);
    }

    /** True if {@code host} matches this rule (case-insensitive for host comparisons). */
    public boolean matches(String host) {
        if (host == null) {
            return kind == Kind.ANY;
        }
        return switch (kind) {
            case ANY -> true;
            case EXACT -> host.equalsIgnoreCase(pattern);
            // Locale.ROOT, not the JVM default: under a Turkish/Azeri default locale ASCII 'I' folds to the
            // dotless 'ı' (U+0131), so a default-locale toLowerCase() would make "TENANT.HANKO.IO" stop
            // matching a ".hanko.io" suffix and silently fall the editor back to the Default profile.
            case SUFFIX -> host.toLowerCase(java.util.Locale.ROOT)
                    .endsWith(pattern.toLowerCase(java.util.Locale.ROOT));
            case REGEX -> safeRegexFind(host);
        };
    }

    private boolean safeRegexFind(String host) {
        // User-supplied regex: compile once (cached), then match under SafeRegex's input cap + backtracking
        // step budget - a catastrophic pattern fails closed (no match) instead of hanging the UI thread
        // (this runs per request via isEnabledFor → urlScopeAllows). A bad pattern (compile failure) also
        // fails closed rather than throwing into detection.
        try {
            return SafeRegex.find(REGEX_CACHE.computeIfAbsent(pattern, Pattern::compile), host);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
