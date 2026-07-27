package com.anvil.passkeyeditor.profile;

import com.anvil.passkeyeditor.util.SafeRegex;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * How a profile recognises the verify endpoint of one ceremony phase - the per-phase URL (+ optional
 * HTTP method) the operator pins.
 *
 * Detection of whether a body is a ceremony stays structural ({@code Detector}); the URL match
 * only scopes a profile to the right request: when a phase declares a URL, the editor applies that
 * phase's locators only to a request whose URL (and method, if set) matches - otherwise it falls back to
 * the Default. {@link Kind#ANY} (the default) means "don't scope by URL", preserving today's host-only
 * behaviour.
 *
 * Mirrors {@link HostMatch}: a compile-once regex cache, and a bad pattern fails closed (no match)
 * rather than throwing into per-request detection.
 */
public record UrlMatch(Kind kind, String pattern, String method) {

    /** {@code ANY} = unscoped; {@code EXACT} = full-URL equals; {@code CONTAINS} = substring; {@code REGEX} = find. */
    public enum Kind { ANY, EXACT, CONTAINS, REGEX }

    private static final Map<String, Pattern> REGEX_CACHE = new ConcurrentHashMap<>();

    public UrlMatch {
        if (kind == null) {
            kind = Kind.ANY;
        }
        if (pattern == null) {
            pattern = "";
        }
        if (method != null && method.isBlank()) {
            method = null; // null = any method
        }
        // A method gate is meaningless without a URL pattern (matches() short-circuits on an inactive rule
        // before the method check), so a method-only rule would be silently inert. Normalise it away so a
        // misconfigured "POST, no URL" can never read as an active constraint.
        if (kind == Kind.ANY || pattern.isBlank()) {
            method = null;
        }
    }

    /** Unscoped - matches any URL/method (the default; today's host-only behaviour). */
    public static UrlMatch any() {
        return new UrlMatch(Kind.ANY, "", null);
    }

    public static UrlMatch exact(String url) {
        return new UrlMatch(Kind.EXACT, url, null);
    }

    /** The common case: the request URL contains this substring (e.g. {@code /verify-authentication}). */
    public static UrlMatch contains(String fragment) {
        return new UrlMatch(Kind.CONTAINS, fragment, null);
    }

    public static UrlMatch regex(String regex) {
        return new UrlMatch(Kind.REGEX, regex, null);
    }

    /** Whether this matcher actually constrains (a configured, non-ANY rule). */
    public boolean isActive() {
        return kind != Kind.ANY && !pattern.isBlank();
    }

    /**
     * True if {@code url} (+ {@code requestMethod}) satisfies this match. An ANY/blank rule always matches;
     * a configured {@code method} must equal {@code requestMethod} (case-insensitive) when both are present.
     *
     * @param url           the full request URL (scheme + host + path [+ query]) - never null in practice
     * @param requestMethod the request's HTTP method, or {@code null} if unknown
     */
    public boolean matches(String url, String requestMethod) {
        if (!isActive()) {
            return true;
        }
        if (url == null) {
            return false;
        }
        if (method != null && requestMethod != null && !method.equalsIgnoreCase(requestMethod)) {
            return false;
        }
        return switch (kind) {
            case ANY -> true;
            case EXACT -> url.equals(pattern);
            case CONTAINS -> url.contains(pattern);
            case REGEX -> safeRegexFind(url);
        };
    }

    private boolean safeRegexFind(String url) {
        // Match under SafeRegex's input cap + backtracking step budget - this runs per request on the UI
        // thread via isEnabledFor → urlScopeAllows, so a catastrophic pattern must fail closed, not hang.
        try {
            return SafeRegex.find(REGEX_CACHE.computeIfAbsent(pattern, Pattern::compile), url);
        } catch (RuntimeException e) {
            return false; // a bad user pattern (compile failure) fails closed, never throws into detection
        }
    }
}
