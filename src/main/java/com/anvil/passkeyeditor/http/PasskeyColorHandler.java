package com.anvil.passkeyeditor.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.detect.Detector.OptionsKind;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.TargetProfile;

/**
 * Colours a Proxy-history row ORANGE when it belongs to a WebAuthn ceremony on a host tracked by an
 * enabled profile - so the operator sees at a glance which traffic is part of the passkey flow, even
 * before opening the Passkey Editor tab. One flat colour marks relevance only; whether a row was tampered is
 * read from Burp's Edited flag (manual edits) and the Output log (AUTO). Two surfaces:
 *   - verify requests (the {@link ProxyRequestHandler} side): an enabled profile matches the host
 *       and its phase URL scope (if pinned) admits the request. Note {@code "Registration|Authentication - <profile>"}.
 *   - options responses (the {@link ProxyResponseHandler} side): a {@code generate-*-options}
 *       response on a tracked host - the message the UV-downgrade tab acts on. Options carry no verify-URL,
 *       so this is host-scoped only. Note {@code "Options - <profile>"}.
 * The generic Default is the fallback, not a tracked target, so it is never coloured (matches the operator
 * expectation that disabling a host's profile stops its highlighting).
 *
 * Annotation only - it NEVER mutates the body (that is {@link PasskeyAutoHandler}'s job). It runs on
 * the Proxy receive stage; when AUTO later acts it appends its audit note to the same ORANGE row. It sets the
 * ORANGE colour only on an un-coloured row (never stomps a colour set by hand or by another extension),
 * but ALWAYS ensures its relevance note is present, so the note appears even on a row something else coloured.
 * Fail-safe: any error → pass the message through uncoloured.
 */
public final class PasskeyColorHandler implements ProxyRequestHandler, ProxyResponseHandler {

    private final Detector detector;
    private final ProfileRegistry registry;

    public PasskeyColorHandler(Detector detector, ProfileRegistry registry) {
        this.detector = detector;
        this.registry = registry;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try {
            // Skip before stringifying: a ceremony verify body is a small JSON document, so an over-cap body
            // cannot be one and the O(1) length check avoids materialising it as a String on the proxy thread.
            if (request.body().length() > detector.maxScanChars()) {
                return ProxyRequestReceivedAction.continueWith(request);
            }
            CeremonyType type = detector.detect(request.bodyToString());
            if (type != null) {
                Phase phase = type == CeremonyType.CREATE ? Phase.REG_VERIFY : Phase.AUTH_VERIFY;
                String host = request.httpService().host();
                TargetProfile matched = registry.match(host); // enabled-only; Default fallback
                if (matched != registry.defaultProfile()
                        && registry.urlScopeAllows(host, phase, request.url(), request.method())) {
                    String label = type == CeremonyType.CREATE ? "Registration" : "Authentication";
                    return ProxyRequestReceivedAction.continueWith(request,
                            mark(request.annotations(), label + ": " + matched.name()));
                }
            }
        } catch (Throwable ignored) {
            // A colouring miss must never disturb proxied traffic - fail open on ANY error (incl. Error, e.g.
            // an OOM/StackOverflow from a huge body), matching the AUTO handler; the worst case is no colour.
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request); // colour at receive; nothing to do here
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            // The always-on response path sees unbounded bodies (media, downloads). An options JSON is a few
            // KB, so skip an over-cap body via the O(1) ByteArray length before bodyToString() would allocate
            // the whole (UTF-16, ~2x) String just to scan its first cap bytes for a marker that cannot be there.
            if (response.body().length() > detector.maxScanChars()) {
                return ProxyResponseReceivedAction.continueWith(response);
            }
            OptionsKind kind = detector.detectOptions(response.bodyToString());
            HttpRequest initiating = response.initiatingRequest();
            if (kind != null && initiating != null && initiating.httpService() != null) {
                String host = initiating.httpService().host();
                TargetProfile matched = registry.match(host); // enabled-only; Default fallback
                // Tracked host only (a specific enabled profile) - the generic Default is never coloured.
                if (matched != registry.defaultProfile()) {
                    return ProxyResponseReceivedAction.continueWith(response,
                            mark(response.annotations(), "Options: " + matched.name()));
                }
            }
        } catch (Throwable ignored) {
            // A colouring miss must never disturb proxied traffic - fail open on ANY error (incl. Error, e.g.
            // an OOM/StackOverflow from a huge body), matching the AUTO handler; the worst case is no colour.
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response); // colour at receive; nothing to do here
    }

    /**
     * Ensure our relevance {@code note} is on the row (idempotent - append after any existing note, never
     * duplicate) and set ORANGE only when the row is un-coloured. Decoupling the note from the colour is the
     * fix for options rows that showed a colour but no note: if another extension loaded
     * alongside or a manual triage colour already coloured the row, the old {@code !hasHighlightColor}
     * guard skipped BOTH the colour and the note. Now the note always lands; only the colour defers.
     */
    private static Annotations mark(Annotations ann, String note) {
        String existing = ann.hasNotes() ? ann.notes() : "";
        String merged = existing.isEmpty() ? note : (existing.contains(note) ? existing : existing + "  " + note);
        Annotations out = ann.withNotes(merged);
        HighlightColor current = ann.highlightColor();
        if (current == null || current == HighlightColor.NONE) {
            out = out.withHighlightColor(HighlightColor.ORANGE);
        }
        return out;
    }
}
