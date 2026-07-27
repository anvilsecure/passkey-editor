package com.anvil.passkeyeditor.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import com.anvil.passkeyeditor.attacks.AutoDecision;
import com.anvil.passkeyeditor.attacks.AutoDecision.AutoContext;
import com.anvil.passkeyeditor.attacks.AutoDecision.Decision;
import com.anvil.passkeyeditor.attacks.ReSignEngine;
import com.anvil.passkeyeditor.crypto.CoseSigner;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.crypto.KeyStoreService.KeyId;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.model.CeremonyType;
import com.anvil.passkeyeditor.profile.Phase;
import com.anvil.passkeyeditor.profile.PhaseSpec;
import com.anvil.passkeyeditor.profile.PlantAttestation;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.util.EditDiffCache;
import com.anvil.passkeyeditor.util.Log;

import java.util.EnumSet;
import java.util.Set;

/**
 * AUTO mode - the in-flight, per-profile re-signer / key-planter. It rewrites the outgoing verify request
 * for an armed profile (plant on a registration / re-sign on an authentication).
 *
 * Two seams, by design:
 *   - As a {@link ProxyRequestHandler} it rewrites at the Proxy to-be-sent stage, so the edit shows
 *       natively in Proxy history as Original vs Edited request (Burp logs the row at the
 *       proxy stage, so a later {@code HttpHandler} edit would be invisible there). This is the primary path
 *       - a live browser ceremony flows through the Proxy.
 *   - As an {@link HttpHandler} it covers Repeater, and ONLY Repeater ({@link #AUTO_TOOLS}). Burp calls an
 *       {@code HttpHandler} for every tool, so this seam is gated by an explicit allowlist rather than by
 *       excluding Proxy: Proxy is already handled above (so it would otherwise be rewritten twice), and
 *       Scanner / Intruder / the recorded-login replayer must never auto-forge credentials unattended.
 *
 * Off by default; fail-open; auditable. It acts only when a profile is explicitly armed
 * ({@code autoPlant} on a registration / {@code autoResign} on an authentication - {@link
 * ProfileRegistry#matchAuto}); the all-off Default is structurally never matched, so an unprofiled host is
 * never auto-rewritten. The whole decision is the pure {@link AutoDecision} predicate. Any exception →
 * pass-through (never break live traffic). Every action is logged to the extension output AND annotated on
 * the request (loud highlight + note), so an auto-rewrite is never invisible. Scope is NOT a gate (Option A):
 * arming the profile is the explicit opt-in.
 *
 * Capability boundary: auto re-sign only signs a credential whose key we already hold (a
 * prior manual or auto plant); a miss is a pass-through. Auto plant creates the key under the profile's
 * default algorithm. Double-sign / re-entrancy guards: requests from our own tool ({@code EXTENSIONS})
 * and requests already carrying the AUTO sentinel note are passed through (so a Repeater resend of an
 * already-auto-signed request is not re-signed with fresh randomised bytes).
 */
public final class PasskeyAutoHandler implements HttpHandler, ProxyRequestHandler {

    /** Prefix prepended to a row's relevance note when AUTO acts, e.g. {@code "[AUTO] Authentication: webauthn.io"};
     *  its presence before a phase label is also the double-sign / re-entrancy sentinel (see {@link #hasSentinel}). */
    private static final String AUTO_PREFIX = "[AUTO] ";

    private final MontoyaApi api;
    private final Detector detector;
    private final ProfileRegistry registry;
    private final KeyStoreService keyStore;

    public PasskeyAutoHandler(MontoyaApi api, Detector detector, ProfileRegistry registry, KeyStoreService keyStore) {
        this.api = api;
        this.detector = detector;
        this.registry = registry;
        this.keyStore = keyStore;
    }

    // ---- Proxy seam: rewrite at the to-be-sent stage so Proxy history shows Original vs Edited -----------

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        // Nothing at receive - PasskeyColorHandler owns the ORANGE "tracked" mark there; AUTO rewrites
        // at to-be-sent so the proxied row carries a clean original-vs-edited diff.
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        try {
            // Skip before materialising the body: a ceremony verify body is a small JSON document, so an
            // over-cap body cannot be one, and the O(1) length check avoids both a full byte[] copy and a
            // full (UTF-16, ~2x) String on the proxy thread. Mirrors PasskeyColorHandler.
            if (request.body().length() > detector.maxScanChars()) {
                return ProxyRequestToBeSentAction.continueWith(request);
            }
            Outcome o = compute(request.body().getBytes(), request.bodyToString(),
                    request.httpService().host(), request.url(), request.method(),
                    false, hasSentinel(request.annotations()), request.isInScope());
            if (o == null) {
                return ProxyRequestToBeSentAction.continueWith(request);
            }
            // Record edited→original so the read-only Passkey Editor tab can show the persistent amber diff
            // when this proxied row is later opened in Proxy history (this rewrite is what history will hold).
            EditDiffCache.record(o.body(), request.body().getBytes());
            return ProxyRequestToBeSentAction.continueWith(request.withBody(ByteArray.byteArray(o.body())),
                    annotate(request.annotations(), o.color(), o.note()));
        } catch (Throwable t) {
            api.logging().logToError("Passkey AUTO: pass-through on error (proxy)", t);
            return ProxyRequestToBeSentAction.continueWith(request);
        }
    }

    // ---- HTTP seam: Repeater only; Proxy is handled by the seam above --------------------------------

    /**
     * The Burp tools AUTO rewrites in on this seam. Deliberately an ALLOWLIST, not a Proxy exclusion: Burp
     * calls an {@code HttpHandler} for every tool, so testing only for {@code PROXY} meant Scanner, Intruder,
     * the recorded-login replayer and eight more silently reached {@code plant()} / {@code resign()} on an
     * armed host. That was live-confirmed on the wire (Intruder re-signed assertions; one active scan planted
     * ~10 distinct keys on the account, which also pushed {@code keyStore.size()} past 1 and disabled the
     * most-recent fallback in {@link #resolveHeld} for the rest of the session).
     *
     * PROXY is absent on purpose - the sibling proxy seam owns it, so admitting it here would rewrite a
     * proxied request twice. Adding a tool here is a behaviour change that must be reflected in the Guide's
     * AUTO section and the README's Responsible use note; {@code PasskeyAutoToolGateTest} pins the set so the
     * two cannot drift apart again.
     */
    static final Set<ToolType> AUTO_TOOLS = EnumSet.of(ToolType.REPEATER);

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            if (!isAutoTool(request.toolSource())) {
                noteExcludedTool(request);
                return RequestToBeSentAction.continueWith(request);
            }
            // O(1) size gate before materialising the body, as in the Proxy seam above.
            if (request.body().length() > detector.maxScanChars()) {
                return RequestToBeSentAction.continueWith(request);
            }
            Outcome o = compute(request.body().getBytes(), request.bodyToString(),
                    request.httpService().host(), request.url(), request.method(),
                    request.toolSource().isFromTool(ToolType.EXTENSIONS), hasSentinel(request.annotations()),
                    request.isInScope());
            if (o == null) {
                return RequestToBeSentAction.continueWith(request);
            }
            return RequestToBeSentAction.continueWith(request.withBody(ByteArray.byteArray(o.body())),
                    annotate(request.annotations(), o.color(), o.note()));
        } catch (Throwable t) {
            // Fail-open on ANYTHING (incl. Error) - an in-flight rewriter must never break or drop live
            // traffic; the worst case is the request passing through untouched.
            api.logging().logToError("Passkey AUTO: pass-through on error", t);
            return RequestToBeSentAction.continueWith(request);
        }
    }

    /** Package-private + {@link ToolSource}-typed so the gate is unit-testable without a live Burp. */
    static boolean isAutoTool(ToolSource source) {
        return source != null && AUTO_TOOLS.stream().anyMatch(source::isFromTool);
    }

    /**
     * Say so in the Output log when a ceremony reaches an armed profile from a tool AUTO does not act in, so
     * the exclusion is never a silent no-op ("I armed it and nothing happened"). Deliberately the last thing
     * checked and cheapest-first: nothing armed, or an over-cap body, costs no allocation at all, and the body
     * is only stringified once a ceremony is actually plausible. Proxy and our own re-emissions are exempt -
     * Proxy is handled by the sibling seam (a note here would double-log every proxied ceremony) and
     * EXTENSIONS is the re-entrancy guard.
     */
    private void noteExcludedTool(HttpRequestToBeSent request) {
        try {
            ToolSource source = request.toolSource();
            if (source == null || source.isFromTool(ToolType.PROXY, ToolType.EXTENSIONS)) {
                return;
            }
            if (!registry.hasArmedProfile() || request.body().length() > detector.maxScanChars()) {
                return;
            }
            CeremonyType type = detector.detect(request.bodyToString());
            if (type == null) {
                return; // not a ceremony - the overwhelming majority
            }
            Phase phase = type == CeremonyType.CREATE ? Phase.REG_VERIFY : Phase.AUTH_VERIFY;
            Log.out(api.logging(), "AUTO skip (" + phaseLabel(phase) + "): ceremony from " + source.toolType()
                    + ", a tool AUTO does not act in (Proxy and Repeater only); request passed through "
                    + "unchanged.");
        } catch (Throwable t) {
            // A diagnostic must never affect traffic.
            api.logging().logToError("Passkey AUTO: excluded-tool note failed", t);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived); // AUTO never touches responses
    }

    // ---- shared decision + rewrite (Burp-action-free, driven by both seams) ------------------------------

    /**
     * A computed rewrite: the new wire body + the loud colour + the audit note. Package-private (not private)
     * so the same-package PasskeyAutoComputeInertTest can assert {@code compute(...) == null} (pass-through)
     * on the inert/disabled path and a non-null ORANGE Outcome on the armed path - the dual-seam no-op proof.
     */
    record Outcome(byte[] body, HighlightColor color, String note) {
    }

    /**
     * Decide and (when armed, matched, and the body actually changes) compute the rewrite for an outgoing
     * request. Returns {@code null} for pass-through (no annotation change). Independent of the Burp request
     * type so the Proxy and HTTP seams share one code path. Logs actions + skip-reasons via the output log.
     */
    Outcome compute(byte[] body, String bodyString, String host, String url, String method,
                    boolean fromExtensions, boolean alreadyMarked, boolean inScope) {
        // Re-entrancy guards only (our own emission / an already-auto-signed resend).
        if (fromExtensions || alreadyMarked) {
            return null;
        }
        CeremonyType type = detector.detect(bodyString);
        if (type == null) {
            return null; // not a ceremony - the overwhelming majority
        }
        Phase phase = type == CeremonyType.CREATE ? Phase.REG_VERIFY : Phase.AUTH_VERIFY;
        TargetProfile profile = registry.matchAuto(host, phase, url, method);
        if (profile == null) {
            // A detected ceremony we are NOT armed for here - surface it so the operator can confirm in Output
            // that the extension SAW the ceremony and deliberately passed it through (the "skip" they look for):
            //   (1) an ENABLED profile tracks this host but AUTO is not armed for this phase - always log it
            //       (the operator deliberately tracks this host, so a pass-through here is signal, not noise); OR
            //   (2) no profile tracks this host, but AUTO is armed somewhere - log the armed-but-not-firing
            //       diagnostic so an armed profile that never fires is never a silent no-op.
            // A disabled / unprofiled host with nothing armed stays SILENT (fully inert) so a pure-manual or
            // unrelated-traffic session isn't spammed on every ceremony.
            String action = phase == Phase.REG_VERIFY ? "plant" : "re-sign";
            TargetProfile tracked = registry.match(host); // enabled match, or the Default when none
            if (tracked != registry.defaultProfile()) {
                Log.out(api.logging(), "AUTO skip (" + phaseLabel(phase) + "): host=" + host + ", tracked by '"
                        + tracked.name() + "', but " + action + " not armed; request passed through unchanged.");
            } else if (registry.hasArmedProfile()) {
                Log.out(api.logging(), "AUTO skip (" + phaseLabel(phase) + "): host=" + host
                        + ", no armed profile matched (check the profile's host match, the phase verify-URL "
                        + "scope, and that " + action + " is ticked + Enabled).");
            }
            return null;
        }
        // MANUAL EDIT WINS over AUTO. An armed profile matched, but the manual Passkey Editor tab records its
        // forged body to EditDiffCache (in getRequest / on render) BEFORE this to-be-sent seam runs. So if this
        // exact body is a recorded manual forge, the operator tampered it by hand (e.g. planted a different alg
        // via Proxy Intercept) - defer to THEIR edit rather than silently overwrite it with AUTO's own
        // plant/re-sign under the profile's default alg. A fresh browser ceremony is never in the cache, so the
        // live-browser AUTO path is unaffected.
        if (EditDiffCache.originalFor(body) != null) {
            Log.out(api.logging(), "AUTO skip (" + phaseLabel(phase) + "): host=" + host + ", profile '"
                    + profile.name() + "' is armed, but this request was manually edited in the Passkey Editor "
                    + "tab; AUTO deferred to the operator's edit.");
            return null;
        }
        PhaseSpec spec = profile.phase(phase); // matchAuto guarantees a non-null spec for the matched phase

        // KEY axis: the clientData-ORIGIN host (what the editor's plant keys on) - NOT the HTTP transport host
        // - so a manual plant and this AUTO re-sign resolve the SAME KeyId, even on a split-origin topology.
        String keyHost = ReSignEngine.originHost(body, spec);
        // Resolve the held signer up front (AUTH only): the capability-boundary input AND the re-sign key.
        Held held = type == CeremonyType.GET ? resolveHeld(body, spec, keyHost) : null;

        Decision decision = AutoDecision.decide(new AutoContext(
                inScope, fromExtensions, alreadyMarked, type, true, held != null));
        if (decision == Decision.PASS_THROUGH) {
            // After an armed match the only remaining PASS_THROUGH is AUTH with no held key (the capability
            // boundary). Name it so the operator knows to plant/register with our key first.
            if (type == CeremonyType.GET) {
                Log.out(api.logging(), "AUTO skip (Authentication): host=" + keyHost + ", profile '"
                        + profile.name() + "' holds no key for this credential (plant with our key first).");
            }
            return null;
        }
        return decision == Decision.PLANT
                ? plant(body, spec, profile, keyHost)
                : resign(body, spec, held, keyHost, profile);
    }

    /**
     * The signer for the assertion + how it was resolved. Exact {@code (keyHost, credId)} lookup first; the
     * most-recent fallback fires ONLY when unambiguous - no locatable credId, or at most one key held - so a
     * multi-account capture with an exact miss is a PASS_THROUGH (never a wrong-account re-sign), and a
     * fallback is flagged so the log/annotation names the key actually used. Returns {@code null} ⇒ no key.
     */
    private Held resolveHeld(byte[] body, PhaseSpec spec, String keyHost) {
        String credId = ReSignEngine.credIdHex(body, spec);
        if (credId != null) {
            CoseSigner exact = keyStore.retrieveSigner(new KeyId(keyHost, "", credId));
            if (exact != null) {
                return new Held(exact, credId, false);
            }
        }
        // Exact miss → fall back to the most-recent key only when the choice is unambiguous (≤1 key held).
        // With ≥2 keys we refuse rather than risk re-signing under the wrong account's key.
        if (keyStore.size() <= 1) {
            CoseSigner mr = keyStore.retrieveMostRecentSigner();
            if (mr != null) {
                KeyId id = keyStore.mostRecentId();
                return new Held(mr, id != null ? id.credId() : null, true);
            }
        }
        return null;
    }

    /** A resolved signer + the credId it is keyed under + whether it came from the most-recent fallback. */
    private record Held(CoseSigner signer, String usedCredId, boolean fallback) {
    }

    /** The tab-aligned label for a verify phase: "Registration" / "Authentication" (matches the editor tab). */
    private static String phaseLabel(Phase phase) {
        return phase == Phase.REG_VERIFY ? "Registration" : "Authentication";
    }

    /**
     * The shrunk AUTO row note: {@code "[AUTO] Registration|Authentication - <profile>"}. It mirrors the
     * receive-stage relevance mark with an {@code [AUTO]} prefix (which is also the re-entrancy sentinel, see
     * {@link #hasSentinel}); the full alg / host / credId audit detail lives in the Output log, not the note.
     */
    private static String autoNote(Phase phase, TargetProfile profile) {
        return AUTO_PREFIX + phaseLabel(phase) + ": " + profile.name();
    }

    private Outcome plant(byte[] body, PhaseSpec spec, TargetProfile profile, String keyHost) {
        SignerAlgorithm alg = SignerAlgorithm.forCoseIdOrDefault(profile.signer().coseAlg(), SignerAlgorithm.ES256);
        CoseSigner signer = alg.generate();
        // AUTO plants under the profile's selected attestation format (fmt="none" by default, or packed
        // self-attestation when armed). Orthogonal to the algorithm above.
        PlantAttestation attestation = profile.plantAttestation();
        ReSignEngine.Result r = ReSignEngine.plantRegistration(body, spec, signer, attestation);
        if (!r.changed()) {
            Log.out(api.logging(), "AUTO skip (Registration): host=" + keyHost + ", profile '" + profile.name()
                    + "', plant produced no change (" + r.detail() + "); check the ATTESTATION_OBJECT locator "
                    + "resolves in this body.");
            return null;
        }
        keyStore.storeSigner(new KeyId(keyHost, "", r.credIdHex() != null ? r.credIdHex() : ""), signer);
        Log.out(api.logging(), "AUTO PLANT: host=" + keyHost + ", alg=" + alg.label()
                + ", attestation=" + attestation.label() + ", credId=" + r.credIdHex());
        return new Outcome(r.body(), HighlightColor.ORANGE, autoNote(Phase.REG_VERIFY, profile));
    }

    private Outcome resign(byte[] body, PhaseSpec spec, Held held, String keyHost, TargetProfile profile) {
        ReSignEngine.Result r = ReSignEngine.reSignAssertion(body, spec, held.signer());
        if (!r.changed()) {
            Log.out(api.logging(), "AUTO skip (Authentication): host=" + keyHost
                    + ", re-sign produced no change (" + r.detail() + "); check the SIGNATURE / "
                    + "AUTHENTICATOR_DATA / CLIENT_DATA_JSON locators resolve in this body.");
            return null;
        }
        String alg = SignerAlgorithm.forCoseIdOrDefault(held.signer().coseAlg(), SignerAlgorithm.ES256).label();
        // Log BOTH the request's credId AND the key actually used (+ a FALLBACK marker) so a most-recent
        // fallback can never silently hide which account's key signed.
        Log.out(api.logging(), "AUTO RE-SIGN: host=" + keyHost + ", alg=" + alg
                + ", req-credId=" + r.credIdHex() + ", key-credId=" + held.usedCredId()
                + (held.fallback() ? " (MOST-RECENT FALLBACK)" : ""));
        return new Outcome(r.body(), HighlightColor.ORANGE, autoNote(Phase.AUTH_VERIFY, profile));
    }

    /**
     * Write the {@code [AUTO] <phase> - <profile>} note and set the ORANGE relevance colour. The receive-stage
     * {@link PasskeyColorHandler} may already have written the plain {@code <phase> - <profile>} mark on this
     * same row; collapse that into the {@code [AUTO]} note (prefix it) rather than duplicating. Any OTHER
     * (operator-set) note is preserved by appending. Colour is (re)set only when the row is un-coloured or
     * carries our own ORANGE mark - never stomp a colour the operator set by hand for triage. (One flat ORANGE
     * marks every passkey-flow row; whether AUTO actually rewrote the body is read from the note + Burp's
     * Edited flag, not the colour.)
     */
    private static Annotations annotate(Annotations ann, HighlightColor color, String note) {
        String existing = ann.hasNotes() ? ann.notes() : "";
        String plain = note.startsWith(AUTO_PREFIX) ? note.substring(AUTO_PREFIX.length()) : note;
        String merged = (existing.isEmpty() || existing.equals(plain)) ? note : existing + "  " + note;
        Annotations out = ann.withNotes(merged);
        HighlightColor current = ann.highlightColor();
        if (current == null || current == HighlightColor.NONE || current == HighlightColor.ORANGE) {
            out = out.withHighlightColor(color);
        }
        return out;
    }

    /**
     * True if this request already carries OUR auto-note (the re-entrancy / double-sign guard). Keys on the
     * {@code "[AUTO] "} prefix immediately followed by a phase label - NOT a bare {@code "[AUTO]"} - so an
     * operator profile literally NAMED {@code [AUTO]} (which the colour handler renders as {@code "<phase> -
     * [AUTO]"}) does not falsely trip the guard and silently block the first legitimate AUTO rewrite.
     */
    private static boolean hasSentinel(Annotations ann) {
        return ann.hasNotes() && noteHasSentinel(ann.notes());
    }

    /**
     * Pure sentinel test on a note string (package-private for unit testing). {@link #annotate} writes our
     * note as either {@code "[AUTO] <phase>: ..."} (at the START of the note) or, after an existing note,
     * {@code "<existing>  [AUTO] <phase>: ..."} (a TWO-space separator). So key on start-of-note OR the
     * two-space-prefixed marker, never on the {@code <phase>}/{@code <profile>} separator itself. A profile
     * NAME that embeds {@code "[AUTO]"} only ever appears after the colour handler's {@code "<phase>: "} (a
     * single space after the colon), so it cannot start the note and is never two-space-prefixed. That avoids
     * the self-inflicted collision where a profile named e.g. {@code "[AUTO] Authentication x"} would
     * otherwise trip the guard and suppress the first real rewrite.
     */
    static boolean noteHasSentinel(String notes) {
        return notes != null && (notes.startsWith(AUTO_PREFIX) || notes.contains("  " + AUTO_PREFIX));
    }
}
