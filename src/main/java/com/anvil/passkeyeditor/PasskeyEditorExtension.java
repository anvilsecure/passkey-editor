package com.anvil.passkeyeditor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.crypto.SignerAlgorithm;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.http.PasskeyAutoHandler;
import com.anvil.passkeyeditor.http.PasskeyColorHandler;
import com.anvil.passkeyeditor.profile.BuiltinProfiles;
import com.anvil.passkeyeditor.profile.HostMatch;
import com.anvil.passkeyeditor.profile.ProfileRegistry;
import com.anvil.passkeyeditor.profile.ProfileStore;
import com.anvil.passkeyeditor.profile.TargetProfile;
import com.anvil.passkeyeditor.ui.Fonts;
import com.anvil.passkeyeditor.ui.editor.CeremonyRequestEditorProvider;
import com.anvil.passkeyeditor.ui.editor.CeremonyResponseEditorProvider;
import com.anvil.passkeyeditor.ui.settings.ProfileEditorTab;
import com.anvil.passkeyeditor.util.EditDiffCache;
import com.anvil.passkeyeditor.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Extension entry point (the only Burp-coupled bootstrap). Responsibilities:
 *   - set the extension name;
 *   - own the shared collaborators - one {@link ProfileRegistry}, one {@link Detector}, one
 *       {@link KeyStoreService} - and inject them into the request-editor provider AND the AUTO handler so a
 *       manual plant and AUTO re-sign read the same key store;
 *   - register the request/response editor providers (the manual "Passkey Editor" tab);
 *   - register the AUTO {@link PasskeyAutoHandler} (in-flight re-sign/plant, off by default, per-profile)
 *       and the {@link PasskeyColorHandler} (Proxy-history colouring of enabled-matched ceremonies);
 *   - register the Passkey Editor suite tab;
 *   - register an unloading handler that deregisters the HTTP handlers (BApp store requirement #6).
 *
 * Everything reachable from the handlers is the Burp-free core (detect / codec / model / crypto / attacks
 * / profile), which is JUnit-testable without Burp.
 */
public final class PasskeyEditorExtension implements BurpExtension {

    /** Display name shown in Burp's Extensions tab. */
    public static final String EXTENSION_NAME = "Passkey Editor";

    /** Build-stamped properties holding the project version (see {@code processResources}). */
    private static final String VERSION_RESOURCE = "/passkey-editor.properties";

    /**
     * Extension version, surfaced in the About tab and prefilled into bug-report links. Read from the
     * properties file the build stamps with the Gradle project version, so it tracks the version this
     * jar was built from instead of a copy pasted into source.
     */
    public static final String VERSION = readVersion();

    /**
     * Project repository, behind the About tab's links, the issue templates, and the Guide's pointer to
     * the README. Single source for all of them, so moving between GitHub organisations is one edit.
     */
    public static final String REPO_URL = "https://github.com/anvilsecure/passkey-editor";

    /**
     * The build-stamped version, or {@code dev} when the resource is absent (running straight from
     * compiled classes without the resource-processing step). Never throws: a missing or unreadable
     * version must not stop the extension from loading.
     */
    private static String readVersion() {
        try (InputStream in = PasskeyEditorExtension.class.getResourceAsStream(VERSION_RESOURCE)) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                String v = props.getProperty("version", "").trim();
                if (!v.isEmpty()) {
                    return v;
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // Fall through to the placeholder.
        }
        return "dev";
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        // Target Profiles: one registry shared by the request editors, the settings tab, AND the AUTO/colour
        // handlers. Only the Default seeds; per-target profiles are the operator's to create. The Default
        // keeps an unprofiled ceremony byte-identical and, being AUTO-inert, is structurally never
        // auto-rewritten.
        ProfileStore profileStore = new ProfileStore(api);
        // "First run" = this project has never written a profile list, NOT "the list is empty". An empty list
        // is the normal state before any target is added, and is also what deleting every profile leaves
        // behind, so keying off emptiness would re-announce a seed forever.
        boolean firstRun = !profileStore.hasStoredProfiles();
        List<TargetProfile> storedProfiles = firstRun ? List.of() : profileStore.load();
        // The Default is an editable profile with its own enabled switch, persisted in its own slot, so an
        // operator who disables it (or edits its locators) keeps that across a reload. Absent ⇒ seed the
        // built-in (enabled, byte-identical) and persist it so it is authoritative thereafter.
        TargetProfile storedDefault = profileStore.loadDefault();
        TargetProfile defaultProfile = storedDefault != null ? storedDefault : BuiltinProfiles.defaultProfile();
        ProfileRegistry profileRegistry = new ProfileRegistry(defaultProfile,
                storedProfiles == null ? List.of() : storedProfiles);
        if (firstRun) {
            // Write the (empty) list immediately so hasStoredProfiles() is true from the second load on.
            profileStore.save(profileRegistry.profiles());
        }
        if (storedDefault == null) {
            profileStore.saveDefault(profileRegistry.defaultProfile());
        }

        // Draw with Burp's own fonts, re-read live. Enlarging the message-editor font must enlarge the
        // decoded ceremony with it: it is the same request, one tab over.
        Fonts.useEditorFont(() -> api.userInterface().currentEditorFont());

        // Shared collaborators created ONCE: the detector (same default markers everywhere) and the key store
        // (so a "Register with our key" plant on the editor is the key the AUTO handler re-signs with).
        Detector detector = new Detector(new Config());
        KeyStoreService keyStore = new KeyStoreService();

        // One provider → the manual tab shows in Proxy, Repeater, … . isEnabledFor() is the only gate.
        api.userInterface().registerHttpRequestEditorProvider(
                new CeremonyRequestEditorProvider(api, profileRegistry, keyStore, detector));

        // The options-phase counterpart (UV-downgrade on a generate-*-options RESPONSE). Gets the registry so
        // its tab honours the profile's enabled switch (a disabled host is silenced).
        api.userInterface().registerHttpResponseEditorProvider(
                new CeremonyResponseEditorProvider(api, profileRegistry));

        // AUTO mode (off by default; per-profile autoPlant/autoResign): the in-flight re-signer/planter.
        // Registered on BOTH seams - the Proxy request handler (so the rewrite shows in Proxy history as
        // Original vs Edited) AND the HTTP handler (so Repeater is covered; it skips
        // Proxy-sourced requests, which the proxy seam already handled).
        PasskeyAutoHandler autoHandler = new PasskeyAutoHandler(api, detector, profileRegistry, keyStore);
        Registration autoHttpHandler = api.http().registerHttpHandler(autoHandler);
        Registration autoProxyHandler = api.proxy().registerRequestHandler(autoHandler);
        // The Proxy-history colour for enabled-matched ceremonies. One handler covers BOTH surfaces - verify
        // REQUESTS (request handler) and options RESPONSES (response handler) - so a tracked host's whole
        // ceremony lights up ORANGE (relevance only); AUTO keeps the same ORANGE and appends its [AUTO] note.
        PasskeyColorHandler colorHandler = new PasskeyColorHandler(detector, profileRegistry);
        Registration colorReqHandler = api.proxy().registerRequestHandler(colorHandler);
        Registration colorRespHandler = api.proxy().registerResponseHandler(colorHandler);

        // The integrated Passkey Editor tab: Profiles (manage + per-field config + per-profile AUTO toggles +
        // live Check) / Guide / About - persisted via profileStore.
        api.userInterface().registerSuiteTab(EXTENSION_NAME,
                new ProfileEditorTab(api, profileRegistry, profileStore).component());

        // BApp #6: release resources cleanly on unload - deregister the HTTP handlers so AUTO/colour stop
        // immediately when the extension is unloaded.
        api.extension().registerUnloadingHandler(() -> {
            autoHttpHandler.deregister();
            autoProxyHandler.deregister();
            colorReqHandler.deregister();
            colorRespHandler.deregister();
            // Purge in-memory credential material so nothing lingers after unload: planted private keys
            // (keyStore) and cached ceremony bodies (EditDiffCache) - both static/process-wide, so a Burp
            // reload-in-place would otherwise keep them for the JVM lifetime.
            keyStore.clear();
            EditDiffCache.clear();
            Fonts.clear();   // drop the MontoyaApi reference the font supplier closes over
            Log.out(api.logging(), "Passkey Editor unloaded");
        });

        Log.out(api.logging(), "Passkey Editor loaded");
        // Per-project visibility: list every profile active in THIS Burp project (profiles persist in the
        // project file via ProfileStore), so the operator can see at a glance which targets are tracked and
        // how each is armed, and whether they were loaded from the project or freshly seeded. Logged as ONE
        // timestamped entry (summary line + one indented line per profile).
        Log.out(api.logging(), String.join("\n", describeProfiles(profileRegistry, firstRun)));
    }

    /**
     * A human-readable, one-line-per-profile summary for the Output log at load. Profiles are persisted
     * per-Burp-project (the {@link ProfileStore} writes to {@code persistence().extensionData()}, the project
     * file), so this confirms which profiles this project carries and how each is configured. Pure and
     * Burp-free, so it is unit-tested headlessly.
     *
     * @param seeded {@code true} when this run seeded the Default (first run for this project) vs loaded a
     *               previously-saved set from the project file
     */
    static List<String> describeProfiles(ProfileRegistry registry, boolean seeded) {
        List<TargetProfile> listed = registry.profiles();
        List<String> lines = new ArrayList<>();
        // The Default counts towards the total and is listed like any other row: it is an ordinary editable
        // profile, just one that cannot be deleted or AUTO-armed.
        lines.add((listed.size() + 1) + " profile(s) "
                + (seeded ? "seeded (first run for this project, saved to the project file)"
                          : "loaded from this Burp project")
                + ". Edit them in the Passkey Editor tab; they persist per project.");
        lines.add("  - " + describeProfile(registry.defaultProfile()));
        for (TargetProfile p : listed) {
            lines.add("  - " + describeProfile(p));
        }
        return lines;
    }

    /** One profile rendered as {@code name  host=…  [enabled|disabled]  plant=… re-sign=…  alg=…  att=…}. */
    private static String describeProfile(TargetProfile p) {
        String alg = SignerAlgorithm.forCoseIdOrDefault(p.signer().coseAlg(), SignerAlgorithm.ES256).label();
        return p.name() + "  host=" + describeHost(p.host())
                + "  [" + (p.enabled() ? "enabled" : "disabled") + "]"
                + "  plant=" + (p.autoPlant() ? "on" : "off")
                + "  re-sign=" + (p.autoResign() ? "on" : "off")
                + "  alg=" + alg
                + "  att=" + p.plantAttestation().name();
    }

    /** A compact, readable host-rule rendering ({@code any} / {@code host} / {@code *.suffix} / {@code ~regex}). */
    private static String describeHost(HostMatch host) {
        return switch (host.kind()) {
            case ANY -> "any";
            case EXACT -> host.pattern();
            case SUFFIX -> "*" + host.pattern();
            case REGEX -> "~" + host.pattern();
        };
    }
}
