package com.anvil.passkeyeditor.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import com.anvil.passkeyeditor.config.Config;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.ProfileRegistry;

/**
 * The response editor provider - the options-phase counterpart of
 * {@link CeremonyRequestEditorProvider}. Registered once via {@code registerHttpResponseEditorProvider},
 * it makes the "Passkey Editor" tab appear on a {@code generate-*-options} response across Proxy,
 * Repeater, and Intercept with no per-tool code; the returned editor's {@code isEnabledFor()} is the
 * only gate.
 *
 * It builds its own cheap, immutable {@link Config}/{@link Detector}, and is handed the shared
 * {@link ProfileRegistry} so the options tab honours each profile's enabled switch (a disabled host
 * is silenced) - symmetric with the request provider.
 */
public final class CeremonyResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final Config config;
    private final Detector detector;
    private final ProfileRegistry registry;

    public CeremonyResponseEditorProvider(MontoyaApi api, ProfileRegistry registry) {
        this.api = api;
        this.config = new Config();
        this.detector = new Detector(config);
        this.registry = registry;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
        return new CeremonyResponseEditor(api, context, detector, registry);
    }
}
