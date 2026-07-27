package com.anvil.passkeyeditor.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import com.anvil.passkeyeditor.crypto.KeyStoreService;
import com.anvil.passkeyeditor.detect.Detector;
import com.anvil.passkeyeditor.profile.ProfileRegistry;

/**
 * The single editor provider. Registered once via {@code registerHttpRequestEditorProvider}, it is
 * why the "Passkey Editor" tab appears in Proxy and Repeater with no per-tool code: Burp
 * calls {@link #provideHttpRequestEditor} once per host editor, and {@code isEnabledFor()} on the
 * returned editor is the only gate.
 *
 * The {@link Detector} and the {@link KeyStoreService} are created once in {@link
 * com.anvil.passkeyeditor.PasskeyEditorExtension} and injected here, so they are shared with the AUTO
 * {@link com.anvil.passkeyeditor.http.PasskeyAutoHandler}. Sharing the key store is load-bearing: the
 * substituted keypair stored when you "Register with our key" on one message must be retrievable both when
 * you forge an assertion on another tab AND when the AUTO handler re-signs in-flight (otherwise a manual
 * plant and AUTO would see two separate stores).
 */
public final class CeremonyRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final Detector detector;
    private final KeyStoreService keyStore;
    private final ProfileRegistry registry;

    public CeremonyRequestEditorProvider(MontoyaApi api, ProfileRegistry registry,
                                         KeyStoreService keyStore, Detector detector) {
        this.api = api;
        this.registry = registry;
        this.keyStore = keyStore;
        this.detector = detector;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
        return new CeremonyRequestEditor(api, context, detector, keyStore, registry);
    }
}
