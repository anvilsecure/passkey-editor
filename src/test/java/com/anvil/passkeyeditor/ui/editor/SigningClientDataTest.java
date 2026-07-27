package com.anvil.passkeyeditor.ui.editor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.anvil.passkeyeditor.model.ClientData;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Assertion re-sign must cover the exact clientDataJSON on the wire, or refuse. The signed input is
 * {@code authData ‖ SHA-256(clientDataJSON)}; the editor previously fell back to {@code new byte[0]} when
 * clientDataJSON had not decoded, silently signing over {@code SHA-256("")} while the wire kept the real
 * bytes — an invalid forgery reported as success. {@link CeremonyRequestEditor#signingClientData} now
 * returns {@code null} (fail closed) instead of a placeholder, so the caller refuses rather than forges garbage.
 */
class SigningClientDataTest {

    @Test
    void editedBytesWinOverTheModel() {
        byte[] edited = "{\"type\":\"webauthn.get\"}".getBytes(StandardCharsets.UTF_8);
        ClientData model = new ClientData("{\"origin\":\"https://rp.test\"}".getBytes(StandardCharsets.UTF_8));
        assertSame(edited, CeremonyRequestEditor.signingClientData(edited, model),
                "an operator edit is what gets signed");
    }

    @Test
    void fallsBackToTheModelWireBytesWhenNotEdited() {
        byte[] wire = "{\"origin\":\"https://rp.test\"}".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(wire, CeremonyRequestEditor.signingClientData(null, new ClientData(wire)),
                "unedited: sign the exact decoded wire bytes");
    }

    @Test
    void nullWhenClientDataDidNotDecode() {
        // The regression pin: clientDataJSON unavailable must yield null (refuse), NOT an empty placeholder
        // that would be hashed into a signature the RP rejects.
        assertNull(CeremonyRequestEditor.signingClientData(null, null),
                "no model clientData → null, never new byte[0]");
        assertNull(CeremonyRequestEditor.signingClientData(null, new ClientData()),
                "model present but raw() null → null, never new byte[0]");
        assertNull(CeremonyRequestEditor.signingClientData(null, new ClientData(null)),
                "model with null raw → null");
    }
}
