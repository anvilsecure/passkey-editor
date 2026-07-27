package com.anvil.passkeyeditor.util;

import burp.api.montoya.logging.Logging;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Output logging for the extension's own Output tab: each entry is prefixed with a {@code [HH:mm:ss]}
 * timestamp and nothing else - no per-line "Passkey …" tag, since Burp's per-extension Output tab already
 * identifies the source. A multi-line message keeps the single timestamp on its first line (continuation
 * lines stay indented), so a summary block reads as one timestamped entry rather than many.
 */
public final class Log {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private Log() {
    }

    /** Write {@code message} to the Output tab, prefixed with the current {@code [HH:mm:ss]}. */
    public static void out(Logging logging, String message) {
        if (logging != null) {
            logging.logToOutput("[" + LocalTime.now().format(TIME) + "] " + message);
        }
    }
}
