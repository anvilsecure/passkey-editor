package com.anvil.passkeyeditor.util;

import java.util.regex.Pattern;

/**
 * Runs an operator-supplied regex without letting catastrophic backtracking hang a per-request Burp
 * callback (the UI thread). A length cap bounds the input; a deterministic step budget bounds the
 * matching work - a {@link java.util.regex.Matcher} drives its backtracking through {@code charAt}, so a
 * pathological pattern trips the budget (surfaced as a thrown {@link RuntimeException} the caller turns into
 * a clean "no match") instead of spinning forever.
 *
 * Shared by every place a user pattern is matched per request: {@code FieldLocator} (REGEX field
 * locator - needs the {@link java.util.regex.Matcher} for capture-group spans), and {@code HostMatch} /
 * {@code UrlMatch} (host + verify-URL scope - boolean find). Centralising it keeps one budget definition
 * rather than re-deriving it per call site.
 */
public final class SafeRegex {

    private SafeRegex() {
    }

    /** Input-length cap for a user regex (defence in depth alongside the step budget). */
    public static final int MAX_INPUT = 1 << 20; // 1 MiB
    /**
     * Backtracking step budget: {@code charAt} reads a {@link java.util.regex.Matcher} may make before we
     * abort. A length cap alone does NOT bound catastrophic backtracking (exponential in the pattern, not
     * the input). 50M cleanly separates a legit linear scan over the full input cap (a few million reads)
     * from an exponential blow-up (billions), and aborts the latter in tens of ms.
     */
    public static final int MAX_STEPS = 50_000_000;

    /**
     * A length-capped, step-budgeted {@link CharSequence} view of {@code s} to hand to
     * {@code Pattern.matcher(...)}. The returned sequence throws once {@link #MAX_STEPS} reads are made, so
     * a runaway match aborts; the caller catches that to return null/false.
     */
    public static CharSequence budgeted(String s) {
        CharSequence capped = s.length() > MAX_INPUT ? s.subSequence(0, MAX_INPUT) : s;
        return new BudgetedCharSequence(capped, MAX_STEPS);
    }

    /**
     * {@code pattern.find()} over {@code input} under the input cap + step budget. Returns {@code false} on
     * no match, a runaway pattern (budget exceeded), or any other matcher error - never throws/hangs into a
     * per-request gate.
     */
    public static boolean find(Pattern pattern, String input) {
        if (pattern == null || input == null) {
            return false;
        }
        try {
            return pattern.matcher(budgeted(input)).find();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * A {@link CharSequence} that throws after a fixed number of {@link #charAt} reads - a deterministic
     * backtracking step budget. {@code length}/{@code toString} are not budgeted (cheap, bounded);
     * {@code subSequence} is off the hot path for the callers here (spans come from {@code start/end}).
     */
    private static final class BudgetedCharSequence implements CharSequence {
        private final CharSequence delegate;
        private int budget;

        BudgetedCharSequence(CharSequence delegate, int budget) {
            this.delegate = delegate;
            this.budget = budget;
        }

        @Override
        public char charAt(int index) {
            if (--budget < 0) {
                throw new IllegalStateException("regex step budget exceeded");
            }
            return delegate.charAt(index);
        }

        @Override
        public int length() {
            return delegate.length();
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return delegate.subSequence(start, end);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }
}
