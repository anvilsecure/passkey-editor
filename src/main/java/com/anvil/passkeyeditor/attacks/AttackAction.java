package com.anvil.passkeyeditor.attacks;

import com.anvil.passkeyeditor.model.CeremonyModel;

/**
 * A one-click transform applied to a decoded ceremony from the "Attacks ▾" dropdown.
 *
 * An action mutates the {@link CeremonyModel} in place; the editor then re-encodes → (re-signs if
 * needed) → re-wraps → splices the result back into the request on the next {@code getRequest()}.
 * {@link SigStripAttack} is the implementor (no crypto). The forge attacks
 * ({@code RegistrationSubstituter} / {@code AssertionForger}) are separate collaborators the editor
 * invokes directly rather than through this model-mutation interface. The {@link #apply} contract is
 * intentionally model-only and Burp-free so each attack is unit-testable in isolation.
 */
public interface AttackAction {

    /** Human-readable label shown in the Attacks dropdown. */
    String name();

    /**
     * Apply the attack transform to {@code model} in place.
     *
     * @param model the decoded ceremony to mutate
     */
    void apply(CeremonyModel model);
}
