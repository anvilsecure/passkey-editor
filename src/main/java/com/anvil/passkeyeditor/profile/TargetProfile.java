package com.anvil.passkeyeditor.profile;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * A complete per-RP recipe: which host its verify traffic is on, and where each WebAuthn field lives in
 * each phase's body.
 *
 * Pure data. The engine reads profiles; it has no per-RP code. A profile is built-in (seeded
 * config - {@link BuiltinProfiles}), hand-entered (the settings form), or auto-learned - all
 * three are the same data consumed by the same locator. This is what makes the tool adapt to any
 * RP instead of hardcoding shapes.
 *
 * {@code enabled} is the operator's per-profile activation switch: only enabled profiles take part in
 * host matching, so a profile can be staged + validated in the Check panel and flipped on only once green
 * (the Default fallback is always effectively on). Defaults to {@code true} via the back-compat constructor.
 *
 * {@code sampleRegBody} / {@code sampleAuthBody} are the operator's pasted registration / authentication
 * bodies for the Check panel - per-profile scratch, persisted so they reload with the profile (not part of
 * the extraction logic; nullable).
 *
 * {@code signer} is the profile's default signing algorithm ({@link SignerSpec}): the algorithm
 * the manual chooser pre-selects when this profile matches, and the one AUTO mode plants / re-signs under.
 * Defaults to {@link SignerSpec#ES256} via the back-compat constructors and the compact constructor (a
 * {@code null} normalises to ES256), so an unset signer keeps the default path byte-identical (freeze-safe).
 *
 * {@code plantAttestation} is the attestation format AUTO plants under ({@link PlantAttestation}) -
 * {@code fmt="none"} or a packed self-attestation - orthogonal to {@code signer} (any algorithm works with
 * either format). Defaults to {@link PlantAttestation#NONE} (a {@code null} normalises to NONE), so an unset
 * value keeps the historical plant behaviour (freeze-safe).
 *
 * {@code enabled}, {@code autoPlant} and {@code autoResign} are three orthogonal per-profile
 * switches (AUTO):
 *   - {@code enabled} → the manual path: the Passkey Editor tab shows on matched req/resp (and the
 *       request is coloured in Proxy history). Defaults {@code true} (back-compat).
 *   - {@code autoPlant} → AUTO substitutes our key on a matched registration (REG_VERIFY), in-flight.
 *   - {@code autoResign} → AUTO re-signs a matched authentication (AUTH_VERIFY) with the held key.
 * The auto flags default {@code false}, so a profile (and the Default) is AUTO-inert unless deliberately
 * armed - an unprofiled host is never auto-rewritten (freeze-safe). Arming implies {@code enabled}:
 * {@code Enabled} is the master switch, so a profile armed for either AUTO action is forced enabled by the
 * compact constructor below (you cannot have a disabled profile that still rewrites live traffic). A profile
 * with all three off is inert (ignored by matching entirely).
 */
public record TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases,
                            boolean enabled, String sampleRegBody, String sampleAuthBody, SignerSpec signer,
                            boolean autoPlant, boolean autoResign, PlantAttestation plantAttestation) {

    public TargetProfile {
        // EnumMap, not Map.copyOf: keep a deterministic Phase-declaration (ordinal) iteration order so a
        // re-persisted/exported profile set is byte-stable across JVM runs (Map.copyOf randomises enum-key
        // order per run). EnumMap's map ctor rejects an empty non-EnumMap, so guard the empty case.
        phases = phases.isEmpty() ? Map.of() : Collections.unmodifiableMap(new EnumMap<>(phases));
        signer = signer != null ? signer : SignerSpec.ES256;
        plantAttestation = plantAttestation != null ? plantAttestation : PlantAttestation.NONE;
        // Enabled is the master switch: any AUTO flag implies Enabled, so a disabled profile is fully inert
        // (no tab, no colour, AND no auto-rewrite). Normalises stores / UI / programmatic builds uniformly.
        enabled = enabled || autoPlant || autoResign;
    }

    /** Back-compat: enabled by default, no sample bodies, ES256 signer, AUTO off, NONE attestation. */
    public TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases) {
        this(id, name, host, phases, true, null, null, SignerSpec.ES256, false, false, PlantAttestation.NONE);
    }

    /** Back-compat: explicit enabled, no sample bodies, ES256 signer, AUTO off, NONE attestation. */
    public TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases, boolean enabled) {
        this(id, name, host, phases, enabled, null, null, SignerSpec.ES256, false, false, PlantAttestation.NONE);
    }

    /** Back-compat: explicit enabled + sample bodies, ES256 signer, AUTO off, NONE attestation. */
    public TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases,
                         boolean enabled, String sampleRegBody, String sampleAuthBody) {
        this(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, SignerSpec.ES256, false, false,
                PlantAttestation.NONE);
    }

    /** Back-compat: explicit signer (pre-AUTO canonical shape, used positionally by tests), AUTO off, NONE attestation. */
    public TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases,
                         boolean enabled, String sampleRegBody, String sampleAuthBody, SignerSpec signer) {
        this(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer, false, false,
                PlantAttestation.NONE);
    }

    /** Back-compat: the pre-attestation canonical shape (10-arg, used positionally by tests) - NONE attestation. */
    public TargetProfile(String id, String name, HostMatch host, Map<Phase, PhaseSpec> phases,
                         boolean enabled, String sampleRegBody, String sampleAuthBody, SignerSpec signer,
                         boolean autoPlant, boolean autoResign) {
        this(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer, autoPlant, autoResign,
                PlantAttestation.NONE);
    }

    /** The spec for {@code phase}, or {@code null} if this profile does not define it. */
    public PhaseSpec phase(Phase phase) {
        return phases.get(phase);
    }

    /** Whether AUTO acts for {@code phase}: auto-plant on REG_VERIFY, auto-re-sign on AUTH_VERIFY. */
    public boolean autoActsFor(Phase phase) {
        return (phase == Phase.REG_VERIFY && autoPlant) || (phase == Phase.AUTH_VERIFY && autoResign);
    }

    /** A copy of this profile with {@code enabled} set (the manual-path activation toggle). */
    public TargetProfile withEnabled(boolean enabled) {
        return new TargetProfile(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer,
                autoPlant, autoResign, plantAttestation);
    }

    /** A copy carrying the operator's pasted sample reg/auth bodies (Check-panel scratch). */
    public TargetProfile withSamples(String regBody, String authBody) {
        return new TargetProfile(id, name, host, phases, enabled, regBody, authBody, signer,
                autoPlant, autoResign, plantAttestation);
    }

    /** A copy with a different default signing algorithm. */
    public TargetProfile withSigner(SignerSpec signer) {
        return new TargetProfile(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer,
                autoPlant, autoResign, plantAttestation);
    }

    /** A copy with the auto-plant (REG_VERIFY) switch set. */
    public TargetProfile withAutoPlant(boolean autoPlant) {
        return new TargetProfile(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer,
                autoPlant, autoResign, plantAttestation);
    }

    /** A copy with the auto-re-sign (AUTH_VERIFY) switch set. */
    public TargetProfile withAutoResign(boolean autoResign) {
        return new TargetProfile(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer,
                autoPlant, autoResign, plantAttestation);
    }

    /** A copy with a different AUTO plant attestation format ({@link PlantAttestation}). */
    public TargetProfile withPlantAttestation(PlantAttestation plantAttestation) {
        return new TargetProfile(id, name, host, phases, enabled, sampleRegBody, sampleAuthBody, signer,
                autoPlant, autoResign, plantAttestation);
    }
}
