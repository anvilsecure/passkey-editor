package com.anvil.passkeyeditor.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Pins WHICH Burp tools AUTO is allowed to rewrite traffic in, on the {@code HttpHandler} seam.
 *
 * This exists because the gate was wrong once, in a way no test could catch: the seam tested only for
 * {@code ToolType.PROXY} (a de-duplication guard against the sibling proxy seam, never intended as a tool
 * policy), which left the other twelve {@code ToolType} values reaching {@code plant()} / {@code resign()}
 * on an armed host. Confirmed on the wire before the fix: an Intruder attack re-signed every assertion it
 * re-issued, and a single active scan of one {@code /registration/verification} request planted ~10 distinct
 * attacker keys on the account - which also pushed {@code keyStore.size()} past 1 and silently disabled the
 * most-recent-key fallback in {@code resolveHeld} for the rest of the session.
 *
 * The shipped docs (the Guide's AUTO section, the README's Responsible use note) name the surface AUTO acts
 * in. If someone widens {@link PasskeyAutoHandler#AUTO_TOOLS} without updating them, that is a claim/behaviour
 * divergence in a tool that forges credentials - so this test fails on ANY change to the set, not just on a
 * dangerous one. Widening it deliberately means updating this test and both documents in the same commit.
 */
class PasskeyAutoToolGateTest {

    /** Fake a {@link ToolSource} for one tool - Montoya is an interface-only API, so a JDK proxy is enough. */
    private static ToolSource sourceOf(ToolType actual) {
        return (ToolSource) Proxy.newProxyInstance(
                PasskeyAutoToolGateTest.class.getClassLoader(),
                new Class<?>[] { ToolSource.class },
                (InvocationHandler) (proxy, method, args) -> switch (method.getName()) {
                    case "toolType" -> actual;
                    // isFromTool is varargs: true when ANY of the queried types matches, mirroring Burp.
                    case "isFromTool" -> Arrays.asList((ToolType[]) args[0]).contains(actual);
                    case "toString" -> "ToolSource(" + actual + ")";
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> null;
                });
    }

    @Test
    void repeaterIsTheOnlyToolAutoActsInOnThisSeam() {
        assertEquals(EnumSet.of(ToolType.REPEATER), PasskeyAutoHandler.AUTO_TOOLS,
                "AUTO_TOOLS changed. This is a behaviour change in a credential-forging tool: update the "
                        + "Guide's AUTO section and the README's Responsible use note in the same commit.");
        assertTrue(PasskeyAutoHandler.isAutoTool(sourceOf(ToolType.REPEATER)));
    }

    @Test
    void everyOtherToolIsExcluded() {
        // The whole enum, minus Repeater: an exhaustive sweep, so a ToolType added by a future Montoya
        // release is excluded by default rather than silently admitted.
        Set<ToolType> excluded = EnumSet.complementOf(EnumSet.copyOf(PasskeyAutoHandler.AUTO_TOOLS));
        for (ToolType tool : excluded) {
            assertFalse(PasskeyAutoHandler.isAutoTool(sourceOf(tool)),
                    tool + " must not be auto-rewritten on the HttpHandler seam");
        }
    }

    @Test
    void theThreeToolsThatCausedTheIncidentAreNamedExplicitly() {
        // Belt and braces over the sweep above: these three are the ones live-confirmed to auto-forge, and
        // they are the ones a future "just let it run everywhere" change would most plausibly re-admit.
        assertFalse(PasskeyAutoHandler.isAutoTool(sourceOf(ToolType.SCANNER)));
        assertFalse(PasskeyAutoHandler.isAutoTool(sourceOf(ToolType.INTRUDER)));
        assertFalse(PasskeyAutoHandler.isAutoTool(sourceOf(ToolType.RECORDED_LOGIN_REPLAYER)));
    }

    @Test
    void proxyIsExcludedHereBecauseTheProxySeamOwnsIt() {
        // Not a safety exclusion but a double-rewrite one: PasskeyAutoHandler is registered on both seams,
        // and the proxy seam is what records EditDiffCache + gives Burp its Original vs Edited view.
        assertFalse(PasskeyAutoHandler.isAutoTool(sourceOf(ToolType.PROXY)));
    }

    @Test
    void aNullToolSourceIsTreatedAsExcluded() {
        // Fail-CLOSED on unknown provenance: this seam rewrites live traffic, so an unprovable tool means
        // don't act. (Tab visibility fails OPEN instead - see ProfileRegistry.tabVisibleFor.)
        assertFalse(PasskeyAutoHandler.isAutoTool(null));
    }
}
