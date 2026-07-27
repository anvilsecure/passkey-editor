package com.anvil.passkeyeditor.attacks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The framing / clickjacking forge ({@code crossOrigin → true} + {@code topOrigin → attacker}) on a captured
 * {@code clientDataJSON}. The oracle it serves: an RP that validates {@code origin} but not the framing pair
 * (CWE-1021) accepts a cross-origin ceremony (the live half is the operator's, and needs a credential whose
 * key the tester controls to re-sign). Here we prove the transform itself: it sets exactly
 * {@code crossOrigin}/{@code topOrigin}, leaves {@code origin} and every other member byte-identical, stays
 * valid JSON, is idempotent, and never throws.
 */
class CrossOriginForgeAttackTest {

    private final CrossOriginForgeAttack attack = new CrossOriginForgeAttack();

    private static final String ATTACKER = "https://attacker.example";

    /** A same-origin clientDataJSON that omits crossOrigin/topOrigin entirely (the common capture). */
    private static final String SAME_ORIGIN_NO_FLAGS =
            "{\"type\":\"webauthn.get\",\"challenge\":\"Y2g\",\"origin\":\"https://rp.example\"}";

    /** A clientDataJSON that carries crossOrigin=false (a browser's same-origin ceremony). */
    private static final String SAME_ORIGIN_CROSS_FALSE =
            "{\"type\":\"webauthn.get\",\"challenge\":\"Y2g\",\"origin\":\"https://rp.example\",\"crossOrigin\":false}";

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String str(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    private static JsonObject parse(byte[] body) {
        return JsonParser.parseString(str(body)).getAsJsonObject();
    }

    @Test
    void insertsCrossOriginAndTopOriginWhenBothAbsent() {
        CrossOriginForgeAttack.Result r = attack.forge(utf8(SAME_ORIGIN_NO_FLAGS), ATTACKER);

        assertTrue(r.changed());
        assertNull(r.previousCrossOrigin(), "crossOrigin was absent");
        assertNull(r.previousTopOrigin(), "topOrigin was absent");
        JsonObject o = parse(r.clientData());
        assertTrue(o.get("crossOrigin").getAsBoolean(), "crossOrigin now true");
        assertEquals(ATTACKER, o.get("topOrigin").getAsString(), "topOrigin now the attacker origin");
        // origin (and type/challenge) byte-identical.
        assertEquals("https://rp.example", o.get("origin").getAsString());
        assertEquals("webauthn.get", o.get("type").getAsString());
        assertEquals("Y2g", o.get("challenge").getAsString());
    }

    @Test
    void flipsCrossOriginFalseToTrue() {
        CrossOriginForgeAttack.Result r = attack.forge(utf8(SAME_ORIGIN_CROSS_FALSE), ATTACKER);

        assertTrue(r.changed());
        assertEquals(Boolean.FALSE, r.previousCrossOrigin(), "the captured crossOrigin was false");
        JsonObject o = parse(r.clientData());
        assertTrue(o.get("crossOrigin").getAsBoolean());
        assertEquals(ATTACKER, o.get("topOrigin").getAsString());
        assertEquals("https://rp.example", o.get("origin").getAsString(), "origin left intact");
    }

    @Test
    void leavesOriginByteIdentical() {
        // The whole point of the attack: origin must not move. Prove it on the byte level, not just parsed.
        byte[] in = utf8(SAME_ORIGIN_CROSS_FALSE);
        byte[] out = attack.forge(in, ATTACKER).clientData();
        String needle = "\"origin\":\"https://rp.example\"";
        assertTrue(str(out).contains(needle), "the exact origin member bytes survive verbatim");
        // Only crossOrigin flipped + topOrigin appended: reconstruct the expected body to prove byte-identity.
        assertEquals("{\"type\":\"webauthn.get\",\"challenge\":\"Y2g\",\"origin\":\"https://rp.example\","
                + "\"crossOrigin\":true,\"topOrigin\":\"" + ATTACKER + "\"}", str(out));
    }

    @Test
    void insertsTopOriginWhenCrossOriginAlreadyPresent() {
        // crossOrigin present-and-true, topOrigin absent → only topOrigin is inserted.
        byte[] in = utf8("{\"type\":\"webauthn.get\",\"origin\":\"https://rp.example\",\"crossOrigin\":true}");
        CrossOriginForgeAttack.Result r = attack.forge(in, ATTACKER);

        assertTrue(r.changed());
        assertEquals(Boolean.TRUE, r.previousCrossOrigin());
        assertNull(r.previousTopOrigin());
        assertEquals(ATTACKER, parse(r.clientData()).get("topOrigin").getAsString());
    }

    @Test
    void replacesExistingTopOrigin() {
        byte[] in = utf8("{\"origin\":\"https://rp.example\",\"crossOrigin\":true,"
                + "\"topOrigin\":\"https://old.example\"}");
        CrossOriginForgeAttack.Result r = attack.forge(in, ATTACKER);

        assertTrue(r.changed());
        assertEquals("https://old.example", r.previousTopOrigin());
        assertEquals(ATTACKER, parse(r.clientData()).get("topOrigin").getAsString());
        assertEquals("https://rp.example", parse(r.clientData()).get("origin").getAsString());
    }

    @Test
    void alreadyForgedIsIdempotentNoOp() {
        byte[] in = utf8("{\"origin\":\"https://rp.example\",\"crossOrigin\":true,\"topOrigin\":\"" + ATTACKER + "\"}");
        CrossOriginForgeAttack.Result r = attack.forge(in, ATTACKER);

        assertFalse(r.changed(), "crossOrigin already true + same topOrigin ⇒ no edit");
        assertSame(in, r.clientData(), "a no-op must return the original array reference");
    }

    @Test
    void isIdempotentAcrossRepeatedApplication() {
        byte[] once = attack.forge(utf8(SAME_ORIGIN_CROSS_FALSE), ATTACKER).clientData();
        CrossOriginForgeAttack.Result twice = attack.forge(once, ATTACKER);

        assertFalse(twice.changed(), "second application must be a no-op");
        assertArrayEquals(once, twice.clientData());
    }

    @Test
    void nullTopOriginSetsOnlyCrossOrigin() {
        CrossOriginForgeAttack.Result r = attack.forge(utf8(SAME_ORIGIN_CROSS_FALSE), null);

        assertTrue(r.changed());
        JsonObject o = parse(r.clientData());
        assertTrue(o.get("crossOrigin").getAsBoolean());
        assertFalse(o.has("topOrigin"), "no topOrigin edit when the argument is null");
        assertEquals("https://rp.example", o.get("origin").getAsString());
    }

    @Test
    void outputAlwaysParsesAsJson() {
        // Whitespaced body: insertion must keep it well-formed JSON.
        byte[] in = utf8("{ \"type\" : \"webauthn.get\" , \"origin\" : \"https://rp.example\" }");
        byte[] out = attack.forge(in, ATTACKER).clientData();
        JsonObject o = parse(out); // throws if not valid JSON
        assertTrue(o.get("crossOrigin").getAsBoolean());
        assertEquals(ATTACKER, o.get("topOrigin").getAsString());
        assertEquals("https://rp.example", o.get("origin").getAsString());
    }

    @Test
    void malformedBodyIsNoOpNoThrow() {
        for (String bad : new String[]{"", "not json at all", "[1,2,3]", "{", "\"just a string\""}) {
            byte[] in = utf8(bad);
            CrossOriginForgeAttack.Result r = attack.forge(in, ATTACKER);
            assertFalse(r.changed(), "malformed/non-object body must be a no-op: " + bad);
            assertSame(in, r.clientData(), "no-op returns the original reference: " + bad);
        }
    }

    @Test
    void nullBodyDoesNotThrow() {
        CrossOriginForgeAttack.Result r = attack.forge(null, ATTACKER);
        assertFalse(r.changed());
        assertEquals(0, r.clientData().length);
    }
}
