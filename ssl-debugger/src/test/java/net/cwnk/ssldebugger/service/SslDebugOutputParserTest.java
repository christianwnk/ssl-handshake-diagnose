package net.cwnk.ssldebugger.service;

import net.cwnk.ssldebugger.model.HandshakeStep;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SslDebugOutputParserTest {

    private final SslDebugOutputParser parser = new SslDebugOutputParser();

    @Test
    void parseTls13Format() {
        String raw = """
                javax.net.ssl|DEBUG|01|main|2024-01-01 00:00:00.000 UTC|ClientHello.java:100|
                Produced ClientHello handshake message (
                "ClientHello": {
                  "client version"      : "TLSv1.3",
                  "cipher suites"       : "[TLS_AES_256_GCM_SHA384]"
                })
                javax.net.ssl|DEBUG|01|main|2024-01-01 00:00:00.001 UTC|ServerHello.java:100|
                Consuming ServerHello handshake message (
                "ServerHello": {
                  "server version"      : "TLSv1.3"
                })
                javax.net.ssl|DEBUG|01|main|2024-01-01 00:00:00.002 UTC|Finished.java:100|
                Consuming Finished handshake message (
                "Finished": {}
                )
                """;

        List<HandshakeStep> steps = parser.parse(raw);

        assertEquals(3, steps.size());
        assertEquals("ClientHello", steps.get(0).name());
        assertEquals("ServerHello", steps.get(1).name());
        assertEquals("Finished", steps.get(2).name());
    }

    @Test
    void parseTls12Format() {
        String raw = """
                *** ClientHello, TLSv1.2
                RandomCookie: ...
                *** ServerHello, TLSv1.2
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                *** Certificate chain
                *** ServerHelloDone
                *** Finished
                verify_data: { 0, 1, 2 }
                """;

        List<HandshakeStep> steps = parser.parse(raw);

        assertFalse(steps.isEmpty());
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("ClientHello")));
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("ServerHello")));
        assertTrue(steps.stream().anyMatch(s -> s.name().equals("Finished")));
    }

    @Test
    void returnsEmptyListForBlankInput() {
        assertTrue(parser.parse("").isEmpty());
        assertTrue(parser.parse(null).isEmpty());
        assertTrue(parser.parse("   \n  ").isEmpty());
    }

    @Test
    void doesNotDuplicateStepsForSameLine() {
        String raw = "Produced ClientHello handshake message\n*** ClientHello, TLSv1.2\n";
        List<HandshakeStep> steps = parser.parse(raw);
        // TLS13 pattern matches first line, TLS12 pattern matches second line — should have 2 distinct steps
        assertEquals(2, steps.size());
    }
}
