package net.cwnk.ssldebugger.service;

import net.cwnk.ssldebugger.model.HandshakeStep;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw JSSE debug output (from javax.net.debug=ssl:handshake:verbose) into
 * structured HandshakeStep entries. Handles both TLS 1.2 (*** MessageName format)
 * and TLS 1.3 (Produced/Consuming MessageName handshake message format).
 */
public class SslDebugOutputParser {

    // TLS 1.3 format: "Produced ClientHello handshake message" or "Consuming ServerHello handshake message"
    private static final Pattern TLS13_PATTERN =
            Pattern.compile("(?:Produced|Consuming)\\s+(\\w+(?:\\s+\\w+)?)\\s+handshake message");

    // TLS 1.2 format: "*** ClientHello, ..." or "*** Finished"
    private static final Pattern TLS12_PATTERN =
            Pattern.compile("^\\*\\*\\*\\s+(\\w+(?:\\s+\\w+)?)(?:,.*)?$");

    public List<HandshakeStep> parse(String rawOutput) {
        List<HandshakeStep> steps = new ArrayList<>();
        if (rawOutput == null || rawOutput.isBlank()) {
            return steps;
        }

        String[] lines = rawOutput.split("\\R");
        long timestamp = System.currentTimeMillis();
        int lineCount = lines.length;

        for (int i = 0; i < lineCount; i++) {
            String line = lines[i];

            // Check TLS 1.3 pattern
            Matcher m13 = TLS13_PATTERN.matcher(line);
            if (m13.find()) {
                String name = normalizeStepName(m13.group(1));
                String details = extractDetails(lines, i + 1, 15);
                steps.add(new HandshakeStep(name, details, timestamp++));
                continue;
            }

            // Check TLS 1.2 pattern (only on lines that look like JSSE output markers)
            String trimmed = line.trim();
            Matcher m12 = TLS12_PATTERN.matcher(trimmed);
            if (m12.matches()) {
                String name = normalizeStepName(m12.group(1));
                String details = extractDetails(lines, i + 1, 10);
                steps.add(new HandshakeStep(name, details, timestamp++));
            }
        }

        return steps;
    }

    private String normalizeStepName(String raw) {
        return switch (raw.trim()) {
            case "client_hello", "ClientHello" -> "ClientHello";
            case "server_hello", "ServerHello" -> "ServerHello";
            case "Certificate" -> "Certificate";
            case "CertificateRequest" -> "CertificateRequest";
            case "CertificateVerify" -> "CertificateVerify";
            case "ServerHelloDone" -> "ServerHelloDone";
            case "ClientKeyExchange" -> "ClientKeyExchange";
            case "NewSessionTicket" -> "NewSessionTicket";
            case "EncryptedExtensions" -> "EncryptedExtensions";
            case "Finished" -> "Finished";
            default -> raw.trim();
        };
    }

    /**
     * Extracts up to maxLines of meaningful detail from the lines following a step marker.
     * Stops early if another step marker is encountered.
     */
    private String extractDetails(String[] lines, int startIndex, int maxLines) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(startIndex + maxLines, lines.length);
        for (int i = startIndex; i < end; i++) {
            String line = lines[i].trim();
            if (line.isBlank()) continue;
            // Stop if we hit the next step marker
            if (TLS12_PATTERN.matcher(line).matches() || TLS13_PATTERN.matcher(line).find()) break;
            // Skip pure JSSE header lines (javax.net.ssl|...)
            if (line.startsWith("javax.net.ssl|")) {
                // Extract the message part after the last pipe
                int lastPipe = line.lastIndexOf('|');
                if (lastPipe >= 0 && lastPipe < line.length() - 1) {
                    line = line.substring(lastPipe + 1).trim();
                }
            }
            if (!line.isBlank()) {
                if (!sb.isEmpty()) sb.append('\n');
                sb.append(line);
            }
        }
        return sb.toString();
    }
}
