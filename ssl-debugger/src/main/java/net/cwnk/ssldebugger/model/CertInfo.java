package net.cwnk.ssldebugger.model;

import java.util.List;

public record CertInfo(
        int index,
        String subject,
        String issuer,
        String notBefore,
        String notAfter,
        List<String> sans,
        String fingerprint
) {
}
