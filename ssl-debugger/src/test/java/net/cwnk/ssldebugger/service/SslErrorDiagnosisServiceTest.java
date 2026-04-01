package net.cwnk.ssldebugger.service;

import net.cwnk.ssldebugger.model.ErrorDiagnosis;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateExpiredException;

import static org.junit.jupiter.api.Assertions.*;

class SslErrorDiagnosisServiceTest {

    private final SslErrorDiagnosisService service = new SslErrorDiagnosisService();

    @Test
    void pkixUntrustedCa() {
        var ex = new SSLHandshakeException("PKIX path building failed: unable to find valid certification path");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("certificate authority"));
        assertTrue(d.remediation().contains("truststore") || d.remediation().contains("Truststore"));
    }

    @Test
    void pkixUntrustedCaViaCauseChain() {
        var root = new CertPathBuilderException("no valid path");
        var ex = new SSLHandshakeException("chain validation failed");
        ex.initCause(root);
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("certificate authority"));
    }

    @Test
    void certificateExpiredViaCauseChain() {
        var root = new CertificateExpiredException("NotAfter: Mon Jan 01 00:00:00 UTC 2020");
        var ex = new SSLHandshakeException("certificate expired");
        ex.initCause(root);
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("expired"));
        assertTrue(d.remediation().contains("renew"));
    }

    @Test
    void hostnameMismatch() {
        var ex = new SSLHandshakeException("No name matching other.example.com found");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "other.example.com", 443);
        assertTrue(d.cause().contains("hostname") || d.cause().contains("other.example.com"));
        assertTrue(d.remediation().contains("certificate chain") || d.remediation().contains("hostname"));
    }

    @Test
    void protocolMismatch() {
        var ex = new SSLHandshakeException("No appropriate protocol (protocol is disabled or cipher suites are inappropriate)");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("protocol"));
        assertTrue(d.remediation().contains("TLS Settings") || d.remediation().contains("protocol"));
    }

    @Test
    void protocolMismatchViaRawLog() {
        var ex = new SSLHandshakeException("Remote host terminated the handshake");
        ErrorDiagnosis d = service.diagnose(ex, null, "received fatal alert: handshake_failure", "example.com", 443);
        assertTrue(d.cause().contains("protocol"));
    }

    @Test
    void cipherMismatch() {
        var ex = new SSLHandshakeException("no cipher suites in common");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("cipher"));
        assertTrue(d.remediation().contains("TLS Settings") || d.remediation().contains("cipher"));
    }

    @Test
    void connectionRefused() {
        var root = new ConnectException("Connection refused");
        var ex = new java.io.IOException("connect failed");
        ex.initCause(root);
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 9999);
        assertTrue(d.cause().contains("example.com:9999"));
        assertTrue(d.remediation().contains("hostname") || d.remediation().contains("port"));
    }

    @Test
    void connectionTimeout() {
        var root = new SocketTimeoutException("connect timed out");
        var ex = new java.io.IOException("timeout");
        ex.initCause(root);
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("example.com:443"));
    }

    @Test
    void certificateRevoked() {
        var ex = new SSLHandshakeException("Certificate has been revoked");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("revoked"));
        assertTrue(d.remediation().contains("replace") || d.remediation().contains("renew") || d.remediation().contains("administrator"));
    }

    @Test
    void mtlsClientCertRequired() {
        var ex = new SSLHandshakeException("Received fatal alert: bad_certificate");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("client certificate") || d.cause().contains("mTLS"));
    }

    @Test
    void proxyConnectFailure() {
        var ex = new java.io.IOException("Proxy CONNECT failed: HTTP/1.1 403 Forbidden");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertTrue(d.cause().contains("proxy") || d.cause().contains("CONNECT"));
        assertTrue(d.remediation().contains("proxy") || d.remediation().contains("Proxy"));
    }

    @Test
    void fallbackForUnknownException() {
        var ex = new RuntimeException("something totally unexpected");
        ErrorDiagnosis d = service.diagnose(ex, null, "", "example.com", 443);
        assertNotNull(d);
        assertFalse(d.cause().isBlank());
        assertFalse(d.remediation().isBlank());
    }

    @Test
    void nullExceptionReturnsFallbackWithoutNpe() {
        ErrorDiagnosis d = service.diagnose(null, null, null, "example.com", 443);
        assertNotNull(d);
        assertFalse(d.cause().isBlank());
    }
}
