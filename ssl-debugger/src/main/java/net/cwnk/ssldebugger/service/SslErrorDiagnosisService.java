package net.cwnk.ssldebugger.service;

import net.cwnk.ssldebugger.model.ErrorDiagnosis;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class SslErrorDiagnosisService {

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    public ErrorDiagnosis diagnose(Exception exception, X509Certificate[] chain,
                                   String rawLog, String hostname, int port) {
        if (exception == null) {
            return fallback("Unknown");
        }

        String allMessages = collectMessages(exception).toLowerCase();
        String log = rawLog != null ? rawLog.toLowerCase() : "";

        // Rule 10: Proxy CONNECT failure (check before generic connection errors)
        if (exception.getMessage() != null && exception.getMessage().startsWith("Proxy CONNECT failed")) {
            return new ErrorDiagnosis(
                "The HTTP CONNECT tunnel through the proxy server failed. " +
                    "The proxy returned a non-2xx response.",
                "Verify the proxy hostname, port, and credentials. Confirm the proxy allows " +
                    "CONNECT tunneling to " + hostname + ":" + port + ". " +
                    "Check with your network administrator if the proxy has an access control list."
            );
        }

        // Rule 6: Connection refused / timeout (check early — no SSL context at all)
        if (hasCauseOfType(exception, ConnectException.class)
                || hasCauseOfType(exception, SocketTimeoutException.class)
                || allMessages.contains("connection refused")
                || allMessages.contains("connect timed out")
                || allMessages.contains("connection timed out")) {
            return new ErrorDiagnosis(
                "The TCP connection to " + hostname + ":" + port + " could not be established. " +
                    "The server is either not reachable, not listening on that port, " +
                    "or a firewall is blocking the connection.",
                "Verify the hostname and port are correct. Check that the server is running " +
                    "and that no firewall or network ACL blocks outbound connections from " +
                    "this machine to " + hostname + ":" + port + "."
            );
        }

        // Rule 7: Certificate revoked
        if (allMessages.contains("revoked") || log.contains("certificate_revoked")) {
            return new ErrorDiagnosis(
                "The server's certificate has been revoked by its issuing certificate authority. " +
                    "This means the certificate is no longer considered valid even though it may not have expired.",
                "The server administrator must replace the revoked certificate with a newly issued one."
            );
        }

        // Rule 9: mTLS / client certificate required
        if (allMessages.contains("bad_certificate")
                || allMessages.contains("certificate_required")
                || allMessages.contains("empty client certificate chain")
                || log.contains("bad_certificate")
                || log.contains("certificate_required")) {
            return new ErrorDiagnosis(
                "The server requires a client certificate for mutual TLS authentication (mTLS). " +
                    "No client certificate was provided in this request.",
                "A client certificate (and its private key) in PKCS12 or JKS format is required. " +
                    "This tool does not currently support uploading a client keystore — contact the " +
                    "server administrator to confirm which client certificate authority is trusted."
            );
        }

        // Rule 8: Self-signed certificate (check cert chain first, then message)
        if (isSelfSigned(chain) || allMessages.contains("self-signed") || allMessages.contains("self signed")) {
            return new ErrorDiagnosis(
                "The server is presenting a self-signed certificate. Self-signed certificates are " +
                    "not trusted by default because they were not issued by a certificate authority.",
                "Upload the self-signed certificate itself as a single-entry truststore " +
                    "(JKS or PKCS12 format) using the 'Truststore' field. This tells the client " +
                    "to explicitly trust this specific certificate."
            );
        }

        // Rule 2: Certificate expired
        if (hasCauseOfType(exception, CertificateExpiredException.class)
                || allMessages.contains("notafter")
                || allMessages.contains("certificate expired")) {
            String expiredOn = expiryDate(chain);
            return new ErrorDiagnosis(
                "The server's certificate has expired." + expiredOn,
                "The server administrator must renew and deploy a new certificate. " +
                    "This cannot be worked around from the client side."
            );
        }

        // Rule 3: Hostname mismatch — use precise JSSE message strings to avoid false matches
        if (allMessages.contains("no name matching")
                || allMessages.contains("no subject alternative")
                || allMessages.contains("doesn't match")) {
            return new ErrorDiagnosis(
                "The hostname you are connecting to (" + hostname + ") does not match any name " +
                    "on the server's certificate. The certificate's Subject Alternative Names (SANs) " +
                    "or Common Name (CN) do not include this hostname.",
                "Check the certificate chain shown above to see which hostnames the certificate is " +
                    "valid for. Connect using one of those names, or ask the server administrator to " +
                    "reissue the certificate to include the correct hostname."
            );
        }

        // Rule 1: PKIX / untrusted CA (after self-signed check, so self-signed gets its own message)
        if (hasCauseOfType(exception, CertPathBuilderException.class)
                || allMessages.contains("pkix path")
                || allMessages.contains("unable to find valid certification path")) {
            return new ErrorDiagnosis(
                "The server's certificate was issued by a certificate authority (CA) that is not trusted. " +
                    "The JVM's trust store does not contain that CA's root certificate.",
                "If this is an internal or private CA, upload its root certificate as a JKS or PKCS12 " +
                    "truststore using the 'Truststore' field. If it's a public CA, the server may have " +
                    "an incomplete chain — ask the server administrator to include intermediate certificates."
            );
        }

        // Rule 5: Cipher suite mismatch (checked before protocol mismatch — more specific signal)
        if (allMessages.contains("no cipher suites in common")) {
            return new ErrorDiagnosis(
                "The client and server have no cipher suites in common. The server may require cipher " +
                    "suites that are disabled in this JVM's security policy.",
                "In the TLS Settings panel, enable additional cipher suites and retry. If the server " +
                    "requires weak ciphers (e.g. export-grade or RC4), a security policy update may be needed."
            );
        }

        // Rule 4: Protocol version mismatch
        if (allMessages.contains("no protocols in common")
                || allMessages.contains("no appropriate protocol")) {
            return new ErrorDiagnosis(
                "The client and server could not agree on a TLS protocol version. The server may only " +
                    "support older versions (e.g. TLS 1.0 or 1.1) that this client has disabled, or vice versa.",
                "In the TLS Settings panel, try enabling older protocol versions (TLSv1.1, TLSv1) and " +
                    "re-run. Note: enabling deprecated protocols is a security risk and should only be done " +
                    "for diagnosis."
            );
        }

        return fallback(exception.getClass().getSimpleName());
    }

    private boolean isSelfSigned(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) return false;
        return chain[0].getSubjectX500Principal().equals(chain[0].getIssuerX500Principal());
    }

    private String expiryDate(X509Certificate[] chain) {
        if (chain != null && chain.length > 0) {
            String date = DATE_FORMAT.format(chain[0].getNotAfter().toInstant());
            return " Its validity period ended on " + date + " (UTC).";
        }
        return "";
    }

    private String collectMessages(Throwable t) {
        StringBuilder sb = new StringBuilder();
        Throwable current = t;
        while (current != null) {
            if (current.getMessage() != null) {
                sb.append(current.getMessage()).append(' ');
            }
            current = current.getCause();
        }
        return sb.toString();
    }

    private boolean hasCauseOfType(Throwable t, Class<? extends Throwable> type) {
        Throwable current = t;
        while (current != null) {
            if (type.isInstance(current)) return true;
            current = current.getCause();
        }
        return false;
    }

    private ErrorDiagnosis fallback(String exceptionName) {
        return new ErrorDiagnosis(
            "An unexpected SSL/TLS error occurred: " + exceptionName + ".",
            "Review the raw JSSE log below for clues. If the error is reproducible, " +
                "share the log with your system administrator."
        );
    }
}
