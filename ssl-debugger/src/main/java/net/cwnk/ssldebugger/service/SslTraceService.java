package net.cwnk.ssldebugger.service;

import jakarta.annotation.PostConstruct;
import net.cwnk.ssldebugger.model.CertInfo;
import net.cwnk.ssldebugger.model.HandshakeStep;
import net.cwnk.ssldebugger.model.SslTraceRequest;
import net.cwnk.ssldebugger.model.SslTraceResult;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class SslTraceService {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int SEMAPHORE_TIMEOUT_S = 30;

    private final Semaphore semaphore = new Semaphore(1);
    private final SslDebugOutputParser parser = new SslDebugOutputParser();

    @PostConstruct
    public void init() {
        // Enable JSSE debug output globally. Output goes to System.err, which we
        // redirect per-request to capture handshake details.
        System.setProperty("javax.net.debug", "ssl:handshake:verbose");
    }

    public SslTraceResult trace(SslTraceRequest request) {
        if (!tryAcquire()) {
            throw new SslTraceBusyException();
        }

        long startMs = System.currentTimeMillis();
        PrintStream originalErr = System.err;
        ByteArrayOutputStream captureBuffer = new ByteArrayOutputStream();

        try {
            System.setErr(new PrintStream(captureBuffer, true, StandardCharsets.UTF_8));
            return doTrace(request, startMs, captureBuffer, originalErr);
        } finally {
            System.setErr(originalErr);
            semaphore.release();
        }
    }

    private SslTraceResult doTrace(SslTraceRequest request, long startMs,
                                   ByteArrayOutputStream captureBuffer, PrintStream originalErr) {
        CapturingTrustManager capturingTm;
        SSLContext sslContext;

        try {
            capturingTm = buildCapturingTrustManager(request);
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{capturingTm}, null);
        } catch (Exception e) {
            return SslTraceResult.builder()
                    .success(false)
                    .error("Failed to initialize SSL context: " + e.getMessage())
                    .durationMs(elapsed(startMs))
                    .build();
        }

        AtomicReference<String> protocol = new AtomicReference<>();
        AtomicReference<String> cipherSuite = new AtomicReference<>();
        String connectError = null;

        try {
            Socket tunnel = connectSocket(request);
            try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory()
                    .createSocket(tunnel, request.getHostname(), request.getPort(), true)) {
                if (request.getEnabledProtocols() != null && !request.getEnabledProtocols().isEmpty()) {
                    socket.setEnabledProtocols(request.getEnabledProtocols().toArray(new String[0]));
                }
                if (request.getEnabledCipherSuites() != null && !request.getEnabledCipherSuites().isEmpty()) {
                    socket.setEnabledCipherSuites(request.getEnabledCipherSuites().toArray(new String[0]));
                }
                socket.addHandshakeCompletedListener(event -> {
                    protocol.set(event.getSession().getProtocol());
                    cipherSuite.set(event.getCipherSuite());
                });
                socket.startHandshake();
            }
        } catch (Exception e) {
            connectError = buildErrorMessage(e, capturingTm);
        }

        // Flush and restore stderr before reading buffer
        System.err.flush();
        String rawLog = captureBuffer.toString(StandardCharsets.UTF_8);

        List<HandshakeStep> steps = parser.parse(rawLog);
        List<CertInfo> certChain = buildCertChain(capturingTm.getCapturedChain());

        boolean success = connectError == null;
        return SslTraceResult.builder()
                .success(success)
                .error(connectError)
                .steps(steps)
                .rawLog(rawLog)
                .certificateChain(certChain)
                .negotiatedProtocol(protocol.get())
                .negotiatedCipherSuite(cipherSuite.get())
                .durationMs(elapsed(startMs))
                .build();
    }

    private CapturingTrustManager buildCapturingTrustManager(SslTraceRequest request) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        if (request.getTruststoreBytes() != null && request.getTruststoreBytes().length > 0) {
            KeyStore ks = KeyStore.getInstance(request.getTruststoreType());
            char[] password = request.getTruststorePassword() != null
                    ? request.getTruststorePassword().toCharArray()
                    : new char[0];
            ks.load(new ByteArrayInputStream(request.getTruststoreBytes()), password);
            tmf.init(ks);
        } else {
            tmf.init((KeyStore) null); // use JVM default trust store
        }

        X509TrustManager delegate = Arrays.stream(tmf.getTrustManagers())
                .filter(tm -> tm instanceof X509TrustManager)
                .map(tm -> (X509TrustManager) tm)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No X509TrustManager found"));

        return new CapturingTrustManager(delegate);
    }

    private List<CertInfo> buildCertChain(X509Certificate[] chain) {
        if (chain == null) return List.of();
        List<CertInfo> result = new ArrayList<>();
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            result.add(new CertInfo(
                    i,
                    cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(),
                    cert.getNotBefore().toString(),
                    cert.getNotAfter().toString(),
                    extractSans(cert),
                    sha256Fingerprint(cert)
            ));
        }
        return result;
    }

    private List<String> extractSans(X509Certificate cert) {
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames == null) return List.of();
            List<String> sans = new ArrayList<>();
            for (List<?> entry : altNames) {
                if (entry.size() >= 2) {
                    int type = (Integer) entry.get(0);
                    String prefix = switch (type) {
                        case 2 -> "DNS";
                        case 7 -> "IP";
                        case 1 -> "Email";
                        default -> "type" + type;
                    };
                    sans.add(prefix + ":" + entry.get(1));
                }
            }
            return sans;
        } catch (Exception e) {
            return List.of();
        }
    }

    private String sha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02X:", b));
            }
            if (!hex.isEmpty()) hex.setLength(hex.length() - 1);
            return hex.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    private String buildErrorMessage(Exception e, CapturingTrustManager tm) {
        StringBuilder msg = new StringBuilder(e.getClass().getSimpleName());
        msg.append(": ").append(e.getMessage());
        if (tm.getCapturedError() != null && tm.getCapturedChain() != null) {
            msg.append(" (certificate chain captured — see chain details above)");
        }
        return msg.toString();
    }

    private boolean tryAcquire() {
        try {
            return semaphore.tryAcquire(SEMAPHORE_TIMEOUT_S, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private Socket connectSocket(SslTraceRequest request) throws IOException {
        if (request.getProxyHost() == null || request.getProxyHost().isBlank()) {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(request.getHostname(), request.getPort()), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(CONNECT_TIMEOUT_MS);
            return s;
        }
        // Open plain TCP connection to proxy
        Socket proxy = new Socket();
        proxy.connect(new InetSocketAddress(request.getProxyHost(), request.getProxyPort()), CONNECT_TIMEOUT_MS);
        proxy.setSoTimeout(CONNECT_TIMEOUT_MS);

        // Send HTTP CONNECT request
        StringBuilder connectReq = new StringBuilder()
                .append("CONNECT ").append(request.getHostname()).append(':').append(request.getPort()).append(" HTTP/1.1\r\n")
                .append("Host: ").append(request.getHostname()).append(':').append(request.getPort()).append("\r\n");
        if (request.getProxyUsername() != null && !request.getProxyUsername().isBlank()) {
            String creds = request.getProxyUsername() + ":"
                    + (request.getProxyPassword() != null ? request.getProxyPassword() : "");
            String encoded = Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
            connectReq.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
        }
        connectReq.append("\r\n");
        proxy.getOutputStream().write(connectReq.toString().getBytes(StandardCharsets.UTF_8));
        proxy.getOutputStream().flush();

        // Read proxy response (until \r\n\r\n)
        String response = readProxyResponse(proxy);
        if (!response.startsWith("HTTP/") || !response.contains(" 2")) {
            proxy.close();
            throw new IOException("Proxy CONNECT failed: "
                    + response.lines().findFirst().orElse("(empty response)"));
        }
        return proxy;
    }

    private String readProxyResponse(Socket proxy) throws IOException {
        InputStream in = proxy.getInputStream();
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            sb.append((char) b);
            if (sb.toString().endsWith("\r\n\r\n")) break;
        }
        return sb.toString();
    }

    private long elapsed(long startMs) {
        return System.currentTimeMillis() - startMs;
    }
}
