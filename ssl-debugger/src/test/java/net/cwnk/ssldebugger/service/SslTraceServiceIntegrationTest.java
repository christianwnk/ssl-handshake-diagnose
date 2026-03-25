package net.cwnk.ssldebugger.service;

import net.cwnk.ssldebugger.model.SslTraceRequest;
import net.cwnk.ssldebugger.model.SslTraceResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SslTraceServiceIntegrationTest {

    private Path tempDir;
    private SSLServerSocket serverSocket;
    private Thread serverThread;
    private int serverPort;
    private byte[] trustStoreBytes;

    private final SslTraceService service = new SslTraceService();

    @BeforeAll
    void startServer() throws Exception {
        tempDir = Files.createTempDirectory("ssl-test");
        service.init();

        // Generate a self-signed keystore using keytool (avoids sun.* internal APIs)
        Path ksPath = tempDir.resolve("server.jks");
        runKeytool(
            "-genkeypair",
            "-alias", "server",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "1",
            "-dname", "CN=localhost,O=Test,C=DE",
            "-keystore", ksPath.toString(),
            "-storepass", "changeit",
            "-keypass", "changeit",
            "-storetype", "JKS"
        );

        // Load server keystore
        KeyStore serverKs = KeyStore.getInstance("JKS");
        try (InputStream is = Files.newInputStream(ksPath)) {
            serverKs.load(is, "changeit".toCharArray());
        }

        // Build client truststore containing only the server cert
        Certificate serverCert = serverKs.getCertificate("server");
        KeyStore clientTs = KeyStore.getInstance("JKS");
        clientTs.load(null, null);
        clientTs.setCertificateEntry("server", serverCert);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        clientTs.store(baos, "changeit".toCharArray());
        trustStoreBytes = baos.toByteArray();

        // Start SSL server
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKs, "changeit".toCharArray());

        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);

        serverSocket = (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0);
        serverPort = serverSocket.getLocalPort();

        CountDownLatch ready = new CountDownLatch(1);
        serverThread = Thread.ofVirtual().start(() -> {
            ready.countDown();
            while (!serverSocket.isClosed()) {
                try {
                    SSLSocket client = (SSLSocket) serverSocket.accept();
                    Thread.ofVirtual().start(() -> {
                        try {
                            client.startHandshake();
                            client.close();
                        } catch (IOException ignored) {}
                    });
                } catch (IOException ignored) {}
            }
        });
        ready.await(5, TimeUnit.SECONDS);
    }

    @AfterAll
    void stopServer() throws Exception {
        serverSocket.close();
        serverThread.interrupt();
        if (tempDir != null) {
            try (var stream = Files.walk(tempDir)) {
                stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void successfulHandshakeWithCustomTruststore() {
        SslTraceRequest request = new SslTraceRequest();
        request.setHostname("localhost");
        request.setPort(serverPort);
        request.setTruststoreBytes(trustStoreBytes);
        request.setTruststorePassword("changeit");
        request.setTruststoreType("JKS");

        SslTraceResult result = service.trace(request);

        assertTrue(result.isSuccess(), "Expected handshake to succeed, error: " + result.getError());
        assertFalse(result.getCertificateChain().isEmpty(), "Expected cert chain to be captured");
        assertNotNull(result.getNegotiatedProtocol());
        assertNotNull(result.getNegotiatedCipherSuite());
        assertTrue(result.getDurationMs() >= 0);
    }

    @Test
    void failsWithDefaultTruststoreForSelfSignedCert() {
        SslTraceRequest request = new SslTraceRequest();
        request.setHostname("localhost");
        request.setPort(serverPort);
        // No custom truststore — JVM default doesn't trust our self-signed cert

        SslTraceResult result = service.trace(request);

        assertFalse(result.isSuccess(), "Expected handshake to fail with untrusted cert");
        assertNotNull(result.getError());
        assertFalse(result.getCertificateChain().isEmpty(), "Cert chain should still be captured even on failure");
    }

    private void runKeytool(String... args) throws Exception {
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        String[] cmd = new String[args.length + 1];
        cmd[0] = keytool;
        System.arraycopy(args, 0, cmd, 1, args.length);

        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes());
        boolean finished = p.waitFor(30, TimeUnit.SECONDS);
        if (!finished || p.exitValue() != 0) {
            throw new IllegalStateException("keytool failed (exit " + p.exitValue() + "): " + output);
        }
    }
}
