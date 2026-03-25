# SSL/TLS Handshake Diagnose

A browser-based diagnostic tool for debugging SSL/TLS connection failures in Java applications.

When a Java application fails with a vague `javax.net.ssl.SSLHandshakeException: handshake_failure` and the stack trace gives no actionable detail, this tool lets you reproduce and inspect the exact handshake sequence against the same target server — showing every step, the full certificate chain, and the raw JSSE debug log.

## Features

- **Step-by-step handshake trace** — each TLS message (ClientHello, ServerHello, Certificate, Finished, …) shown as a labeled step, for both TLS 1.2 and TLS 1.3
- **Certificate chain inspection** — subject, issuer, validity dates, SANs, and SHA-256 fingerprint for every certificate in the chain, even when validation fails
- **Custom truststore support** — upload a `.jks` or `.p12` truststore to test against private CAs or self-signed certificates
- **Raw JSSE debug log** — full `javax.net.debug=ssl:handshake:verbose` output available via toggle
- **Browser UI** — plain HTML/JS, no frontend framework required; served directly from the Spring Boot app

## Quick Start

**Run locally:**

```bash
./gradlew :ssl-debugger:bootRun
```

Open [http://localhost:8080](http://localhost:8080), enter a hostname and port, and click **Trace**.

**Build and run as container:**

```bash
./gradlew :ssl-debugger:build
docker build -t ssl-debugger ssl-debugger/
docker run -p 8080:8080 ssl-debugger
```

## Usage

| Field | Description |
|---|---|
| Hostname | The target server hostname (e.g. `myserver.internal`) |
| Port | TLS port, typically `443` |
| Truststore | Optional `.jks` or `.p12` file — use when the server presents a private CA or self-signed certificate |
| Truststore password | Password for the uploaded truststore file |
| Type | `JKS` (default) or `PKCS12` |

### Typical diagnostics

| Symptom | What to look for |
|---|---|
| `handshake_failure` with no detail | Check the Certificate step — is the chain captured? Is the issuer a private CA? Upload the CA truststore. |
| Certificate not trusted | Certificate card shows the chain; the issuer in `[0]` is not in the JVM trust store. |
| Protocol/cipher mismatch | ServerHello step shows the negotiated cipher; compare with what the client supports. |
| Connection refused / timeout | Error banner shows the exact exception before any handshake steps. |

## Architecture

The `ssl-debugger` module is a self-contained Spring Boot application within this Gradle multi-module project.

```
ssl-debugger/
├── Dockerfile
├── build.gradle
└── src/
    ├── main/
    │   ├── java/net/cwnk/ssldebugger/
    │   │   ├── SslDebuggerApplication.java
    │   │   ├── controller/SslTraceController.java     # POST /api/trace
    │   │   ├── model/                                  # Request/result types
    │   │   └── service/
    │   │       ├── SslTraceService.java                # Core tracing logic
    │   │       ├── CapturingTrustManager.java          # Captures cert chain on validation
    │   │       └── SslDebugOutputParser.java           # Parses JSSE debug output into steps
    │   └── resources/static/index.html                 # Browser UI
    └── test/
        └── java/net/cwnk/ssldebugger/service/
            ├── SslDebugOutputParserTest.java
            └── SslTraceServiceIntegrationTest.java     # Spins up a local TLS server
```

**How tracing works:**

1. `javax.net.debug=ssl:handshake:verbose` is activated at startup, directing JSSE output to `System.err`
2. Per request, `System.err` is redirected to a buffer (requests are serialized via a `Semaphore`)
3. A custom `X509TrustManager` wraps the selected truststore and captures the certificate chain before delegating validation — so the chain is available even when the handshake fails
4. After the handshake attempt, the captured output is parsed into structured `HandshakeStep` entries

## Requirements

- Java 25
- Gradle 9.4+ (wrapper included)
- Docker (optional, for container builds)
