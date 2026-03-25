package net.cwnk.ssldebugger.controller;

import net.cwnk.ssldebugger.model.SslTraceRequest;
import net.cwnk.ssldebugger.model.SslTraceResult;
import net.cwnk.ssldebugger.service.SslTraceBusyException;
import net.cwnk.ssldebugger.service.SslTraceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api")
public class SslTraceController {

    record CapabilitiesResponse(List<String> protocols, List<String> cipherSuites) {}

    private final SslTraceService sslTraceService;

    public SslTraceController(SslTraceService sslTraceService) {
        this.sslTraceService = sslTraceService;
    }

    @GetMapping("/capabilities")
    public ResponseEntity<CapabilitiesResponse> capabilities() throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            return ResponseEntity.ok(new CapabilitiesResponse(
                    Arrays.asList(socket.getSupportedProtocols()),
                    Arrays.asList(socket.getSupportedCipherSuites())
            ));
        }
    }

    @PostMapping(value = "/trace", consumes = "multipart/form-data")
    public ResponseEntity<SslTraceResult> trace(
            @RequestParam String hostname,
            @RequestParam int port,
            @RequestParam(required = false) MultipartFile truststore,
            @RequestParam(required = false) String truststorePassword,
            @RequestParam(required = false, defaultValue = "JKS") String truststoreType,
            @RequestParam(required = false) List<String> protocols,
            @RequestParam(required = false) List<String> cipherSuites
    ) throws IOException {

        if (hostname == null || hostname.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        if (port < 1 || port > 65535) {
            return ResponseEntity.badRequest().build();
        }

        SslTraceRequest request = new SslTraceRequest();
        request.setHostname(hostname.trim());
        request.setPort(port);
        request.setTruststorePassword(truststorePassword);
        request.setTruststoreType(truststoreType);

        if (truststore != null && !truststore.isEmpty()) {
            request.setTruststoreBytes(truststore.getBytes());
        }
        if (protocols != null && !protocols.isEmpty()) {
            request.setEnabledProtocols(protocols);
        }
        if (cipherSuites != null && !cipherSuites.isEmpty()) {
            request.setEnabledCipherSuites(cipherSuites);
        }

        SslTraceResult result = sslTraceService.trace(request);
        return ResponseEntity.ok(result);
    }

    @ExceptionHandler(SslTraceBusyException.class)
    public ResponseEntity<String> handleBusy(SslTraceBusyException e) {
        return ResponseEntity.status(503).body(e.getMessage());
    }
}
