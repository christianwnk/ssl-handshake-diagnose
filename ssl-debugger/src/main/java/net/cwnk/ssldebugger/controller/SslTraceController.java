package net.cwnk.ssldebugger.controller;

import net.cwnk.ssldebugger.model.SslTraceRequest;
import net.cwnk.ssldebugger.model.SslTraceResult;
import net.cwnk.ssldebugger.service.SslTraceBusyException;
import net.cwnk.ssldebugger.service.SslTraceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api")
public class SslTraceController {

    private final SslTraceService sslTraceService;

    public SslTraceController(SslTraceService sslTraceService) {
        this.sslTraceService = sslTraceService;
    }

    @PostMapping(value = "/trace", consumes = "multipart/form-data")
    public ResponseEntity<SslTraceResult> trace(
            @RequestParam String hostname,
            @RequestParam int port,
            @RequestParam(required = false) MultipartFile truststore,
            @RequestParam(required = false) String truststorePassword,
            @RequestParam(required = false, defaultValue = "JKS") String truststoreType
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

        SslTraceResult result = sslTraceService.trace(request);
        return ResponseEntity.ok(result);
    }

    @ExceptionHandler(SslTraceBusyException.class)
    public ResponseEntity<String> handleBusy(SslTraceBusyException e) {
        return ResponseEntity.status(503).body(e.getMessage());
    }
}
