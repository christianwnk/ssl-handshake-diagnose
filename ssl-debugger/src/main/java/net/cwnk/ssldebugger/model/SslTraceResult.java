package net.cwnk.ssldebugger.model;

import java.util.List;

public class SslTraceResult {
    private final boolean success;
    private final String error;
    private final List<HandshakeStep> steps;
    private final String rawLog;
    private final List<CertInfo> certificateChain;
    private final String negotiatedProtocol;
    private final String negotiatedCipherSuite;
    private final long durationMs;

    private SslTraceResult(Builder b) {
        this.success = b.success;
        this.error = b.error;
        this.steps = b.steps;
        this.rawLog = b.rawLog;
        this.certificateChain = b.certificateChain;
        this.negotiatedProtocol = b.negotiatedProtocol;
        this.negotiatedCipherSuite = b.negotiatedCipherSuite;
        this.durationMs = b.durationMs;
    }

    public boolean isSuccess() { return success; }
    public String getError() { return error; }
    public List<HandshakeStep> getSteps() { return steps; }
    public String getRawLog() { return rawLog; }
    public List<CertInfo> getCertificateChain() { return certificateChain; }
    public String getNegotiatedProtocol() { return negotiatedProtocol; }
    public String getNegotiatedCipherSuite() { return negotiatedCipherSuite; }
    public long getDurationMs() { return durationMs; }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private boolean success;
        private String error;
        private List<HandshakeStep> steps = List.of();
        private String rawLog = "";
        private List<CertInfo> certificateChain = List.of();
        private String negotiatedProtocol;
        private String negotiatedCipherSuite;
        private long durationMs;

        public Builder success(boolean success) { this.success = success; return this; }
        public Builder error(String error) { this.error = error; return this; }
        public Builder steps(List<HandshakeStep> steps) { this.steps = steps; return this; }
        public Builder rawLog(String rawLog) { this.rawLog = rawLog; return this; }
        public Builder certificateChain(List<CertInfo> chain) { this.certificateChain = chain; return this; }
        public Builder negotiatedProtocol(String protocol) { this.negotiatedProtocol = protocol; return this; }
        public Builder negotiatedCipherSuite(String suite) { this.negotiatedCipherSuite = suite; return this; }
        public Builder durationMs(long ms) { this.durationMs = ms; return this; }
        public SslTraceResult build() { return new SslTraceResult(this); }
    }
}
