package net.cwnk.ssldebugger.model;

import java.util.List;

public class SslTraceRequest {
    private String hostname;
    private int port;
    private byte[] truststoreBytes;
    private String truststorePassword;
    private String truststoreType = "JKS";
    private List<String> enabledProtocols;    // null = use JVM defaults
    private List<String> enabledCipherSuites; // null = use JVM defaults

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public byte[] getTruststoreBytes() { return truststoreBytes; }
    public void setTruststoreBytes(byte[] truststoreBytes) { this.truststoreBytes = truststoreBytes; }

    public String getTruststorePassword() { return truststorePassword; }
    public void setTruststorePassword(String truststorePassword) { this.truststorePassword = truststorePassword; }

    public String getTruststoreType() { return truststoreType; }
    public void setTruststoreType(String truststoreType) { this.truststoreType = truststoreType != null ? truststoreType : "JKS"; }

    public List<String> getEnabledProtocols() { return enabledProtocols; }
    public void setEnabledProtocols(List<String> enabledProtocols) { this.enabledProtocols = enabledProtocols; }

    public List<String> getEnabledCipherSuites() { return enabledCipherSuites; }
    public void setEnabledCipherSuites(List<String> enabledCipherSuites) { this.enabledCipherSuites = enabledCipherSuites; }
}
