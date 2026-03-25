package net.cwnk.ssldebugger.model;

public class SslTraceRequest {
    private String hostname;
    private int port;
    private byte[] truststoreBytes;
    private String truststorePassword;
    private String truststoreType = "JKS";

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
}
