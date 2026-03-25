package net.cwnk.ssldebugger.service;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Wraps an existing X509TrustManager to capture the server certificate chain
 * before delegating validation. This allows the chain to be inspected even
 * when validation fails.
 */
public class CapturingTrustManager implements X509TrustManager {

    private final X509TrustManager delegate;
    private X509Certificate[] capturedChain;
    private CertificateException capturedError;

    public CapturingTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.capturedChain = chain;
        try {
            delegate.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            this.capturedError = e;
            throw e;
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    public X509Certificate[] getCapturedChain() {
        return capturedChain;
    }

    public CertificateException getCapturedError() {
        return capturedError;
    }
}
