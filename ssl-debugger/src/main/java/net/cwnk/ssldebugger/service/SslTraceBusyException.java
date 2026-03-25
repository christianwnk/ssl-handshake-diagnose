package net.cwnk.ssldebugger.service;

public class SslTraceBusyException extends RuntimeException {
    public SslTraceBusyException() {
        super("Another SSL trace is already in progress. Please try again shortly.");
    }
}
