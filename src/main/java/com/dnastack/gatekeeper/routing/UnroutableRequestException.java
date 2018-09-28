package com.dnastack.gatekeeper.routing;

public class UnroutableRequestException extends Exception {
    private final int status;

    public UnroutableRequestException(int status, String message) {
        super(message);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }
}
