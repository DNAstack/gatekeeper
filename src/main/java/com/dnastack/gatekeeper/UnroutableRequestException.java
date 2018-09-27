package com.dnastack.gatekeeper;

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
