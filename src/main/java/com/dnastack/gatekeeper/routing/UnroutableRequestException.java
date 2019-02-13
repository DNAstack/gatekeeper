package com.dnastack.gatekeeper.routing;

import lombok.Getter;

public class UnroutableRequestException extends Exception {
    @Getter
    private final int status;

    public UnroutableRequestException(int status, String message) {
        super(message);
        this.status = status;
    }

}
