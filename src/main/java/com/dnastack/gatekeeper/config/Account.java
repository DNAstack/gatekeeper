package com.dnastack.gatekeeper.config;

import lombok.Data;

@Data
public class Account {
    private String accountId, issuer, email;
}
