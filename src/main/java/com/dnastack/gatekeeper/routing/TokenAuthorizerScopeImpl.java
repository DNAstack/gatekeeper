package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class TokenAuthorizerScopeImpl {

    public static final TypeReference<List<GatekeeperRequestRouter.Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<List<GatekeeperRequestRouter.Account>>() {

    };

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private String controlledPrefix;
    private String registeredPrefix;
    private String publicPrefix;
    private List<String> requiredScopeList;
    private ObjectMapper objectMapper;

    TokenAuthorizerScopeImpl(String controlledPrefix, String registeredPrefix, String publicPrefix, List<String> requiredScopeList, ObjectMapper objectMapper) {
        this.controlledPrefix = controlledPrefix;
        this.registeredPrefix = registeredPrefix;
        this.publicPrefix = publicPrefix;
        this.requiredScopeList = requiredScopeList;
        this.objectMapper = objectMapper;
    }
}
