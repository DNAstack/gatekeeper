package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class TokenAuthorizerFactory {

    public ITokenAuthorizer getTokenAuthorizer(String tokenAuthorizationMethod, String controlledPrefix, String registeredPrefix, String publicPrefix, List<String> requiredScopeList, InboundEmailWhitelistConfiguration emailWhitelist, ObjectMapper objectMapper) {
        if (tokenAuthorizationMethod.equals("email")) {
            return new TokenAuthorizerEmailImpl(controlledPrefix, registeredPrefix, publicPrefix, emailWhitelist, objectMapper);
        } else if (tokenAuthorizationMethod.equals("scope")) {
            return new TokenAuthorizerScopeImpl(controlledPrefix, registeredPrefix, publicPrefix, requiredScopeList, objectMapper);
        } else {
            return null;
        }
    }
}
