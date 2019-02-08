package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * Sometimes we want to use the email field in the decrypted auth token to authenticate the claims of the incoming user,
 * other times we want to authenticate using the "scope" field in the decrypted auth token.
 *
 * So we have a factory class which can give you the right token authorizer implementation depending on whether you're
 * auth'ing with email or scope.
 */
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
