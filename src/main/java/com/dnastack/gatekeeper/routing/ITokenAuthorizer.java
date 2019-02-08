package com.dnastack.gatekeeper.routing;

import io.jsonwebtoken.JwtParser;

public interface ITokenAuthorizer {

    String authorizeToken(String authToken, JwtParser jwtParser) throws UnroutableRequestException;

}
