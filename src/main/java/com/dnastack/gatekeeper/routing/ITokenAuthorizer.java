package com.dnastack.gatekeeper.routing;

import io.jsonwebtoken.JwtParser;

import javax.servlet.http.HttpServletResponse;

public interface ITokenAuthorizer {

    String authorizeToken(String authToken, JwtParser jwtParser, HttpServletResponse response) throws UnroutableRequestException;

}
