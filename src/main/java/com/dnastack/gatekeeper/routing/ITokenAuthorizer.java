package com.dnastack.gatekeeper.routing;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import javax.servlet.http.HttpServletResponse;

public interface ITokenAuthorizer {

    String authorizeToken(Jws<Claims> jws, HttpServletResponse response) throws UnroutableRequestException;

}
