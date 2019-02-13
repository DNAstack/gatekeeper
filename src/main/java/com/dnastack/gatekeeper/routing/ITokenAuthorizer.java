package com.dnastack.gatekeeper.routing;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.http.server.reactive.ServerHttpResponse;

public interface ITokenAuthorizer {

    String authorizeToken(Jws<Claims> jws, ServerHttpResponse response) throws UnroutableRequestException;

}
