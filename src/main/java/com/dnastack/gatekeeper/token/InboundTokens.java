package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.acl.UnroutableRequestException;
import lombok.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Optional;

@Value
public class InboundTokens {
    private String accessToken;
    private String idToken;
    public static Optional<InboundTokens> extractAuthToken(ServerHttpRequest request) throws UnroutableRequestException {
        final String authHeader = request.getHeaders().getFirst("authorization");

        if (authHeader != null) {
            final String[] parts = Optional.of(authHeader)
                .map(value -> value.split(" "))
                .filter(values -> values.length == 2)
                .orElseThrow(() -> new UnroutableRequestException(400,
                    "Invalid authorization header"));

            final String authScheme = parts[0];
            if (!authScheme.equalsIgnoreCase("bearer")) {
                return Optional.empty();
            }

            return Optional.of(new InboundTokens(parts[1], null));
        } else {
            final String paramAccessToken = request.getQueryParams().getFirst("access_token");
            final String paramIdToken = request.getQueryParams().getFirst("id_token");
            if (paramAccessToken != null || paramIdToken != null) {
                return Optional.of(new InboundTokens(paramAccessToken, paramIdToken));
            } else {
                final String accessTokenCookie = Optional.ofNullable(request.getCookies()
                    .getFirst("access_token")).map(HttpCookie::getValue).orElse(null);
                final String idTokenCookie = Optional.ofNullable(request.getCookies()
                    .getFirst("id_token")).map(HttpCookie::getValue).orElse(null);
                return Optional.of(new InboundTokens(accessTokenCookie, idTokenCookie))
                    .filter(tokens -> tokens.getAccessToken() != null || tokens.getIdToken() != null);
            }
        }
    }
}
