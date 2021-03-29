package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.token.TokenParser;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Optional;

import static com.dnastack.gatekeeper.util.XForwardUtil.getExternalPath;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.*;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.ServerResponse.*;

@Slf4j
@Configuration
public class LoginRouter {

    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    private static final String ID_TOKEN_COOKIE_NAME = "id_token";

    @Value("${gatekeeper.auth-server.token-url}")
    private String tokenUrl;

    @Value("${gatekeeper.auth-server.client-id}")
    private String clientId;

    @Value("${gatekeeper.auth-server.client-secret}")
    private String clientSecret;

    @Value("${gatekeeper.auth-server.authorize-url}")
    private String metadataServerAuthUrl;

    @Autowired
    private TokenParser tokenParser;

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    RouterFunction<ServerResponse> apiLogin() {
        return RouterFunctions.route(GET("/api/identity/login"), this::handleLoginRequest);
    }

    @Bean
    RouterFunction<ServerResponse> apiLogout(){
        return RouterFunctions.route(GET("/api/identity/logout"), this::handleLogoutRequest);
    }

    private Mono<ServerResponse> handleLogoutRequest(ServerRequest serverRequest){
        final String state = serverRequest.queryParam("state").orElse("/");
        final URI targetUri = URI.create(getExternalPath(serverRequest,state));
        final BodyBuilder builder = temporaryRedirect(targetUri);

        builder.cookie(ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME,"expired").maxAge(Duration.ZERO).domain(targetUri.getHost()).path("/").build());
        builder.cookie(ResponseCookie.from(ID_TOKEN_COOKIE_NAME,"expired").maxAge(Duration.ZERO).domain(targetUri.getHost()).path("/").build());
        return builder.build();
    }

    private Mono<ServerResponse> handleLoginRequest(ServerRequest serverRequest) {
        final Optional<String> foundToken = Optional.ofNullable(serverRequest.cookies()
                                                                             .getFirst(ACCESS_TOKEN_COOKIE_NAME))
                                                    .map(HttpCookie::getValue);
        final String state = serverRequest.queryParam("state").orElse("/metadata");
        if (foundToken.filter(tokenParser::isValid).isPresent()) {
            final String targetUri = getExternalPath(serverRequest, state);
            return temporaryRedirect(URI.create(targetUri)).build();
        } else {
            final String scopes = serverRequest.queryParam("scope").orElse("openid+ga4gh_passport_v1");
            final UriComponentsBuilder authUriBuilder = UriComponentsBuilder.fromUriString(metadataServerAuthUrl)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri(serverRequest))
                .queryParam("client_id", clientId)
                .queryParam("state", state)
                .queryParam("scope", scopes);
            serverRequest.queryParams()
                .keySet()
                .stream()
                .filter(param -> !"state".equals(param) && !"scope".equals(param))
                .forEach(param -> authUriBuilder.queryParam(param, serverRequest.queryParams().get(param).toArray()));

            return temporaryRedirect(authUriBuilder.build().toUri()).build();
        }
    }

    private String redirectUri(ServerRequest request) {
        return getExternalPath(request, "/api/identity/token");
    }

    @Bean
    RouterFunction<ServerResponse> apiToken() {
        return RouterFunctions.route(GET("/api/identity/token"), this::handleTokenRequest);
    }

    private Mono<ServerResponse> handleTokenRequest(ServerRequest request) {
        final Optional<String> foundCode = request.queryParam("code");
        return foundCode.map(code ->
                                     idpTokenRequest(request, code).flatMap(response -> downstreamTokenResponse(request,
                                                                                                                response)))
                        .orElseGet(() -> badRequest().contentType(TEXT_PLAIN)
                                                     .syncBody("Token request requires 'code' parameter."));
    }

    private Mono<ServerResponse> downstreamTokenResponse(ServerRequest request, ClientResponse response) {
        if (response.statusCode().is2xxSuccessful() && contentTypeIsApplicationJson(response)) {
            return response.bodyToMono(String.class)
                           .flatMap(body -> {
                               final Optional<TokenResponse> foundTokens = extractToken(body);
                               return foundTokens.map(tokens -> successfulUserTokenResponse(request, tokens))
                                   .orElseGet(() -> failedUserTokenResponse(response));
                           });
        } else {
            logTokenFailureInDetail(response);
            return badRequest().contentType(TEXT_PLAIN).syncBody("Failed to acquire token.");
        }
    }

    private Mono<ServerResponse> failedUserTokenResponse(ClientResponse response) {
        logTokenFailureInDetail(response);
        return status(INTERNAL_SERVER_ERROR).syncBody("Failed to parse token.");
    }

    private Mono<ServerResponse> successfulUserTokenResponse(ServerRequest request, TokenResponse tokens) {
        final String redirectPath = request.queryParam("state").orElse("/metadata");
        final URI redirectUri = URI.create(getExternalPath(request, redirectPath));
        final BodyBuilder builder = temporaryRedirect(redirectUri);
        if (tokens.getAccessToken() != null) {
            builder.cookie(ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, tokens.getAccessToken())
                .domain(redirectUri.getHost())
                .path("/")
                .build());
        }
        if (tokens.getIdToken() != null) {
            builder.cookie(ResponseCookie.from(ID_TOKEN_COOKIE_NAME, tokens.getIdToken())
                .domain(redirectUri.getHost())
                .path("/")
                .build());
        }

        return builder.build();
    }

    @Data
    static class TokenResponse {
        @JsonProperty("id_token")
        private String idToken;
        @JsonProperty("access_token")
        private String accessToken;
    }

    private Optional<TokenResponse> extractToken(String body) {
        try {
            if (body != null) {
                return Optional.of(objectMapper.readValue(body, TokenResponse.class));
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to parse token from payload. Payload: " + body, e);
            }
        }
        return Optional.empty();
    }

    private void logTokenFailureInDetail(ClientResponse response) {
        if (log.isDebugEnabled()) {
            response.bodyToMono(String.class).subscribe(body -> {
                log.debug("Failed to negotiate token. Status=[{}], ContentType=[{}], Body=[{}]",
                          response.statusCode().toString(),
                          response.headers().contentType().map(Object::toString).orElse("none"),
                          body);
            });
        }
    }

    private boolean contentTypeIsApplicationJson(ClientResponse response) {
        return response.headers()
                       .contentType()
                       .filter(mediaType -> mediaType.isCompatibleWith(
                               APPLICATION_JSON))
                       .isPresent();
    }

    private Mono<ClientResponse> idpTokenRequest(ServerRequest request, String code) {
        final String redirectUri = getExternalPath(request, "/api/identity/token");
        final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("code", code);
        formData.add("redirect_uri", redirectUri);
        request.queryParam("state")
               .ifPresent(state -> formData.add("state", state));

        final String authHeaderValue = basicAuthHeaderValue(clientId, clientSecret);

        if (log.isDebugEnabled()) {
            log.debug("Sending token request with form data: {}", formData);
        }

        return WebClient.create(tokenUrl)
                        .post()
                        .header("Authorization", authHeaderValue)
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .syncBody(formData)
                        .exchange();
    }

    private String basicAuthHeaderValue(String clientId, String clientSecret) {
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(Charset.forName("UTF-8")));
    }
}
