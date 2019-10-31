package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.token.TokenParser;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
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
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Optional;

import static com.dnastack.gatekeeper.util.XForwardUtil.getExternalPath;
import static java.lang.String.format;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.*;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.ServerResponse.*;

@Slf4j
@Configuration
public class LoginRouter {

    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";

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

    @Bean
    RouterFunction<ServerResponse> apiLogin() {
        return RouterFunctions.route(GET("/api/identity/login"), this::handleLoginRequest);
    }

    private Mono<ServerResponse> handleLoginRequest(ServerRequest serverRequest) {
        final Optional<String> foundToken = Optional.ofNullable(serverRequest.cookies()
                                                                             .getFirst(ACCESS_TOKEN_COOKIE_NAME))
                                                    .map(HttpCookie::getValue);
        final String state = serverRequest.queryParam("state").orElse("/metadata");
        if (foundToken.filter(tokenParser::isValid).isPresent()) {
            final String token = foundToken.get();
            final String targetUri = format("%s?access_token=%s", getExternalPath(serverRequest, state), token);
            return temporaryRedirect(URI.create(targetUri)).build();
        } else {
            final String fullAuthUrl = format("%s?response_type=code&scope=%s&client_id=%s&redirect_uri=%s&state=%s",
                                              metadataServerAuthUrl,
                                              "openid ga4gh_passport_v1",
                                              clientId,
                                              redirectUri(serverRequest),
                                              state);
            return temporaryRedirect(URI.create(fullAuthUrl)).build();
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
                           .map(this::extractToken)
                           .flatMap(oToken -> oToken.map(token -> successfulUserTokenResponse(request, token))
                                                    .orElseGet(() -> failedUserTokenResponse(response)));
        } else {
            logTokenFailureInDetail(response);
            return badRequest().contentType(TEXT_PLAIN).syncBody("Failed to acquire token.");
        }
    }

    private Mono<ServerResponse> failedUserTokenResponse(ClientResponse response) {
        logTokenFailureInDetail(response);
        return status(INTERNAL_SERVER_ERROR).syncBody("Failed to parse token.");
    }

    private Mono<ServerResponse> successfulUserTokenResponse(ServerRequest request, String token) {
        final String redirectPath = request.queryParam("state").orElse("/metadata");
        final URI redirectUri = URI.create(getExternalPath(request, redirectPath) + "?access_token=" + token);
        return temporaryRedirect(redirectUri).cookie(ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, token)
                                                                   .domain(redirectUri.getHost())
                                                                   .path("/")
                                                                   .build())
                                             .build();
    }

    private Optional<String> extractToken(String body) {
        try {
            return Optional.of(((JSONObject) new JSONParser().parse(body)).get("id_token").toString());
        } catch (ParseException | NullPointerException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to parse token from payload. Payload: " + body, e);
            }
            return Optional.empty();
        }
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
