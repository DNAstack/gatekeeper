package com.dnastack.gatekeeper.routing;

import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
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

import static com.dnastack.gatekeeper.header.XForwardUtil.getExternalPath;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.*;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.ServerResponse.*;

@Slf4j
@Configuration
public class Router {

    @Value("classpath:/static/index.html")
    private Resource index;

    @Value("${gatekeeper.metadataServer.auth-server.token-url}")
    private String tokenUrl;

    @Value("${gatekeeper.metadataServer.auth-server.client-id}")
    private String clientId;

    @Value("${gatekeeper.metadataServer.auth-server.client-secret}")
    private String clientSecret;

    @Bean
    RouterFunction<ServerResponse> index() {
        return RouterFunctions.route(GET("/"),
                                     request -> ok()
                                             .contentType(TEXT_HTML)
                                             .syncBody(index));
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
        return temporaryRedirect(redirectUri).build();
    }

    private Optional<String> extractToken(String body) {
        try {
            return Optional.of(((JSONObject) new JSONParser().parse(body)).get("access_token").toString());
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
