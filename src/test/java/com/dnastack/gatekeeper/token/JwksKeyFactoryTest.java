package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.config.InboundConfiguration;
import com.dnastack.gatekeeper.token.ConfiguredSigningKeyResolver.KeyResolver;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class JwksKeyFactoryTest {
    static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    static final String TEST_JWKS =
        "{\n" +
        "\"keys\": [\n" +
        "{\n" +
        "\"use\": \"sig\",\n" +
        "\"kty\": \"RSA\",\n" +
        "\"alg\": \"RS256\",\n" +
        "\"kid\": \"test-key-1\",\n" +
        "\"e\": \"AQAB\",\n" +
        "\"n\": \"ALa-VYpNfvWYoha2vLtrJUwBJ_o_XTdlO4O5VPZK5YqaTBm-AO4Ump-yZMeHNjNJXFCbUABzNC0NNZybUKrm7T35iAlLYBlxNxdZW9kVDCvg1PjriKbOrMZXrRkQoKpXNxXDV7FgQcfJ0bctJ8wsErOfdfuavv_pm75QD3yA3lDshLLgc162qjG70mWQBTIg8FjOK124ZJV9ekV4NSqUGY5RPcDPflk88YNohdQysg5ZpXTQ8OE4wf_3AVs6MRvjuPGQqO8t-jJ7fqrPNYl2x46faL-gknnKho_8wPMbBz3wu_02I0AE8uWirWmYyr3TX3z7uwkYr61FsrYHJAyKRkc\"\n" +
        "},\n" +
        "{\n" +
        "\"use\": \"sig\",\n" +
        "\"kty\": \"RSA\",\n" +
        "\"alg\": \"RS256\",\n" +
        "\"kid\": \"test-key-2\",\n" +
        "\"e\": \"AQAB\",\n" +
        "\"n\": \"AMZvxKpZec98OgPuea6DMElKZDE65o0AkOFquGTGOolflnADEnKnwUP5V9miBqmBxHCV2o8nog6bABlsbAGeAfx5vFi0EX-VQlQQFbjYS9-0jb9VUHkyslHUCXc_0oMgt-74QdO8uv_WAVISGWlgeNPFiXxWovgPUFCupptuLZvbuohrBT2zwu-thzZEFWCuPgHoOztqF1L_TrS6-63YUGWvl5aWdmxrt9798va9NAv4LhmF_lT3EPZmDweXhQ2fnFQQoxbyO4rUMDktSJsbvgn7c4GfsVdY96Qid38gb8dUNgVkMfp4I1H-w2cabs9d6U7GixeM7ZYFfahfHmAskV8\"\n" +
        "}\n" +
        "]\n" +
        "}";

    static final String TEST_OIDC_CONFIGURATION =
        "{\n" +
        "\"issuer\": \"http://localhost:8081\",\n" +
        "\"authorization_endpoint\": \"http://localhost:8081/oauth/authorize\",\n" +
        "\"token_endpoint\": \"http://localhost:8081/oauth/token\",\n" +
        "\"jwks_uri\": \"http://localhost:8081/oauth/jwks\",\n" +
        "\"userinfo_endpoint\": \"http://localhost:8081/userinfo\",\n" +
        "\"scopes_supported\": [\n" +
        "\"openid\",\n" +
        "\"profile\",\n" +
        "\"email\",\n" +
        "\"offline_access\",\n" +
        "\"ga4gh_passport_v1\",\n" +
        "\"identities\"\n" +
        "],\n" +
        "\"response_types_supported\": [\n" +
        "\"code\"\n" +
        "],\n" +
        "\"grant_types_supported\": [\n" +
        "\"authorization_code\"\n" +
        "],\n" +
        "\"subject_types_supported\": [\n" +
        "\"public\"\n" +
        "],\n" +
        "\"id_token_signing_alg_values_supported\": [\n" +
        "\"RS256\"\n" +
        "]\n" +
        "}";
    JwksKeyFactory jwksKeyFactory;
    KeyResolver keyResolver;
    HttpServer server;

    @BeforeEach
    public void setup() throws IOException {
        jwksKeyFactory = new JwksKeyFactory(OBJECT_MAPPER);
        keyResolver = jwksKeyFactory.create(new JwksKeyFactory.Config());
        int port = 8081;
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/oauth/jwks", exchange -> {
            exchange.sendResponseHeaders(200, TEST_JWKS.length());
            OutputStream os = exchange.getResponseBody();
            os.write(TEST_JWKS.getBytes());
            os.close();
        });
        server.createContext("/.well-known/openid-configuration", exchange -> {
            exchange.sendResponseHeaders(200, TEST_OIDC_CONFIGURATION.length());
            OutputStream os = exchange.getResponseBody();
            os.write(TEST_OIDC_CONFIGURATION.getBytes());
            os.close();
        });
        server.start();
    }

    @AfterEach
    public void cleanup() {
        server.stop(0);
    }

    @Test
    public void resolve_shouldValidateToken_afterKeyRotation() {
        final InboundConfiguration.IssuerConfig issuerConfig = new InboundConfiguration.IssuerConfig();

        issuerConfig.setIssuer("http://localhost:8081");
        issuerConfig.setBean("oidc-jwks");
        issuerConfig.setArgs(Map.of("jwksUri", "http://localhost:8081/oauth/jwks"));

        final Key key1 = keyResolver.resolve(issuerConfig, "test-key-1");
        final Key key2 = keyResolver.resolve(issuerConfig, "test-key-2");

        assertNotEquals(key1, key2, "Keys with different IDs should not be the same");
    }
}
