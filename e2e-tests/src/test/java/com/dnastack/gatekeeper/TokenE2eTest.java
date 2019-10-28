package com.dnastack.gatekeeper;

import io.jsonwebtoken.Jwts;
import io.restassured.RestAssured;
import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

public class TokenE2eTest extends BaseE2eTest {

    private static final String DEVELOPMENT_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEowIBAAKCAQEAxRvdt2Mrt1ZjX4KCSdFHNMEuENtrZzXv8Tkd0q572PGPHPx3\n" +
            "xnkj5qNA8BZzWsb1s+MTtyW7WGuQ0V9iipBjutA6X8wyGoNIEZtkWM2Xp61YMq3n\n" +
            "NetHoW4GR7S7ILirMVO0coBHrRnsKFKMKf3ZjL0s8xuy1EsTMmYBb3jdMqZxOpGg\n" +
            "yQB4t2rUfYbHkspDQqEK6qWxNkHsX8YbQucxqhu2ud2QWPczG3t11jdMWSF//yAp\n" +
            "yfOUn7X9fkhMxGMDQrvZ7W3BKOKZ6jYcm3vM40X5kGJHax0ZU2KeaVAl8qrJSE7c\n" +
            "Oiv6TxnIcBJ00isVdLggzz72xK5R9R1e9MEODQIDAQABAoIBAQCA/u2pOOPBRm4e\n" +
            "cYDm4mlhYxPMwGyXzTrMeX7FBJ/UqLHqXGfeoiUWqbyz4113CUJ/iZq7f5wOD8dk\n" +
            "3rHU0Q4TknbBfxdDNquRqkqPu20GtXFFKX5pUSM9yI2fm+3jSjfvPkKXtNAzvwVI\n" +
            "lk1YpeMcMioaqAPu33sevpct5sGMhS71S1t8oIJ82d4e7t53nWSWYs7AAbUf3zbb\n" +
            "mcXag6UiqMeuXk3m+eLC/s6gwyOm4FcS54SKKt9EcweaZwk89oBrQRdoeqzvejfZ\n" +
            "rrwC19LVNggr2DVsaAMV7VKV0C6xJoY1eitqgKKjZqsD5cQupAqou89hGRhYbqoU\n" +
            "Ad3jJ7zBAoGBAOYpWUxrHfcrDD8v6GgP/nW4co3KQpWHKiq5pPjVmFrj96HqHZiL\n" +
            "4adAzfSHFTSnL7vo3ZSRtFZVAcU/csXG2PvyR04L2+k6pbn/gSzLvQLWObG57VQt\n" +
            "vr+RQjArOaJOJ0ZXLn6MWz/26kzVtwjpXvxLk6TSGDKVcKeRuqe18H9VAoGBANs8\n" +
            "nGvDrQ4dykcVdWtHRsguX7A8820KZpx+mb4RC8CRgkpF1fqokY4FhilL4CjA8yzF\n" +
            "gt6mNP4MVCVyfu9J2GbsXLQHkPm8m03u/SYL0NpHodNXGuv6YOuTTikCljf/oy9/\n" +
            "qHjeXWqpThaPejU4n0DTDuyscGZ3RxroQB8biqPZAoGAEdZMhF6c0OX2KgN1eHMc\n" +
            "3lSwFAsDxADYpL0EawBqsUiPjW3OY18b2tFr5LJ/UzhNu7tdSMFN/47Q909mfqtd\n" +
            "b5EkM4k5vsZ7x4FkqmsTt9+QUxS8rtRovwHr5j3DVq/F3W6uPMJ14+wn1lKNv9QO\n" +
            "N3FH/PMHSwxH0cS6eXrhK40CgYAo74dRg+bzRNK5NSOIlXV8+VO6p5bYXGHOhMEW\n" +
            "QT6NhV3rmmCa/hC3kQZ8/YLseSKu0G5gPm6UpR6tI1TaP1Kd3TJuFx+V0ga5pY81\n" +
            "JG2p5EguGwyW1Vh1hDrK44XDDQOeYdrGPtb4jIZdJgsultT9mKsnvAb8yvbG6mjW\n" +
            "piDb+QKBgFSVXaxQQgUzlXGg5amGKNll2pSWmcIq2PqDmSPUCUQLj0zA0rpfRQzV\n" +
            "53pem4cn7JfsV4xvQRlTqrdvtGObdSyTmkogUB8Ymk0v1F8oacRJnwBTwD0SVEUG\n" +
            "WNZ6QCnkEy3l3CWBReVCu5pP1//yWOv8S8jO4jDSCDyu9WuPwzGh\n" +
            "-----END RSA PRIVATE KEY-----";

    private String developmentPrivateKey;

    @Before
    public void setupJwt() {
        // Give option to override when running locally
        developmentPrivateKey = optionalEnv("E2E_DEVELOPMENT_KEY", DEVELOPMENT_PRIVATE_KEY);
    }

    @Test
    public void loginEndpointRejectsMalformedTokens() {
        final String token = "definitelyNotAToken";
        //@formatter:off
        given()
                .log().method()
                .log().uri()
                .redirects().follow(false)
                .when()
                .cookie("access_token", token)
                .get("/api/identity/login?state=/metadata/path-that-almost-certainly-does-not-exist")
                .then()
                .log().ifValidationFails()
                .statusCode(isStatus3xx())
                .header("location", not(containsString("/api/identity/login")));
        //@formatter:on
    }

    @Test
    public void loginEndpointRejectsDeveloperKeySignedTokens() {
        final String token = Jwts.builder()
                                 .setIssuer("http://localhost:8081")
                                 .signWith(RsaKeyHelper.parsePrivateKey(developmentPrivateKey))
                                 .setExpiration(new Date(Instant.now().plusMillis(10000).toEpochMilli()))
                                 .compact();
        //@formatter:off
        given()
                .log().method()
                .log().uri()
                .redirects().follow(false)
                .when()
                .cookie("access_token", token)
                .get("/api/identity/login?state=/metadata/path-that-almost-certainly-does-not-exist")
                .then()
                .log().ifValidationFails()
                .statusCode(isStatus3xx())
                .header("location", not(startsWith(RestAssured.baseURI)));
        //@formatter:on
    }

    private Matcher<Integer> isStatus3xx() {
        return allOf(greaterThanOrEqualTo(300), lessThan(400));
    }
}