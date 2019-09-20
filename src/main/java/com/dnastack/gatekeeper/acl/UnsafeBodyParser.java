package com.dnastack.gatekeeper.acl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The "Unsafe" is because this parser does not validate signature. It is used to extract claims
 * from a body that are necessary before parsing.
 */
@Component
public class UnsafeBodyParser {
    @Autowired
    private ObjectMapper objectMapper;

    @Data
    static class JwtBodyWithIssuer {
        private String iss;
    }

    public String extractIssuerWithoutValidation(String jwt) {
        final String rawBody = decodeBodyWithoutValidation(jwt);
        try {
            final JwtBodyWithIssuer body = objectMapper.readValue(rawBody, JwtBodyWithIssuer.class);
            return body.getIss();
        } catch (IOException e) {
            throw new JwtException("Malformed auth token was not a JWT: Could not parse body");
        }
    }

    private String decodeBodyWithoutValidation(String jwt) {
        final String[] jwtParts = jwt.split("\\.", -1);
        if (jwtParts.length != 3) {
            throw new JwtException("Given auth token is not JWT: Missing header, body, or signature");
        }

        try {
            return new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Malformed auth token was not a JWT: Could not decode body");
        }
    }
}
