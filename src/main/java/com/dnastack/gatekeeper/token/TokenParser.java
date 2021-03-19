package com.dnastack.gatekeeper.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Slf4j
@Component
@Validated
public class TokenParser {

    private final JwtParser jwtParser;
    private final TokenConfig tokenConfig;

    @Autowired
    public TokenParser(JwtParser jwtParser, TokenConfig tokenConfig) {
        this.jwtParser = jwtParser;
        this.tokenConfig = tokenConfig;
    }


    public Jws<Claims> parseAndValidateJws(String authToken) throws JwtException, IllegalArgumentException {
        final Jws<Claims> jws = jwtParser.parseClaimsJws(authToken);

        final Object rawTokenAudience = Optional.of(jws)
                .map(Jws::getBody)
                .map(claims -> claims.get("aud"))
                .orElseThrow(() -> new JwtException(
                        "No audience specified in token."));
        final List<String> givenAudiences;
        if (rawTokenAudience instanceof List) {
            givenAudiences = (List<String>) rawTokenAudience;
        } else {
            givenAudiences = List.of(rawTokenAudience.toString());
        }

        final Optional<String> validAudience = tokenConfig.getAudiences().stream()
                .filter(givenAudiences::contains)
                .findAny();
        if (validAudience.isPresent()) {
            log.debug("Token audience successfully validated [{}]", validAudience.get());
        } else {
            throw new JwtException(format("Token audience %s is invalid.", givenAudiences));
        }


        log.info("Validated signature of inbound token {}", jws);
        return jws;
    }

    public boolean isValid(String authToken) {
        try {
            parseAndValidateJws(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }
}
