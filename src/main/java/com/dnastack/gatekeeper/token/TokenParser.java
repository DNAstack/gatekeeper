package com.dnastack.gatekeeper.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Slf4j
@Component
@Validated
@ConfigurationProperties(prefix = "gatekeeper.token")
public class TokenParser {

    @Autowired
    private JwtParser jwtParser;
    @NotEmpty
    @Setter
    private List<String> audiences;


    public Jws<Claims> parseAndValidateJws(String authToken) throws JwtException, IllegalArgumentException {
        final Jws<Claims> jws = jwtParser.parseClaimsJws(authToken);

        final String tokenAudience = Optional.of(jws)
                .map(Jws::getBody)
                .map(Claims::getAudience)
                .orElseThrow(() -> new JwtException(
                        "No audience specified in token."));
        final Optional<String> validAudience = audiences.stream()
                .filter(tokenAudience::equals)
                .findAny();
        if (validAudience.isPresent()) {
            log.debug("Token audience successfully validated [{}]", validAudience.get());
        } else {
            throw new JwtException(format("Token audience [%s] is invalid.", tokenAudience));
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
