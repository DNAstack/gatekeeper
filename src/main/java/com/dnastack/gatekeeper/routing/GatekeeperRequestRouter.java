package com.dnastack.gatekeeper.routing;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class GatekeeperRequestRouter implements RequestRouter {

    public static final TypeReference<List<Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<List<Account>>() {

    };
    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Autowired
    private InboundEmailWhitelistConfiguration emailWhitelist;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtParser jwtParser;

    @Override
    public URI route(HttpServletRequest request, HttpServletResponse response) throws URISyntaxException, UnroutableRequestException {

        URI incomingUri = URI.create(request.getRequestURI());
        URI targetBaseUri = URI.create(beaconServerUrl);

        String path = incomingUri.getPath();
        if (path.startsWith("/beacon/")) {
            path = path.substring("/beacon".length());
        }
        String publicOrProtected = choosePrefixBasedOnAuth(request, response);
        path = publicOrProtected + "/" + path;

        return new URI(
                targetBaseUri.getScheme(),
                targetBaseUri.getAuthority(),
                targetBaseUri.getPath() + path,
                incomingUri.getQuery(),
                incomingUri.getFragment());
    }

    private String choosePrefixBasedOnAuth(HttpServletRequest request, HttpServletResponse response) throws UnroutableRequestException {
        String authHeader = request.getHeader("authorization");
        if (authHeader == null) {
            log.debug("No auth found. Sending auth challenge.");
            response.setHeader("WWW-Authenticate", "Bearer");
            final String accessDecision = String.format("requires-credentials %s $.accounts[*].email",
                                                        GOOGLE_ISSUER_URL);
            setAccessDecision(response, accessDecision);
            return "public";
        }

        String[] parts = authHeader.split(" ");
        if (parts.length != 2) {
            throw new UnroutableRequestException(400, "Invalid authorization header");
        }

        String authScheme = parts[0];
        String authToken = parts[1];

        if (!authScheme.equalsIgnoreCase("bearer")) {
            throw new UnroutableRequestException(400, "Unsupported authorization scheme");
        }

        Jws<Claims> jws;
        try {
            jws = jwtParser.parseClaimsJws(authToken);
            
            log.info("Validated signature of inbound token {}", jws);

            final Claims claims = jws.getBody();
            Stream<String> googleEmails = extractGoogleEmailAddresses(claims);
            final boolean hasWhitelistedEmailAddress = googleEmails.anyMatch(this::isWhitelisted);
            if (hasWhitelistedEmailAddress) {
                setAccessDecision(response, "access-granted");
                return "protected";
            } else {
                setAccessDecision(response, "insufficient-credentials");
                return "public";
            }
        } catch (ExpiredJwtException ex) {
        	setAccessDecision(response, "insufficient-credentials");
        	return "public";
        }       		
        catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
        }
    }

    private void setAccessDecision(HttpServletResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.setHeader("X-Gatekeeper-Access-Decision", decision);
    }

    private Stream<String> extractGoogleEmailAddresses(Claims claims) {
        final List<Account> accounts = objectMapper.convertValue(claims.get("accounts", List.class),
                                                                 LIST_OF_ACCOUNT_TYPE);
        return accounts.stream()
                       .filter(this::issuedByGoogle)
                       .flatMap(this::accountEmail);
    }

    private Stream<String> accountEmail(Account account) {
        final String email = account.getEmail();
        return (email == null) ? Stream.empty() : Stream.of(email);
    }

    private boolean issuedByGoogle(Account account) {
        return GOOGLE_ISSUER_URL.equals(account.getIssuer());
    }

    private boolean isWhitelisted(String email) {
        return emailWhitelist.getEmailWhitelist().contains(email);
    }

    @Data
    static class Account {
        private String accountId, issuer, email;
    }
}
