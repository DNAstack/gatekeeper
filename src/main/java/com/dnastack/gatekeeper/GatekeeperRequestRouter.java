package com.dnastack.gatekeeper;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;

@Component
@Slf4j
public class GatekeeperRequestRouter implements RequestRouter {

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Autowired
    private InboundKeyConfiguration keyConfiguration;

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
            response.setHeader("WWW-Authenticate", "Bearer");
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

        PublicKey publicKey = RsaKeyHelper.parsePublicKey(keyConfiguration.getPublicKey());

        Jws<Claims> jws;
        try {
            jws = Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(authToken);

            log.info("Validated inbound token {}", jws);
            return "protected";

        } catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
        }
    }
}
