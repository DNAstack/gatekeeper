package com.dnastack.gatekeeper;

import com.netflix.zuul.exception.ZuulException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

@Component
@Slf4j
public class GatekeeperRequestRouter implements RequestRouter {

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Override
    public URI route(HttpServletRequest request) throws URISyntaxException {

        URI incomingUri = URI.create(request.getRequestURI());
        URI targetBaseUri = URI.create(beaconServerUrl);

        String path = incomingUri.getPath();
        if (path.startsWith("/beacon/")) {
            path = path.substring("/beacon".length());
        }
        String publicOrProtected = choosePrefixBasedOnAuth(request);
        path = publicOrProtected + "/" + path;

        return new URI(
                targetBaseUri.getScheme(),
                targetBaseUri.getAuthority(),
                targetBaseUri.getPath() + path,
                incomingUri.getQuery(),
                incomingUri.getFragment());
    }

    private String choosePrefixBasedOnAuth(HttpServletRequest request) {
        if (request.getHeader("authorization") != null) {
            return "protected";
        } else {
            return "public";
        }
    }

}