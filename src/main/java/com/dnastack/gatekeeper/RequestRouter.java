package com.dnastack.gatekeeper;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

public interface RequestRouter {

    /**
     * Examines the given request and returns the URI that the request should be routed to.
     *
     * @param request the inbound request
     * @return the backend URI that the request should be sent to
     */
    URI route(HttpServletRequest request) throws URISyntaxException;
}
