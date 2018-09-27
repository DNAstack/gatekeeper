package com.dnastack.gatekeeper;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

@Slf4j
@Component
public class GatekeeperProxyRoutingFilter extends ZuulFilter {

    @Autowired
    private RequestRouter requestRouter;

    @Override
    public String filterType() {
        log.trace("returning filterType 'route'");
        return "route";
    }

    @Override
    public int filterOrder() {
        log.trace("returning filterOrder 0");
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        log.trace("returning shouldFilter 'route'");
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext ctx = RequestContext.getCurrentContext();
        final HttpServletRequest request = ctx.getRequest();

        String remoteHost = request.getRemoteHost();
        String originalUrl = request.getRequestURI();

        log.debug("Beginning to route request with original coordinates {} {}", remoteHost, originalUrl);

        URI targetUrl;
        try {
            targetUrl = requestRouter.route(request);
        } catch (URISyntaxException e) {
            throw new ZuulException(e, 500, "Routing logic failed");
        }

        log.info("Routing {} request {} -> {}", request.getMethod(), originalUrl, targetUrl);

        try {
            ctx.setRouteHost(targetUrl.resolve("/").toURL());
        } catch (MalformedURLException e) {
            throw new ZuulException(e, 500, "Could not construct forward URI");
        }
        ctx.set(FilterConstants.REQUEST_URI_KEY, targetUrl.getPath());
        log.debug("Context request uri key: {}", ctx.get(FilterConstants.REQUEST_URI_KEY));

        return null;
    }

}