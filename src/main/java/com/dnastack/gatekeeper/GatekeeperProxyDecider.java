package com.dnastack.gatekeeper;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

@Slf4j
@Component
public class GatekeeperProxyDecider extends ZuulFilter {

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Override
    public String filterType() {
        log.debug("returning filterType 'route'");
        return "route";
    }

    @Override
    public int filterOrder() {
        log.debug("returning filterOrder 0");
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        log.debug("returning shouldFilter 'route'");
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext ctx = RequestContext.getCurrentContext();
        String remoteHost = ctx.getRequest().getRemoteHost();
        URI originalRequestUri = URI.create(ctx.getRequest().getRequestURI());

//        final String requestURI = this.urlPathHelper.getPathWithinApplication(ctx.getRequest());
        log.info("Beginning to route request with original coordinates {} {}", remoteHost, originalRequestUri);

        String publicOrProtected = choosePrefixBasedOnAuth(ctx.getRequest());

        String path = originalRequestUri.getPath();
        if (path.startsWith("/beacon/")) {
            path = path.substring("/beacon".length());
        }

        URI configuredBeaconBaseUrl = URI.create(beaconServerUrl);

        URI targetUrl;
        try {
            targetUrl = new URI(
                    configuredBeaconBaseUrl.getScheme(),
                    configuredBeaconBaseUrl.getAuthority(),
                    configuredBeaconBaseUrl.getPath() + publicOrProtected + path,
                    originalRequestUri.getQuery(),
                    originalRequestUri.getFragment());
        } catch (URISyntaxException e) {
            throw new ZuulException(e, 500, "Could not construct forward URI");
        }

        HttpServletRequestWrapper httpServletRequestWrapper = new HttpServletRequestWrapper(ctx.getRequest()) {
            public String getRequestURI() {
                log.debug("Returning {}", targetUrl);
                return targetUrl.toString();
            }
            public StringBuffer getRequestURL() {
                log.debug("Returning {}", targetUrl);
                return new StringBuffer(targetUrl.toString());
            }
        };

        ctx.setRequest(httpServletRequestWrapper);
        try {
            ctx.setRouteHost(targetUrl.toURL());
        } catch (MalformedURLException e) {
            throw new ZuulException(e, 500, "Could not construct forward URI");
        }

        log.info("Forwarding target is {}", targetUrl);

        return null;
    }

    private String choosePrefixBasedOnAuth(HttpServletRequest request) {
        if (request.getHeader("authorization") != null) {
            return "protected";
        } else {
            return "public";
        }
    }
}
