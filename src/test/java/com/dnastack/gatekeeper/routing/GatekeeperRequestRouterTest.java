package com.dnastack.gatekeeper.routing;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class GatekeeperRequestRouterTest {


	GatekeeperRequestRouter router = new GatekeeperRequestRouter();

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Autowired
    private InboundEmailWhitelistConfiguration emailWhitelist;


	@SuppressWarnings("unused")
	@Before
	public void setUp() throws Exception {

	}


	@Test
	public final void testRoute() throws ZuulException {
		

        RequestContext ctx = RequestContext.getCurrentContext();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; 
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
     
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("andrewglynnandrewglynnandrewglynnandrewglynnandrewglynnandrewglynnandrewglynnandrewglynnandrewglynn");
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());


        @SuppressWarnings("deprecation")
		JwtBuilder builder = Jwts.builder().setId("jwtoken")
                                    .setIssuedAt(now)
                                    .setSubject("test")
                                    .setIssuer("dnastack")
                                    .signWith(signatureAlgorithm, signingKey);
     
        int ttlMillis = -20000;


        long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);

     

        String jsonWebToken = builder.compact();
        String value = "authScheme:jwt , authToken:";
        value = value + jsonWebToken;
        ctx.set("authToken", jsonWebToken);        
        ctx.addZuulRequestHeader("authentication", value);

        HttpServletRequest request = ctx.getRequest();
        HttpServletResponse response = ctx.getResponse();


        URI targetUrl;
        try {
        	request.setAttribute("requestURI", "/beacon/");
            targetUrl = router.route(request, response);
        } catch (URISyntaxException e) {
            throw new ZuulException(e, 500, "Routing logic failed");
        } catch (UnroutableRequestException e) {
            throw new ZuulException(e, e.getStatus(), e.getMessage());
        }

        try {
            ctx.setRouteHost(targetUrl.resolve("/").toURL());
        } catch (MalformedURLException e) {
            throw new ZuulException(e, 500, "Could not construct forward URI");
        }
        ctx.set(FilterConstants.REQUEST_URI_KEY, targetUrl.getPath());
        
        Object decision;
		decision = response.getHeader("X-Gatekeeper-Access-Decision");
        assert(decision.equals("insufficient-credentials"));



	}

}
