package com.dnastack.gatekeeper.routing;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RunWith(org.mockito.junit.MockitoJUnitRunner.class)
public class GatekeeperRequestRouterTest {

    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; 
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("32126741023641032641023641036201264102367126410261026423762032763122146702664021");
    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
    
	@InjectMocks
	GatekeeperRequestRouter router = new GatekeeperRequestRouter();

	@Spy
	ObjectMapper objectMapper = new ObjectMapper();
	
	@Spy 
	JwtParser jwtParser = Jwts.parser()
            				.setSigningKey(signingKey);
	
	
	@Before
	public void setUp() throws Exception {
		router.setBeaconServerUrl("http://example.com/beacon/");
		router.setPublicPrefix("public");
		router.setRegisteredPrefix("registered");
		router.setControlledPrefix("controlled");
	}

	
	
	@SuppressWarnings("unused")
	@Test
	public final void testRoute() throws ZuulException {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        @SuppressWarnings("deprecation")
		JwtBuilder builder = Jwts.builder().setId("jwtToken")
                                    .setIssuedAt(now)
                                    .setSubject("test")
                                    .setIssuer("example")
                                    .signWith(signatureAlgorithm, signingKey);
     
        int ttlMillis = -20000;

        long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        String jsonWebToken = builder.compact();
        
        String value = "bearer " + jsonWebToken;

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse(); 
        request.setAuthType("Basic");
        request.addHeader("authorization", value);
        request.setRequestURI("http://example.com/beacon/");
        request.setQueryString("param1=whatever");
        request.setServletPath("/beacon/");

        URI targetUrl;
        try {
            targetUrl = router.route(request, response);
        } catch (URISyntaxException e) {
            throw new ZuulException(e, 500, "Routing logic failed");
        } catch (UnroutableRequestException e) {
            throw new ZuulException(e, e.getStatus(), e.getMessage());
        }
        
        assert(response.getHeader("X-Gatekeeper-Access-Decision").equals("expired-credentials"));
	}

}
