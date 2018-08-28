package org.dnastack.gatekeeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
@EnableResourceServer
@EnableWebSecurity
public class GatekeeperApp extends ResourceServerConfigurerAdapter {

    private static final String GATEKEEPER_ID = "GATEKEEPER1";

    private static final Pattern BEARER_HEADER = Pattern.compile("^Bearer\\s+([^\\s]+)$");

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.antMatcher("/**")
            .authorizeRequests()
                .anyRequest().authenticated().and()
            .csrf().disable()
            .addFilterBefore(new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                    final String authHeader = request.getHeader("Authentication");
                    if (authHeader != null) {
                        final Matcher matcher = BEARER_HEADER.matcher(authHeader);
                        if (matcher.matches()) {
                            final String token = matcher.group(1);
                            // TODO validate token
                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", token);
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            System.out.println("Logged in user with token [" + token + "].");
                        }
                    }
                    filterChain.doFilter(request, response);
                }
            }, BasicAuthenticationFilter.class);
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenServices(tokenService()).stateless(true);
    }

    private ResourceServerTokenServices tokenService() {
        RemoteTokenServices tokenServices = new RemoteTokenServices();
        tokenServices.setCheckTokenEndpointUrl("http://localhost:8080/oauth/check_token");
        tokenServices.setClientId("acme");
        tokenServices.setClientSecret("acmesecret");
        tokenServices.setAccessTokenConverter(new DefaultAccessTokenConverter());
        return tokenServices;
    }

    public static void main(String[] args) {
        SpringApplication.run(GatekeeperApp.class, args);
    }
}
