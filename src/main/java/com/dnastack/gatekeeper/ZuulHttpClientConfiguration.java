package com.dnastack.gatekeeper;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ZuulHttpClientConfiguration {

    @Value("${outbound.basic.username}")
    private String username;

    @Value("${outbound.basic.password}")
    private String password;

    @Bean
    public CloseableHttpClient httpClient() {
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        final Credentials credentials = new UsernamePasswordCredentials(username, password);
        credentialsProvider.setCredentials(AuthScope.ANY, credentials);
        return HttpClientBuilder.create()
                .disableCookieManagement()
                .setDefaultCredentialsProvider(credentialsProvider)
                .build();
    }
}
