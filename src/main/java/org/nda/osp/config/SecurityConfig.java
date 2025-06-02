package org.nda.osp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.applyDefaultSecurity;


@Configuration
public class SecurityConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient registeredClient = RegisteredClient.withId("gateway")
                .clientId("gateway")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .scope("openid")
                .scope("read")
                .clientSettings(
                        ClientSettings.builder().requireAuthorizationConsent(true).build()
                )
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * PREVENT CSRF check
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Integer.MIN_VALUE)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }

}
