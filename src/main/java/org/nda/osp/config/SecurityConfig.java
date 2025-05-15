package org.nda.osp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;


@Configuration
public class SecurityConfig {


    @Bean
    public UserDetailsManager authenticationManager() {

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails ud = User.builder()
                .passwordEncoder(
                        passwordEncoder::encode
                )
                .username("admin").password("java").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(ud);

    }
}
