package io.futakotome.authService.config.web.confiuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfiguration {
    @Bean
    public WebSecurityConfigurer<WebSecurity> defaultOAuth2AuthorizationServerSecurity() {
        return new OAuth2AuthorizationServerSecurity();
    }
}
