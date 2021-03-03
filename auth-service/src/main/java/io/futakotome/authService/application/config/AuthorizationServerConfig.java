package io.futakotome.authService.application.config;

import io.futakotome.authService.application.service.FeignUserDetailsService;
import io.futakotome.authService.config.web.confiuration.OAuth2AuthorizationServerConfiguration;
import io.futakotome.authService.crypto.keys.KeyManager;
import io.futakotome.authService.crypto.keys.StaticKeyGeneratingKeyManager;
import io.futakotome.authService.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClientRepository;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.UUID;

@EnableWebSecurity
@Import(OAuth2AuthorizationServerConfiguration.class)
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class AuthorizationServerConfig {

    private final @NonNull FeignUserDetailsService feignUserDetailsService;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("123456")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8015")
                .scope("message.read")
                .scope("message.write")
                .clientSettings(clientSettings -> clientSettings.requireProofKey(false))
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public KeyManager keyManager() {
        return new StaticKeyGeneratingKeyManager();
    }

    @Bean
    public UserDetailsService users() {
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("admin")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
        return feignUserDetailsService;
    }
}
