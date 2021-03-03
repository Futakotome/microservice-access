package io.futakotome.authService.config.web.configurer;

import io.futakotome.authService.crypto.keys.KeyManager;
import io.futakotome.authService.oauth2.jose.jws.NimbusJwsEncoder;
import io.futakotome.authService.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.authorization.*;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClientRepository;
import io.futakotome.authService.oauth2.server.authorization.web.*;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {
    private final RequestMatcher authorizationEndpointMatcher = new OrRequestMatcher(
            new AntPathRequestMatcher(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI, HttpMethod.GET.name()),
            new AntPathRequestMatcher(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI, HttpMethod.POST.name()));

    private final RequestMatcher tokenEndpointMatcher = new AntPathRequestMatcher(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI, HttpMethod.POST.name());
    private final RequestMatcher tokenRevocationEndpointMatcher = new AntPathRequestMatcher(OAuth2TokenRevocationEndpointFilter.DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI, HttpMethod.POST.name());
    private final RequestMatcher jwkSetEndpointMatcher = new AntPathRequestMatcher(JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI, HttpMethod.GET.name());
    private final RequestMatcher loginMatcher = new AntPathRequestMatcher("/login.html", HttpMethod.GET.name());

    public OAuth2AuthorizationServerConfigurer<B> registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        return this;
    }

    public OAuth2AuthorizationServerConfigurer<B> keyManager(KeyManager keyManager) {
        Assert.notNull(keyManager, "keyManager cannot be null");
        this.getBuilder().setSharedObject(KeyManager.class, keyManager);
        return this;
    }

    public List<RequestMatcher> getEndpointMatchers() {
        return Arrays.asList(this.authorizationEndpointMatcher, this.tokenEndpointMatcher,
                this.tokenRevocationEndpointMatcher, this.jwkSetEndpointMatcher,
                this.loginMatcher);
    }

    @Override
    public void init(B builder) throws Exception {
        OAuth2ClientAuthenticationProvider clientAuthenticationProvider = new OAuth2ClientAuthenticationProvider(
                getRegisteredClientRepository(builder),
                getAuthorizationService(builder));
        builder.authenticationProvider(postProcess(clientAuthenticationProvider));

        NimbusJwsEncoder jwtEncoder = new NimbusJwsEncoder(getKeyManager(builder));

        OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
                getRegisteredClientRepository(builder),
                getAuthorizationService(builder),
                jwtEncoder);
        builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

        OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(
                getAuthorizationService(builder),
                jwtEncoder);
        builder.authenticationProvider(postProcess(refreshTokenAuthenticationProvider));

        OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider(
                getAuthorizationService(builder),
                jwtEncoder);
        builder.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));

        OAuth2TokenRevocationAuthenticationProvider tokenRevocationAuthenticationProvider = new OAuth2TokenRevocationAuthenticationProvider(
                getAuthorizationService(builder));
        builder.authenticationProvider(postProcess(tokenRevocationAuthenticationProvider));

        ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    new OrRequestMatcher(this.tokenEndpointMatcher, this.tokenRevocationEndpointMatcher));
        }
    }


    @Override
    public void configure(B builder) throws Exception {
        JwkSetEndpointFilter jwkSetEndpointFilter = new JwkSetEndpointFilter(getKeyManager(builder));
        builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

        OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
                authenticationManager,
                new OrRequestMatcher(this.tokenEndpointMatcher, this.tokenRevocationEndpointMatcher));
        builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);

        OAuth2AuthorizationEndpointFilter authorizationEndpointFilter = new OAuth2AuthorizationEndpointFilter(
                getRegisteredClientRepository(builder),
                getAuthorizationService(builder));
        builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

        OAuth2TokenEndpointFilter tokenEndpointFilter = new OAuth2TokenEndpointFilter(
                authenticationManager,
                getAuthorizationService(builder));
        builder.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);

        OAuth2TokenRevocationEndpointFilter tokenRevocationEndpointFilter =
                new OAuth2TokenRevocationEndpointFilter(
                        authenticationManager);
        builder.addFilterAfter(postProcess(tokenRevocationEndpointFilter), OAuth2TokenEndpointFilter.class);

    }

    private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
        RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
        if (registeredClientRepository == null) {
            registeredClientRepository = getRegisteredClientRepositoryBean(builder);
            builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }
        return registeredClientRepository;
    }

    private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepositoryBean(B builder) {
        return builder.getSharedObject(ApplicationContext.class).getBean(RegisteredClientRepository.class);
    }

    private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
        OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = getAuthorizationServiceBean(builder);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }
            builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }
        return authorizationService;
    }

    private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationServiceBean(B builder) {
        Map<String, OAuth2AuthorizationService> authorizationServiceMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(builder.getSharedObject(ApplicationContext.class), OAuth2AuthorizationService.class);
        if (authorizationServiceMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(OAuth2AuthorizationService.class, authorizationServiceMap.size(),
                    "Expected single matching bean of type '" + OAuth2AuthorizationService.class.getName() + "' but found " +
                            authorizationServiceMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(authorizationServiceMap.keySet()));
        }
        return (!authorizationServiceMap.isEmpty() ? authorizationServiceMap.values().iterator().next() : null);
    }

    private static <B extends HttpSecurityBuilder<B>> KeyManager getKeyManager(B builder) {
        KeyManager keyManager = builder.getSharedObject(KeyManager.class);
        if (keyManager == null) {
            keyManager = getKeyManagerBean(builder);
            builder.setSharedObject(KeyManager.class, keyManager);
        }
        return keyManager;
    }

    private static <B extends HttpSecurityBuilder<B>> KeyManager getKeyManagerBean(B builder) {
        return builder.getSharedObject(ApplicationContext.class).getBean(KeyManager.class);
    }
}
