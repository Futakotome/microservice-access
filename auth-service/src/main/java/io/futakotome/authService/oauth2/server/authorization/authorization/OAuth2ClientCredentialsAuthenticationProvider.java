package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.jwt.JwtEncoder;
import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final JwtEncoder jwtEncoder;

    public OAuth2ClientCredentialsAuthenticationProvider(OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.authorizationService = authorizationService;
        this.jwtEncoder = jwtEncoder;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = (OAuth2ClientCredentialsAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(clientCredentialsAuthentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) clientCredentialsAuthentication.getPrincipal();
        }
        if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        }
        Set<String> scopes = registeredClient.getScopes();
        if (!CollectionUtils.isEmpty(clientCredentialsAuthentication.getScopes())) {
            Set<String> unauthorizedScopes = clientCredentialsAuthentication.getScopes().stream()
                    .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                    .collect(Collectors.toSet());
            if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));
            }
            scopes = new LinkedHashSet<>(clientCredentialsAuthentication.getScopes());
        }

        Jwt jwt = OAuth2TokenIssuerUtil.issueJwtAccessToken(this.jwtEncoder, clientPrincipal.getName(), registeredClient.getClientId(), scopes);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                jwt.getIssuedAt(),
                jwt.getExpiresAt(),
                scopes);
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .tokens(OAuth2Tokens.builder().accessToken(accessToken).build())
                .attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
                .build();
        this.authorizationService.save(authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
